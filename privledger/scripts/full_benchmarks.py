"""Expanded live E2/E4/E5 benchmark; call run_benchmarks(exp, >=400 items).

exp is run_experiment.Experiment (or subclass) attached to the intended ledger.
items contain eid,cid,key,raw,sha. No concurrent chain writer is allowed: the
expiry experiment advances the local chain one UTC epoch before fresh proofs.
All completed steps are fsync-journaled under exp.out. Secrets live only under
exp.secret_dir. A pending mined transaction is recovered by exact calldata,
sender and contract matching before any resend. Snapshot restores benchmark
rows/latencies on resume. The original source run is never modified.
"""
import hashlib
import json
import os
from pathlib import Path
import random
import secrets
import time

from privledger.encryption import encrypt, decrypt
from privledger.hashing import sha256_hex, keccak256_hex


def _hex(data):
    return '0x' + hashlib.sha256(data).hexdigest()


def _atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class Journal:
    def __init__(self, exp):
        self.exp = exp
        self.path = exp.out / 'benchmark_steps.jsonl'
        self.state = {}
        if self.path.exists():
            # Preserve valid prefix if process died in the final append.
            data = self.path.read_bytes()
            offset = 0
            for line in data.splitlines(keepends=True):
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    with self.path.open('r+b') as f:
                        f.truncate(offset)
                    break
                self.state[row['step']] = row['result']
                offset += len(line)
        self.address = exp.chain.call('address')['address']
        root = Path(__file__).resolve().parents[1]
        abi = json.loads((root / 'abi/PrivLedger.json').read_text())
        self.contract = exp.web3.eth.contract(address=self.address, abi=abi)
        self.sender = exp.web3.eth.accounts[0]

    def save(self, key, value):
        with self.path.open('a', encoding='utf-8') as f:
            f.write(json.dumps({'step': key, 'result': value}) + '\n')
            f.flush()
            os.fsync(f.fileno())
        self.state[key] = value
        return value

    def step(self, key, fn):
        if key in self.state:
            return self.state[key]
        return self.save(key, fn())

    def tx(self, key, op, **kw):
        if key in self.state:
            return self.state[key]
        names = {
            'issue': ('issueCredential', ['credentialCommitment', 'role', 'expiry']),
            'register': ('registerEvidence', ['evidenceId', 'sha256Digest', 'keccakDigest', 'zkCommitment', 'cid', 'retentionUntil', 'custodianDidHash']),
            'access': ('requestAccess', ['evidenceId', 'action', 'credentialCommitment', 'nullifierHash', 'proof']),
            'revoke': ('revokeCredential', ['credentialCommitment', 'reasonHash']),
            'redact': ('recordRedaction', ['parentEvidenceId', 'childEvidenceId', 'cid', 'storageAttestationHash', 'proofRef']),
            'delete': ('recordDeletion', ['evidenceId', 'storageAttestationHash', 'proofRef']),
            'verifyPaid': ('verifyProof', ['circuitId', 'publicSignals', 'proof']),
        }
        defaults = {'zkCommitment': '0x'+'00'*32, 'retentionUntil': 0,
                    'custodianDidHash': '0x'+'00'*32, 'reasonHash': _hex(b'benchmark revocation')}
        encoded = {**defaults, **kw}
        if op == 'verifyPaid':
            encoded['circuitId'] = self.contract.functions.CIRCUIT_ID().call()
            encoded['publicSignals'] = list(map(int, kw['publicSignals']))
        fname, fields = names[op]
        calldata = self.contract.encode_abi(fname, args=[encoded[k] for k in fields])
        intent = key + ':intent'
        if intent in self.state:
            prior = self.state[intent]
            if prior['calldata'] != calldata:
                raise RuntimeError('Benchmark resume changed transaction arguments')
            for number in range(prior['block']+1, self.exp.web3.eth.block_number+1):
                block = self.exp.web3.eth.get_block(number, full_transactions=True)
                for tx in block.transactions:
                    if (str(tx.get('to','')).lower() == self.address.lower()
                            and str(tx['from']).lower() == self.sender.lower()
                            and tx['input'].hex().removeprefix('0x') == calldata.removeprefix('0x')):
                        r = self.exp.web3.eth.get_transaction_receipt(tx['hash'])
                        if r['status'] != 1:
                            raise RuntimeError('Pending benchmark transaction reverted')
                        result = {'transactionHash': '0x'+r['transactionHash'].hex().removeprefix('0x'),
                                  'gasUsed': str(r['gasUsed']), 'blockNumber': r['blockNumber'],
                                  'transactionMs': None, 'latency_recovery_note': 'receipt recovered after interruption; latency unavailable',
                                  'logs': [{'address': l['address'], 'topics': ['0x'+v.hex().removeprefix('0x') for v in l['topics']], 'data': '0x'+l['data'].hex().removeprefix('0x')} for l in r['logs']]}
                        if op == 'access':
                            events = self.contract.events.AccessDecision().process_receipt(r)
                            result['allowed'] = bool(events[0]['args']['allowed'])
                        if op == 'issue':
                            result['credentialCommitment'] = kw['credentialCommitment']
                        if op == 'verifyPaid':
                            result['valid'] = bool(self.contract.functions.verifyProof(encoded['circuitId'], encoded['publicSignals'], kw['proof']).call())
                        existing = {v['transactionHash'] for v in self.exp.receipts}
                        if result['transactionHash'] not in existing:
                            self.exp.gas[op].append(int(result['gasUsed']))
                            row = {'operation': op, **result, 'evidence_type': 'measured'}
                            self.exp.receipts.append(row)
                            with (self.exp.out/'transaction_receipts.jsonl').open('a',encoding='utf-8') as f:
                                f.write(json.dumps(row)+'\n'); f.flush(); os.fsync(f.fileno())
                        return self.save(key, result)
        else:
            self.save(intent, {'block': self.exp.web3.eth.block_number, 'calldata': calldata})
        if op == 'revoke':
            kw.setdefault('reasonHash', defaults['reasonHash'])
        return self.save(key, self.exp.tx(op, **kw))

    def credential(self, key, role=1, expiry=None):
        secret_file = self.exp.secret_dir / ('benchmark_'+key+'.json')
        if secret_file.exists():
            credential = json.loads(secret_file.read_text())
        else:
            credential = {'secret': str(secrets.randbelow(2**250)+1), 'role': role,
                          'expiry': expiry if expiry is not None else self.exp.chain.call('status')['epoch']+365}
            _atomic(secret_file, credential)
        commitment = self.step(key+':commitment', lambda: self.exp.chain.call('commitment', **credential))['credentialCommitment']
        self.tx(key+':issue', 'issue', credentialCommitment=commitment, role=role, expiry=credential['expiry'])
        return credential, commitment

    def proof(self, key, credential, eid, action=1, **kw):
        return self.step(key, lambda: self.exp.proof(credential, eid, action, **kw))

    def access(self, key, eid, proof, action=1):
        return self.tx(key, 'access', evidenceId=eid, action=action,
                       **{k:proof[k] for k in ('credentialCommitment','nullifierHash','proof')})


def run_benchmarks(exp, items):
    """Append 227 E2 cases, 100 E4 pairs and real paid gas samples to exp.

    Journal steps are authoritative on resume. exp.gas/receipts should already
    be restored by the full runner; row arrays are replaced with the benchmark
    snapshot so interrupted/restarted execution does not duplicate rows.
    """
    if len(items) < 400:
        raise ValueError('Expanded benchmark requires at least 400 distinct registered artifacts')
    journal = Journal(exp)
    def has_event(receipt, signature):
        topic=exp.web3.keccak(text=signature).hex().removeprefix('0x')
        return any(log['topics'] and log['topics'][0].removeprefix('0x')==topic for log in receipt['logs'])
    snapshot = exp.out / 'benchmark_snapshot.json'
    if snapshot.exists():
        saved = json.loads(snapshot.read_text())
        exp.e2, exp.redactions, exp.deletions = saved['e2'], saved['redactions'], saved['deletions']
        for key, value in saved['latency'].items():
            exp.latency[key] = value
        if saved['complete']:
            return saved
    initial_epoch = journal.step('initial_epoch', lambda: exp.chain.call('status')['epoch'])
    expired, _ = journal.credential('expired', expiry=initial_epoch)
    expired_proofs = [journal.proof(f'expired-proof-{i}', expired, items[200+i]['eid'], epoch=initial_epoch) for i in range(25)]
    journal.step('advance_epoch', lambda: exp.chain.call('advanceEpoch', epoch=initial_epoch+1))
    legal, _ = journal.credential('legal', 3)
    investigator, _ = journal.credential('investigator')
    wrong_role, _ = journal.credential('auditor', 2)
    revoked, revoked_commitment = journal.credential('revoked')
    journal.tx('revoke-primary', 'revoke', credentialCommitment=revoked_commitment)

    def save(complete=False):
        proofs = [v for v in journal.state.values() if isinstance(v,dict) and 'generationMs' in v and 'verificationMs' in v]
        exp.latency['zkp_generation_ms'] = [v['generationMs'] for v in proofs]
        exp.latency['zkp_offchain_verification_ms'] = [v['verificationMs'] for v in proofs]
        value = {'complete': complete, 'e2': exp.e2, 'redactions': exp.redactions,
                 'deletions': exp.deletions, 'latency': dict(exp.latency)}
        _atomic(snapshot, value)
        return value

    def proof_reference(key, proof, auth):
        ref = _hex(bytes.fromhex(proof['proof'][2:]))
        path = exp.out / 'lifecycle_proofs' / (key+'.json')
        _atomic(path, {'publicSignals': proof['publicSignals'], 'proof': proof['proof'],
                       'proof_ref': ref, 'authorization_receipt': auth})
        return ref, str(path.relative_to(exp.out))

    for i, item in enumerate(items[:100]):
        key = f'redaction-{i:03d}'
        if key+':row' in journal.state:
            row = journal.state[key+':row']
        else:
            resumed = key+':started' in journal.state
            journal.step(key+':started', lambda: {'timestamp': time.time()})
            start = time.perf_counter()
            p = journal.proof(key+':proof', legal, item['eid'], 3)
            auth = journal.access(key+':auth', item['eid'], p, 3)
            if not auth['allowed']:
                raise RuntimeError('Fresh legal redaction authorization denied')
            ref, proof_path = proof_reference(key, p, auth)
            replacement = b'[REDACTED RESEARCH EVIDENCE]\n'+sha256_hex(item['raw']).encode()
            # Persist random encryption once, so retries use the same CID.
            blob_path = exp.secret_dir/(key+'.encrypted')
            if not blob_path.exists():
                blob_path.write_bytes(exp.timed('encryption_ms', lambda: encrypt(replacement,item['key'])))
            cid = journal.step(key+':cid', lambda: exp.timed('ipfs_add_ms',lambda:exp.ipfs.add(blob_path.read_bytes())))
            child = _hex((str(exp.out.name)+item['eid']+':redacted').encode())
            journal.tx(key+':register', 'register', evidenceId=child,sha256Digest='0x'+sha256_hex(replacement),keccakDigest='0x'+keccak256_hex(replacement),cid=cid)
            rr = journal.tx(key+':redact','redact',parentEvidenceId=item['eid'],childEvidenceId=child,cid=cid,
                            storageAttestationHash=_hex(json.dumps({'parent':item['eid'],'child':child,'cid':cid},sort_keys=True).encode()),proofRef=ref)
            cs = exp.chain.call('evidence',evidenceId=child)
            ps = exp.chain.call('evidence',evidenceId=item['eid'])
            recovered = decrypt(exp.timed('ipfs_retrieval_ms',lambda:exp.ipfs.cat(cid)),item['key'])
            row = {'case_id':key,'parent':item['eid'],'child':child,'replacement_cid':cid,
                   'lineage_valid':cs['parent']==item['eid'],'replacement_verified':recovered==replacement,
                   'replacement_hash_correct':sha256_hex(recovered)==cs['sha256Digest'][2:] and keccak256_hex(recovered)==cs['keccakDigest'][2:],
                   'original_hash_preserved':ps['sha256Digest']=='0x'+item['sha'],
                   'event_emitted':has_event(rr,'EvidenceRedacted(bytes32,bytes32,string,bytes32,bytes32)'),
                   'proof_reference_available':(exp.out/proof_path).exists(),'proof_file':proof_path,
                   'authorization_transaction':auth['transactionHash'],'transaction_hash':rr['transactionHash'],
                   'gas_used':int(rr['gasUsed']),'latency_ms':None if resumed else (time.perf_counter()-start)*1000,
                   'latency_recovery_note':'interrupted workflow; omitted from latency statistics' if resumed else '', 'evidence_type':'measured'}
            journal.save(key+':row',row)
        if not any(r.get('case_id')==key for r in exp.redactions):
            exp.redactions.append(row)
            if row['latency_ms'] is not None: exp.latency['end_to_end_redaction_ms'].append(row['latency_ms'])
        save()
        if (i+1)%20==0: print(f'Benchmark redactions {i+1}/100',flush=True)

    for i,item in enumerate(items[100:200]):
        key=f'deletion-{i:03d}'
        if key+':row' in journal.state:
            row=journal.state[key+':row']
        else:
            resumed=key+':started' in journal.state
            journal.step(key+':started',lambda:{'timestamp':time.time()})
            start=time.perf_counter()
            p=journal.proof(key+':proof',legal,item['eid'],3)
            auth=journal.access(key+':auth',item['eid'],p,3)
            if not auth['allowed']: raise RuntimeError('Fresh legal deletion authorization denied')
            ref,proof_path=proof_reference(key,p,auth)
            def remove_pin():
                if key+':unpin-intent' in journal.state:
                    pins=exp.ipfs._post('pin/ls',params={'type':'recursive'}).json().get('Keys',{})
                    if item['cid'] not in pins:
                        return {'Pins':[item['cid']], 'recovery_note':'previous unpin request interrupted; recursive pin absence verified on resume'}
                journal.step(key+':unpin-intent',lambda:{'cid':item['cid']})
                return exp.ipfs.unpin(item['cid'])
            unpin=journal.step(key+':unpin',remove_pin)
            dr=journal.tx(key+':delete','delete',evidenceId=item['eid'],storageAttestationHash=_hex(json.dumps(unpin,sort_keys=True).encode()),proofRef=ref)
            state=exp.chain.call('evidence',evidenceId=item['eid'])
            row={'case_id':key,'evidence_id':item['eid'],'local_unpin_success':item['cid'] in unpin.get('Pins',[]),
                 'local_unpin_recovery_note':unpin.get('recovery_note',''),
                 'authorized_logical_deletion':bool(auth['allowed']),'logical_deleted':int(state['state'])==3,'lifecycle_state':int(state['state']),
                 'event_emitted':has_event(dr,'EvidenceDeletionRecorded(bytes32,bytes32,bytes32)'),
                 'proof_reference_available':(exp.out/proof_path).exists(),'proof_file':proof_path,
                 'authorization_transaction':auth['transactionHash'],'transaction_hash':dr['transactionHash'],
                 'gas_used':int(dr['gasUsed']),'latency_ms':None if resumed else (time.perf_counter()-start)*1000,
                 'latency_recovery_note':'interrupted workflow; omitted from latency statistics' if resumed else '', 'evidence_type':'measured'}
            journal.save(key+':row',row)
        if not any(r.get('case_id')==key for r in exp.deletions):
            exp.deletions.append(row)
            if row['latency_ms'] is not None: exp.latency['end_to_end_deletion_ms'].append(row['latency_ms'])
        save()
        if (i+1)%20==0:print(f'Benchmark deletions {i+1}/100',flush=True)

    cases=[(category,i) for category in ['authorized','wrong_role','expired_credential','revoked_credential','invalid_proof','altered_public_input','replayed_nullifier','unknown_evidence','deleted_evidence'] for i in range(25)]
    cases += [('unknown_credential',0),('conflicting_policy_unsupported_action',0)]
    random.Random(42).shuffle(cases)
    for index,(category,i) in enumerate(cases):
        key=f'access-{category}-{i:03d}'
        if key+':row' in journal.state:
            row=journal.state[key+':row']
        else:
            resumed=key+':started' in journal.state
            journal.step(key+':started',lambda:{'timestamp':time.time()})
            # Separate credential per category avoids nullifier contamination.
            cred=wrong_role if category=='wrong_role' else revoked if category=='revoked_credential' else investigator
            if category not in ('wrong_role','expired_credential','revoked_credential'):
                cred,_=journal.credential('category-'+category)
            eid=items[200+i]['eid']
            if category=='deleted_evidence':eid=items[100+i]['eid']
            if category=='unknown_evidence':eid=_hex((exp.out.name+':unknown:'+str(i)).encode())
            start=time.perf_counter()
            if category=='expired_credential':p=expired_proofs[i]
            else:p=journal.proof(key+':proof',cred,eid,1)
            base=dict(p)
            action=1
            setup_ms=0
            if category=='wrong_role':
                # Sound proof of auditor role supplied to investigator action.
                pass
            elif category=='invalid_proof':
                p={**p,'proof':'0x'+'00'*32+p['proof'][66:]}
            elif category=='altered_public_input':
                eid=items[225+i]['eid']
            elif category=='replayed_nullifier':
                precursor_start=time.perf_counter()
                initial=journal.access(key+':initial',eid,p)
                setup_ms=(time.perf_counter()-precursor_start)*1000
                if not initial['allowed']:raise RuntimeError('Replay precursor was not allowed')
            elif category=='unknown_credential':
                p={**p,'credentialCommitment':'0x'+'00'*31+'01'}
            elif category=='conflicting_policy_unsupported_action':
                action=255
            result=journal.access(key+':attempt',eid,p,action)
            expected=category=='authorized'
            row={'case_id':key,'category':category,'evidence_id':eid,'expected_decision':expected,
                 'actual_decision':bool(result['allowed']),'correct':bool(result['allowed'])==expected,
                 'gas_used':int(result['gasUsed']),'transaction_hash':result['transactionHash'],
                 'proof_generation_ms':base['generationMs'],'proof_verification_ms':base['verificationMs'],
                 'latency_ms':None if resumed else (time.perf_counter()-start)*1000 - setup_ms + (base['generationMs']+base['verificationMs'] if category=='expired_credential' else 0),
                 'latency_method':'stored proof-generation/verification stages plus current access elapsed' if category=='expired_credential' else 'monotonic proof-to-receipt elapsed',
                 'latency_recovery_note':'interrupted workflow; omitted from latency statistics' if resumed else '', 'layer':'on-chain','evidence_type':'measured',
                 'expiry_note':'proof generated while valid; expired credential rejected on-chain after epoch advance' if category=='expired_credential' else ''}
            journal.save(key+':row',row)
        if not any(r.get('case_id')==key for r in exp.e2):
            exp.e2.append(row)
            if row['latency_ms'] is not None:exp.latency['end_to_end_access_ms'].append(row['latency_ms'])
        save()
        if (index+1)%25==0:print(f'Benchmark E2 {index+1}/{len(cases)}',flush=True)

    for i in range(99):
        _,commitment=journal.credential(f'revocation-{i:03d}')
        journal.tx(f'revoke-{i:03d}','revoke',credentialCommitment=commitment)
    verify_cred,_=journal.credential('paid-verify')
    for i in range(100):
        p=journal.proof(f'paid-proof-{i}',verify_cred,items[300+i]['eid'])
        result=journal.tx(f'paid-verify-{i}','verifyPaid',publicSignals=p['publicSignals'],proof=p['proof'])
        if not result['valid']:raise RuntimeError('Paid verification failed')
        if (i+1)%25==0:print(f'Benchmark paid verifier {i+1}/100',flush=True)
        save()
    return save(complete=True)
