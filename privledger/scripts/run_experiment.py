"""Run real encrypted-IPFS/EVM workflows with separately labelled simulations."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import csv
import hashlib
import importlib.metadata
import json
import os
import platform
import secrets
import subprocess
import time
import traceback
import yaml
from web3 import Web3
from privledger.blockchain import Chain
from privledger.hashing import sha256_hex, keccak256_hex, metadata_commitment
from privledger.encryption import generate_key, encrypt, decrypt
from privledger.ingestion import build_candidates, select_artifacts, manifest, find_dataset
from privledger.storage import KuboClient
from privledger.metrics import summarize
from privledger.privacy import scan_pii, extract_pii
from privledger.policy import generate_workload
from privledger.linkability import run_linkability
from privledger.reporting import generate_report, generate_plots

def write_json(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, indent=2, default=str), encoding='utf-8')

def write_csv(path, rows, fields=None):
    rows = list(rows)
    fields = fields or list(dict.fromkeys(k for row in rows for k in row))
    with Path(path).open('w',newline='',encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields or ['evidence_type'], extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)

def hx(value):
    return '0x'+value

def environment(config, ipfs):
    def command(args):
        try:
            r = subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=15)
            return r.stdout.strip() if r.returncode == 0 else 'unavailable'
        except (OSError,subprocess.TimeoutExpired):
            return 'unavailable'
    versions = {}
    for name in ['numpy','pandas','scikit-learn','web3','cryptography','PyYAML','matplotlib','pytest']:
        versions[name] = importlib.metadata.version(name)
    for name in ['hardhat','solc','circom2','snarkjs']:
        versions[name] = json.loads((ROOT/'node_modules'/name/'package.json').read_text())['version']
    return {'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'os': platform.platform(),
            'python': sys.version, 'node': command(['node','--version']), 'versions': versions,
            'npm': command(['npm','--version']), 'kubo': ipfs.version(), 'docker': command(['docker','--version']),
            'cpu_model': platform.processor(), 'logical_cpu_count': os.cpu_count(),
            'git_commit': command(['git','rev-parse','HEAD']), 'git_status': command(['git','status','--porcelain']),
            'seed': config['reproducibility']['seed'],
            'config_sha256': sha256_hex(yaml.safe_dump(config,sort_keys=True).encode())}

def fixture():
    folder = ROOT/'.runtime/smoke/maildir'
    for cust in ('lay-k','skilling-j','kaminski-v'):
        target = folder/cust/'inbox'
        target.mkdir(parents=True,exist_ok=True)
        for i in range(4):
            (target/str(i)).write_bytes((f'From: Synthetic Researcher <fixture{i}@example.invalid>\nTo: fixture-recipient@example.invalid\nSubject: Synthetic research fixture {cust} {i}\n\nSynthetic evidence body for unit and smoke testing only {i}.\n').encode())
    return folder

class Experiment:
    def __init__(self, args):
        self.args = args
        self.config = yaml.safe_load((ROOT/'configs/privledger_config.yaml').read_text())
        self.seed = self.config['reproducibility']['seed']
        self.choices = self.config['implementation_choices']
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
        self.out = ROOT/'results'/f'run_{stamp}_{args.mode}'
        self.out.mkdir(parents=True)
        self.secret_dir = ROOT/'secrets'/self.out.name
        self.secret_dir.mkdir(parents=True)
        self.salt = secrets.token_bytes(32)
        (self.secret_dir/'metadata_salt.bin').write_bytes(self.salt)
        self.ipfs = KuboClient(os.getenv('IPFS_API',self.choices['ipfs_api']))
        self.chain = Chain(ROOT,self.out/'bridge.log')
        self.web3 = Web3(Web3.HTTPProvider(self.choices['rpc_url']))
        self.gas = defaultdict(list)
        self.latency = defaultdict(list)
        self.receipts = []
        self.integrity = []
        self.metadata = []
        self.scale = []
        self.e2 = []
        self.redactions = []
        self.deletions = []
        self.pii = {'passed': True,'plaintext_pii_matches': 0,'plaintext_pii_bytes': 0,'fields_checked': 0,'findings': [],'evidence_type':'measured','scope':'Per-artifact source terms at least 8 UTF-8 bytes, plus email regex; actual calldata, decoded arguments, event data/topics and state. Short terms excluded to reduce random-byte collisions. This is not an inference-resistance test.'}
        self.summary = {'mode':args.mode,'status':'running','limitations':[
            'Controlled local prototype; Hardhat automining is not public-chain finality.',
            'Full artifact ingestion/registration measured; full lifecycle mix simulated; live proof-backed lifecycle sample bounded to 10.',
            'CMU corpus excludes attachments; MIME attachments tested with fixtures only.',
            'Local trusted setup, administrative issuance and DID/VC prototype, not production identity infrastructure.',
            'On-chain account and credential commitments remain linkable; rotating-DID attacker experiment is a separate simulation.',
            'Deletion is logical plus local unpin; proof reference is an authorization proof, not proof of universal physical erasure.',
            'Registration uses hashes and RBAC; registration-correctness ZKP and ring signatures are not implemented.',
            'Retention is recorded metadata, not enforced legal policy. Independent security audit and multisignature governance not evaluated.',
            'E6 anomaly detection and E8 human usability are future work; no scores fabricated.']}

    def timed(self, metric, fn):
        t = time.perf_counter_ns()
        result = fn()
        elapsed = (time.perf_counter_ns()-t)/1e6
        self.latency[metric].append(elapsed)
        return result

    def tx(self, op, **kwargs):
        result = self.chain.call(op,**kwargs)
        if 'gasUsed' in result:
            self.gas[op].append(int(result['gasUsed']))
            self.latency['transaction_submission_to_receipt_ms'].append(result['transactionMs'])
            row = {'operation':op, **result, 'evidence_type':'measured'}
            self.receipts.append(row)
            with (self.out/'transaction_receipts.jsonl').open('a',encoding='utf-8') as f:
                f.write(json.dumps(row)+'\n')
        return result

    def proof(self, credential, evidence_id, action=1, **kw):
        result = self.chain.call('prove',**credential,evidenceId=evidence_id,action=action,**kw)
        self.latency['zkp_generation_ms'].append(result['generationMs'])
        self.latency['zkp_offchain_verification_ms'].append(result['verificationMs'])
        return result

    def issue(self,role=1):
        credential = {'secret':str(secrets.randbelow(2**250)+1),'role':role,'expiry':self.chain.call('status')['epoch']+365}
        r = self.tx('issue',**credential)
        # Keep the private witness out of reports and logs.
        write_json(self.secret_dir/f'credential_{len(self.receipts)}.json',credential)
        return credential,r['credentialCommitment']

    def access(self,eid,proof,action=1,**kw):
        args = {k:proof[k] for k in ('credentialCommitment','nullifierHash','proof')}
        args.update(kw)
        return self.tx('access',evidenceId=eid,action=action,**args)

    def case(self,name,expected,fn,layer='on-chain'):
        t = time.perf_counter_ns()
        result = fn()
        actual = bool(result['allowed'])
        self.e2.append({'case_id':name,'expected_decision':expected,'actual_decision':actual,'correct':actual==expected,
                        'gas_used':result.get('gasUsed'),'latency_ms':(time.perf_counter_ns()-t)/1e6,'layer':layer,'evidence_type':'measured'})
        return result

    def register_artifact(self,artifact,index,n):
        start = time.perf_counter_ns()
        raw = artifact.read_bytes()
        sha = self.timed('hash_sha256_ms',lambda:sha256_hex(raw))
        kek = self.timed('hash_keccak_ms',lambda:keccak256_hex(raw))
        eid = hx(sha256_hex(f'{n}:{artifact.stable_id}'.encode()))
        key = generate_key()
        blob = self.timed('encryption_ms',lambda:encrypt(raw,key))
        (self.secret_dir/f'{eid[2:]}.key').write_bytes(key)
        cid = self.timed('ipfs_add_ms',lambda:self.ipfs.add(blob))
        meta = {'evidence_id':eid,'byte_length':len(raw),'sha256_digest':sha,'keccak256_digest':kek,'artifact_type':artifact.artifact_type}
        commitment = metadata_commitment(meta,self.salt)
        receipt = self.tx('register',evidenceId=eid,sha256Digest=hx(sha),keccakDigest=hx(kek),zkCommitment=hx(commitment),cid=cid,
                          custodianDidHash=hx(sha256_hex(self.salt+artifact.custodian.encode())))
        self.latency['end_to_end_registration_ms'].append((time.perf_counter_ns()-start)/1e6)
        fetched = self.timed('ipfs_retrieval_ms',lambda:self.ipfs.cat(cid))
        recovered = decrypt(fetched,key)
        state = self.chain.call('evidence',evidenceId=eid)
        hash_ok = hx(sha256_hex(recovered))==state['sha256Digest'] and hx(keccak256_hex(recovered))==state['keccakDigest']
        tampered = bytes([raw[0]^1])+raw[1:] if raw else b'x'
        tamper = hx(sha256_hex(tampered))!=state['sha256Digest'] and hx(keccak256_hex(tampered))!=state['keccakDigest']
        event_topic = Web3.keccak(text='EvidenceRegistered(bytes32,bytes32,bytes32,string)').hex()
        event_ok = any(l['topics'][0].removeprefix('0x')==event_topic.removeprefix('0x') for l in receipt['logs'])
        self.integrity.append({'sample_size':n,'evidence_id':eid,'hash_fidelity':hash_ok,'tamper_detected':tamper,'registration_event':event_ok,
                               'ipfs_retrieval_success':fetched==blob,'onchain_offchain_consistency':hash_ok and state['cid']==cid,'evidence_type':'measured'})
        row = {'artifact_index':index,'sample_size':n,**meta,'custodian':sha256_hex(self.salt+artifact.custodian.encode()),
               'source_relative_path_hash':sha256_hex(artifact.source_relative_path.encode()),'attachment_index':artifact.attachment_index,
               'metadata_commitment':commitment,'custodian_did_hash':state['custodianDidHash'],'retention_until':0,
               'encrypted_artifact_path':'IPFS:'+cid,'ipfs_cid':cid,'selection_seed':self.seed,'evidence_type':'measured'}
        self.metadata.append(row)
        # Scan actual submitted bytes, decoded registration arguments and resulting state/events.
        transaction = self.web3.eth.get_transaction(receipt['transactionHash'])
        surfaces = {'calldata':transaction['input'].hex(),'state':state,'logs':receipt['logs'],'decoded_arguments':{'evidenceId':eid,'sha256Digest':hx(sha),'keccakDigest':hx(kek),'zkCommitment':hx(commitment),'cid':cid,'custodianDidHash':state['custodianDidHash']}}
        terms = [s for s in extract_pii(raw) if len(s.encode('utf-8'))>=8]
        scan = scan_pii(surfaces,terms)
        self.pii['fields_checked'] += len(surfaces)
        self.pii['plaintext_pii_matches'] += scan['finding_count']
        self.pii['findings'].extend(scan['findings'])
        self.pii['passed'] &= scan['passed']
        with (self.out/'onchain_export.jsonl').open('a',encoding='utf-8') as f:
            f.write(json.dumps(surfaces)+'\n')
        return {'eid':eid,'cid':cid,'key':key,'raw':raw,'sha':sha,'blob_bytes':len(blob)}

    def lifecycle(self,items):
        first = items[0]
        credential, _ = self.issue()
        proof = self.proof(credential,first['eid'])
        self.case('authorized_investigator',True,lambda:self.access(first['eid'],proof))
        self.case('replayed_nullifier',False,lambda:self.access(first['eid'],proof))
        for role,name in [(2,'authorized_auditor'),(3,'authorized_legal_authority')]:
            cred,_ = self.issue(role)
            p = self.proof(cred,first['eid'],role)
            self.case(name,True,lambda p=p,role=role:self.access(first['eid'],p,role))
        self.case('wrong_role',False,lambda:self.access(first['eid'],proof,2))
        self.case('unknown_credential',False,lambda:self.access(first['eid'],proof,credentialCommitment=hx('0'*63+'1')))
        invalid_proof = dict(proof); invalid_proof['proof'] = '0x'
        self.case('invalid_zkp',False,lambda:self.access(items[1]['eid'],invalid_proof))
        # Different active evidence avoids replay short circuit, exercising invalid public binding.
        fresh,_ = self.issue()
        fresh_proof = self.proof(fresh,items[1]['eid'])
        self.case('altered_public_input',False,lambda:self.access(first['eid'],fresh_proof))
        self.case('unknown_evidence',False,lambda:self.access(hx('ab'*32),fresh_proof))
        self.case('conflicting_policy_unsupported_action',False,lambda:self.access(items[1]['eid'],fresh_proof,255))
        self.tx('revoke',credentialCommitment=fresh_proof['credentialCommitment'])
        self.case('revoked_credential',False,lambda:self.access(items[1]['eid'],fresh_proof))
        # Expiry is tested by actual circuit witness rejection at a future evaluation epoch.
        try:
            self.proof(credential,first['eid'],epoch=credential['expiry']+1)
            expired = {'allowed':True}
        except RuntimeError:
            expired = {'allowed':False}
        self.case('expired_credential',False,lambda:expired,layer='Groth16 witness constraint')
        bench,_ = self.issue()
        for item in items:
            t = time.perf_counter_ns()
            p = self.proof(bench,item['eid'])
            r = self.access(item['eid'],p)
            self.latency['end_to_end_access_ms'].append((time.perf_counter_ns()-t)/1e6)
            if not r['allowed']:
                raise RuntimeError('Fresh benchmark access denied')
        # A legal-role authorization proof is referenced by each live lifecycle event.
        for i,item in enumerate(items[:min(3,len(items))]):
            cred,_ = self.issue(3)
            p = self.proof(cred,item['eid'],3)
            auth = self.access(item['eid'],p,3)
            if not auth['allowed']:
                raise RuntimeError('Lifecycle authorization denied')
            proof_ref = hx(sha256_hex(bytes.fromhex(p['proof'][2:])))
            write_json(self.out/f'lifecycle_authorization_{i}.json',{'publicSignals':p['publicSignals'],'proof':p['proof'],'proof_ref':proof_ref,'receipt':auth})
            t = time.perf_counter_ns()
            redacted = b'[REDACTED RESEARCH EVIDENCE]\n'+sha256_hex(item['raw']).encode()
            blob = encrypt(redacted,item['key'])
            cid = self.ipfs.add(blob)
            child = hx(sha256_hex((item['eid']+':redacted').encode()))
            self.tx('register',evidenceId=child,sha256Digest=hx(sha256_hex(redacted)),keccakDigest=hx(keccak256_hex(redacted)),cid=cid)
            attestation = hx(sha256_hex(json.dumps({'operation':'redact','parent':item['eid'],'child':child,'cid':cid},sort_keys=True).encode()))
            rr = self.tx('redact',parentEvidenceId=item['eid'],childEvidenceId=child,cid=cid,storageAttestationHash=attestation,proofRef=proof_ref)
            child_state = self.chain.call('evidence',evidenceId=child)
            parent_state = self.chain.call('evidence',evidenceId=item['eid'])
            recovered = decrypt(self.ipfs.cat(cid),item['key'])
            self.redactions.append({'parent':item['eid'],'child':child,'lineage_valid':child_state['parent']==item['eid'],
                                     'replacement_verified':recovered==redacted,'original_hash_preserved':parent_state['sha256Digest']==hx(item['sha']),
                                     'event_emitted':bool(rr['logs']),'proof_reference_available':(self.out/f'lifecycle_authorization_{i}.json').exists(),'evidence_type':'measured'})
            self.latency['end_to_end_redaction_ms'].append((time.perf_counter_ns()-t)/1e6)
            t = time.perf_counter_ns()
            unpin = self.ipfs.unpin(item['cid'])
            dr = self.tx('delete',evidenceId=item['eid'],storageAttestationHash=hx(sha256_hex(json.dumps(unpin,sort_keys=True).encode())),proofRef=proof_ref)
            deleted_state = self.chain.call('evidence',evidenceId=item['eid'])
            self.deletions.append({'evidence_id':item['eid'],'local_unpin_success':item['cid'] in unpin.get('Pins',[]),
                                   'logical_deleted':int(deleted_state['state'])==3,'event_emitted':bool(dr['logs']),'proof_reference_available':True,'evidence_type':'measured'})
            self.latency['end_to_end_deletion_ms'].append((time.perf_counter_ns()-t)/1e6)
        self.case('deleted_evidence',False,lambda:self.access(first['eid'],proof))

    def finish(self):
        def rate(rows,key):
            return sum(bool(r[key]) for r in rows)/len(rows) if rows else None
        e1 = {'count':len(self.integrity),'hash_fidelity_rate':rate(self.integrity,'hash_fidelity'),
              'tamper_detection_rate':rate(self.integrity,'tamper_detected'),'registration_event_completeness':rate(self.integrity,'registration_event'),
              'ipfs_retrieval_success':rate(self.integrity,'ipfs_retrieval_success'),'onchain_offchain_consistency':rate(self.integrity,'onchain_offchain_consistency'),'evidence_type':'measured'}
        e2 = {'count':len(self.e2),'correct_decisions':sum(r['correct'] for r in self.e2),'controlled_policy_correctness':rate(self.e2,'correct'),'evidence_type':'measured'}
        e4 = {'redaction_count':len(self.redactions),'deletion_count':len(self.deletions),'redaction_traceability_rate':rate(self.redactions,'event_emitted'),
              'proof_reference_availability':rate(self.redactions+self.deletions,'proof_reference_available'),
              'deletion_event_completeness':rate(self.deletions,'event_emitted'),'local_unpin_success':rate(self.deletions,'local_unpin_success'),
              'lineage_validation_rate':rate(self.redactions,'lineage_valid'),'evidence_type':'measured'}
        write_csv(self.out/'metadata.csv',self.metadata)
        write_csv(self.out/'e1_integrity_results.csv',self.integrity)
        write_json(self.out/'e1_integrity_summary.json',e1)
        write_csv(self.out/'e2_access_results.csv',self.e2)
        write_json(self.out/'e2_access_summary.json',e2)
        write_json(self.out/'e3_pii_scan.json',self.pii)
        write_csv(self.out/'e4_redaction_results.csv',self.redactions)
        write_csv(self.out/'e4_deletion_results.csv',self.deletions)
        write_json(self.out/'e4_summary.json',e4)
        gas_rows = [{'operation':op,**summarize(v),'evidence_type':'measured'} for op,v in self.gas.items()]
        latency_rows = [{'metric':op,**summarize(v),'unit':'ms','evidence_type':'measured'} for op,v in self.latency.items()]
        write_csv(self.out/'gas_results.csv',gas_rows)
        write_csv(self.out/'latency_results.csv',latency_rows)
        write_csv(self.out/'scalability_results.csv',self.scale)
        self.summary.update({'E1':e1,'E2':e2,'E3':{'pii':self.pii,'linkability':self.summary.get('linkability',{})},'E4':e4,
                             'E5':{'gas':gas_rows,'latency':latency_rows},'scalability':self.scale})
        write_json(self.out/'summary.json',self.summary)
        generate_plots(self.out)
        generate_report(self.out,self.summary)
        inventory = [{'path':str(p.relative_to(self.out)),'bytes':p.stat().st_size,'sha256':hashlib.file_digest(p.open('rb'),'sha256').hexdigest()} for p in self.out.rglob('*') if p.is_file() and p.name!='inventory.json']
        write_json(self.out/'inventory.json',inventory)

    def run(self):
        print(f'Run directory: {self.out}',flush=True)
        try:
            self.summary['environment'] = environment(self.config,self.ipfs)
            write_json(self.out/'environment.json',self.summary['environment'])
            (self.out/'config_used.yaml').write_text(yaml.safe_dump(self.config,sort_keys=False))
            self.summary['deployment'] = self.chain.call('deploy')
            write_json(self.out/'deployment.json',self.summary['deployment'])
            root = fixture() if self.args.mode=='smoke' else find_dataset(ROOT,self.args.dataset)
            self.summary['dataset'] = {'name':'synthetic fixtures' if self.args.mode=='smoke' else 'CMU Enron 2015','root':str(root),'real_enron':self.args.mode!='smoke'}
            t = time.perf_counter()
            candidates = build_candidates(root)
            preprocessing = time.perf_counter()-t
            sizes = self.config['dataset']['sample_sizes'] if self.args.mode=='full' else [self.choices[self.args.mode+'_size']]
            manifests = []
            last_items = []
            for n in sizes:
                print(f'Processing {n} artifacts with real IPFS and EVM',flush=True)
                begin = time.perf_counter()
                selected = select_artifacts(candidates,n,self.seed)
                manifests.append(manifest(root,candidates,selected,self.seed))
                items = []
                byte_sum = 0
                for i,a in enumerate(selected):
                    item = self.register_artifact(a,i,n)
                    byte_sum += item['blob_bytes']
                    live_limit = (self.choices['live_lifecycle_sample_limit'] if self.args.mode == 'smoke'
                                  else self.choices[f'{self.args.mode}_live_lifecycle_sample_limit'])
                    if len(items)<live_limit:
                        items.append(item)
                    if (i+1)%100 == 0:
                        print(f'{n}: {i+1}/{n} artifacts verified',flush=True)
                        write_csv(self.out/'e1_integrity_results.csv',self.integrity)
                elapsed = time.perf_counter()-begin
                rows = [r for r in self.metadata if r['sample_size']==n]
                workload = generate_workload([r['evidence_id'] for r in rows],self.seed,self.choices['access_allow_ratio'],self.choices['redaction_probability'],self.choices['deletion_probability'])
                write_csv(self.out/f'simulated_lifecycle_{n}.csv',[{**e,'evidence_type':'simulated'} for e in workload])
                self.scale.append({'sample_size':n,'runtime_seconds':elapsed,'preprocessing_seconds':preprocessing,
                                   'registration_throughput_per_second':n/elapsed,'ipfs_payload_bytes':byte_sum,
                                   'metadata_bytes':len(json.dumps(rows).encode()),'simulated_lifecycle_event_count':len(workload),
                                   'measured_registration_transactions':n,'evidence_type':'measured','workload_evidence_type':'simulated'})
                last_items = items
            write_json(self.out/'manifest.json',{'samples':manifests,'seed':self.seed})
            print('Running proof-backed access, redaction and deletion cases',flush=True)
            self.lifecycle(last_items)
            print('Running 10000-pair linkability simulation',flush=True)
            self.summary['linkability'] = run_linkability(self.out,pairs=10000,seed=self.seed)
            threats = yaml.safe_load((ROOT/'configs/threats.yaml').read_text())['threats']
            write_csv(self.out/'e0_threat_coverage.csv',threats)
            reliability = [{'scenario':s,'rpo_target':0,'rto_target_seconds':60,'evidence_loss_target':0,'assumption':'Durable pinned storage and committed ledger survive; restoration within target assumed, not measured','evidence_type':'analytical'} for s in ['IPFS restart','blockchain client restart','temporary network partition','off-chain unavailable']]
            write_csv(self.out/'e7_reliability_results.csv',reliability)
            self.summary['E7'] = {'scenarios':reliability,'live_restart':'not evaluated by default runner','evidence_type':'analytical'}
            write_json(self.out/'e7_reliability_summary.json',self.summary['E7'])
            # A separate analytical model adds assumed confirmation delay to measured off-chain work.
            analytical = []
            for op in ['registration','access','redaction','deletion']:
                v = self.latency.get(f'end_to_end_{op}_ms',[])
                count = 2 if op=='redaction' else 1
                analytical.append({'operation':op,'measured_local_mean_ms':summarize(v)['mean'],'assumed_transaction_count':count,
                                   'assumed_confirmation_ms_per_transaction':4000,'analytical_mean_ms':summarize(v)['mean']+4000*count if v else None,'evidence_type':'analytical',
                                   'model':'local measured workflow plus assumed confirmation delay; local submission overhead retained'})
            write_csv(self.out/'analytical_latency.csv',analytical)
            self.summary['status'] = 'passed' if self.pii['passed'] and all(r['correct'] for r in self.e2) and all(all(r[k] for k in ['hash_fidelity','tamper_detected','registration_event','ipfs_retrieval_success','onchain_offchain_consistency']) for r in self.integrity) else 'failed'
        except Exception as e:
            self.summary['status'] = 'failed'
            self.summary['failure'] = str(e)
            (self.out/'failure_traceback.txt').write_text(traceback.format_exc())
            raise
        finally:
            self.chain.close()
            self.finish()
            print(f"Result: {self.summary['status']}; {self.out/'REPORT.md'}",flush=True)
        return 0 if self.summary['status']=='passed' else 1

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--mode',choices=['smoke','quick','full'],default='smoke')
    p.add_argument('--dataset')
    p.add_argument('--resume',action='store_true')
    p.add_argument('--workload',type=int,choices=[1000,5000,10000])
    p.add_argument('--resume-test',action='store_true',help='Four real integration fixtures for checkpoint testing only')
    p.add_argument('--stop-after',type=int,help='Intentional checkpoint test pause after N new artifacts')
    args=p.parse_args()
    if args.mode=='full' or args.resume_test:
        from full_checkpoint_runner import main
        sys.exit(main(args))
    sys.exit(Experiment(args).run())
