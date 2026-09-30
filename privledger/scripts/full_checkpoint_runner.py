"""Checkpointed continuation of the existing real PrivLedger experiment."""
from run_experiment import *
from privledger.checkpoints import append_record, read_records, latest_records, atomic_json
from privledger.ingestion import Artifact
import random
import shutil
import psutil

FIELDS = ['hash_fidelity','tamper_detected','registration_event','ipfs_retrieval_success','onchain_offchain_consistency']

class ResumableExperiment(Experiment):
    def __init__(self,args):
        self.args=args
        self.config=yaml.safe_load((ROOT/'configs/privledger_config.yaml').read_text())
        self.seed=42; self.choices=self.config['implementation_choices']
        self.cp=ROOT/('work/resume_test' if args.resume_test else 'results/checkpoints')
        self.cp.mkdir(parents=True,exist_ok=True)
        self.out=self.cp/'staging'; self.out.mkdir(exist_ok=True)
        self.session_path=self.cp/'session.json'
        self.ipfs=KuboClient(self.choices['ipfs_api'])
        self.web3=Web3(Web3.HTTPProvider(self.choices['rpc_url']))
        self.chain=Chain(ROOT,self.out/'bridge.log')
        self.gas=defaultdict(list); self.latency=defaultdict(list)
        self.receipts=[];self.integrity=[];self.metadata=[];self.scale=[]
        self.e2=[];self.redactions=[];self.deletions=[]
        self.pii={'passed':True,'plaintext_pii_matches':0,'plaintext_pii_bytes':0,'fields_checked':0,'findings':[],
                  'evidence_type':'measured','scope':'Actual calldata/events/state; source terms >=8 bytes plus email regex. Short terms excluded; this does not test metadata inference.'}
        if self.session_path.exists():
            if not args.resume: raise RuntimeError('Existing checkpoint session; specify --resume to preserve and continue it')
            self.session=json.loads(self.session_path.read_text())
            address=self.session['deployment']['address']
            try:
                receipt=self.web3.eth.get_transaction_receipt(self.session['deployment_probe_tx'])
                if not receipt or not self.web3.eth.get_code(address): raise ValueError('Missing code')
                if self.web3.eth.get_block(0).hash.hex()!=self.session['genesis_hash']: raise ValueError('Genesis changed')
            except Exception as error:
                raise RuntimeError('Checkpoint ledger is unavailable or changed. Keep its records; restore the owned node before resuming. No registrations were skipped.') from error
            self.chain.call('attach',address=address)
        else:
            deployment=self.chain.call('deploy')
            genesis=self.web3.eth.get_block(0).hash.hex()
            latest=self.web3.eth.get_block('latest',full_transactions=True)
            stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
            secret_dir=ROOT/'secrets'/('checkpoint_'+stamp+('_test' if args.resume_test else ''))
            secret_dir.mkdir(parents=True,exist_ok=True)
            (secret_dir/'metadata_salt.bin').write_bytes(secrets.token_bytes(32))
            self.session={'deployment':deployment,'genesis_hash':genesis,'deployment_probe_tx':latest.transactions[-1]['hash'].hex(),
                          'created_utc':datetime.now(timezone.utc).isoformat(),'secret_dir':str(secret_dir),'workloads':{}}
            atomic_json(self.session_path,self.session)
        self.secret_dir=Path(self.session['secret_dir'])
        self.salt=(self.secret_dir/'metadata_salt.bin').read_bytes()
        self.contract=self.web3.eth.contract(address=self.session['deployment']['address'],abi=json.loads((ROOT/'abi/PrivLedger.json').read_text()))
        self.summary={'mode':'full','status':'running','deployment':self.session['deployment'],
          'limitations':['Local prototype receipts are not Ethereum mainnet finality.',
          'All 16000 scale registrations are real; seeded full lifecycle event mixes are simulated separately from bounded live benchmarks.',
          'CMU release contains messages without original attachment payloads.',
          'Stable on-chain credentials and transaction account remain linkable; E3 rotating-DID results are a separate event-pair simulation.',
          'Research-only single-party Groth16 setup; no production DID infrastructure, ring signatures or independent audit.',
          'Logical deletion and local unpin are not global erasure; storage attestations are orchestrator statements.',
          'Registration is RBAC plus digest anchoring, not a registration-correctness ZKP; retention metadata is not enforced legal policy.',
          'Previous 1000/partial5000 retained as prior evidence, not pooled: the ephemeral ledger was unavailable and complete phase timings absent.'],
          'E6':{'status':'not evaluated','evidence_type':'future-work'},'E8':{'status':'not evaluated','evidence_type':'future-work'}}
        if not (self.out/'environment.json').exists():
            atomic_json(self.out/'environment.json',environment(self.config,self.ipfs))
            (self.out/'config_used.yaml').write_text(yaml.safe_dump(self.config,sort_keys=False))
        self.summary['environment']=json.loads((self.out/'environment.json').read_text())
        atomic_json(self.out/'deployment.json',self.session['deployment'])

    def tx(self,op,**kwargs):
        result=self.chain.call(op,**kwargs)
        if 'gasUsed' in result:
            row={'operation':op,**result,'evidence_type':'measured'}
            append_record(self.out/'transaction_receipts.jsonl',row)
            self.receipts.append(row);self.gas[op].append(int(result['gasUsed']))
            self.latency['transaction_submission_to_receipt_ms'].append(result['transactionMs'])
        return result

    def load_candidates(self):
        start=time.perf_counter()
        fixture_root=ROOT/'.runtime/smoke/maildir'
        self.dataset_root=(fixture_root if fixture_root.exists() else fixture()) if self.args.resume_test else find_dataset(ROOT,self.args.dataset)
        cache=self.cp/'candidate_inventory.json'
        if cache.exists():
            inventory=json.loads(cache.read_text())
            current=[]
            for custodian in ('lay-k','skilling-j','kaminski-v'):
                current.extend(sorted(str(p.relative_to(self.dataset_root).as_posix()) for p in (self.dataset_root/custodian).rglob('*') if p.is_file()))
            if sorted(set(i['source_relative_path'] for i in inventory))!=sorted(current):
                raise RuntimeError('Candidate dataset file list changed; do not pool incompatible selections')
            self.candidates=[]
            for row in inventory:
                row=dict(row);size=row.pop('source_size');mtime=row.pop('source_mtime_ns');source=self.dataset_root/row['source_relative_path']
                stat=source.stat()
                if stat.st_size!=size or stat.st_mtime_ns!=mtime: raise RuntimeError('Dataset bytes may have changed since checkpoint inventory')
                self.candidates.append(Artifact(**row,source=source))
        else:
            self.candidates=build_candidates(self.dataset_root)
            inventory=[]
            for a in self.candidates:
                stat=a.source.stat()
                inventory.append({'stable_id':a.stable_id,'custodian':a.custodian,'source_relative_path':a.source_relative_path,
                                  'artifact_type':a.artifact_type,'attachment_index':a.attachment_index,'source_size':stat.st_size,'source_mtime_ns':stat.st_mtime_ns})
            atomic_json(cache,inventory)
        self.preprocessing_seconds=time.perf_counter()-start
        self.summary['dataset']={'name':'synthetic resume fixtures' if self.args.resume_test else 'CMU Enron 2015','candidate_count':len(self.candidates),
            'counts_by_custodian':{c:sum(a.custodian==c and a.artifact_type=='email' for a in self.candidates) for c in ('lay-k','skilling-j','kaminski-v')},
            'attachment_count':sum(a.artifact_type=='attachment' for a in self.candidates),'selected_sizes':[1000,5000,10000],
            'attachment_availability':'The selected CMU Enron release contains email messages without the original attachment payloads.'}
        print(f'Candidate inventory: {len(self.candidates)}; preprocessing/validation {self.preprocessing_seconds:.2f}s',flush=True)

    def record_artifact(self,a,i,n,previous):
        journal=self.cp/f'workload_{n}.jsonl'
        record=dict(previous or {})
        record.update({'stable_id':a.stable_id,'stable_artifact_id':a.stable_id,'artifact_index':i,'sample_size':n,'workload_size':n,'timestamp_utc':datetime.now(timezone.utc).isoformat()})
        elapsed={};start=time.perf_counter()
        def timed(name,fn):
            t=time.perf_counter();value=fn();elapsed[name]=(time.perf_counter()-t)*1000;return value
        stage='read'
        try:
            raw=timed('artifact_read_ms',a.read_bytes)
            sha=timed('hash_sha256_ms',lambda:sha256_hex(raw));kek=timed('hash_keccak_ms',lambda:keccak256_hex(raw))
            eid=hx(sha256_hex(f'{n}:{a.stable_id}'.encode()))
            record.update({'evidence_id':eid,'sha256_digest':sha,'keccak256_digest':kek})
            keypath=self.secret_dir/f'{eid[2:]}.key'
            payloadpath=self.secret_dir/f'{eid[2:]}.ciphertext'
            if not keypath.exists(): keypath.write_bytes(generate_key())
            key=keypath.read_bytes()
            stage='encryption'
            if payloadpath.exists(): blob=payloadpath.read_bytes()
            else:
                blob=timed('encryption_ms',lambda:encrypt(raw,key));payloadpath.write_bytes(blob)
            stage='ipfs_add'
            cid=record.get('ipfs_cid')
            if not cid: cid=timed('ipfs_add_ms',lambda:self.ipfs.add(blob))
            meta={'evidence_id':eid,'byte_length':len(raw),'sha256_digest':sha,'keccak256_digest':kek,'artifact_type':a.artifact_type}
            commitment=metadata_commitment(meta,self.salt);did=hx(sha256_hex(self.salt+a.custodian.encode()))
            record.update({'state':'prepared','ipfs_cid':cid,'encrypted_payload_bytes':len(blob),'latencies_ms':{**record.get('latencies_ms',{}),**elapsed}})
            append_record(journal,record)
            stage='registration'
            state=self.chain.call('evidence',evidenceId=eid)
            receipt=record.get('receipt')
            if int(state['state'])==0:
                receipt=timed('blockchain_registration_ms',lambda:self.tx('register',evidenceId=eid,sha256Digest=hx(sha),keccakDigest=hx(kek),zkCommitment=hx(commitment),cid=cid,custodianDidHash=did))
                record.update({'state':'registered','transaction_hash':receipt['transactionHash'],'gas_used':int(receipt['gasUsed']),'receipt':receipt,
                               'latencies_ms':{**record['latencies_ms'],**elapsed}})
                append_record(journal,record)
            elif receipt is None:
                # Crash after broadcast/receipt but before registered journal: recover receipt, never register twice.
                logs=self.web3.eth.get_logs({'address':self.contract.address,'fromBlock':0,'toBlock':'latest','topics':['0x'+Web3.keccak(text='EvidenceRegistered(bytes32,bytes32,bytes32,string)').hex().removeprefix('0x'),eid]})
                if len(logs)!=1: raise RuntimeError('Ambiguous registration recovery')
                r=self.web3.eth.get_transaction_receipt(logs[0]['transactionHash'])
                receipt={'transactionHash':r.transactionHash.hex(),'gasUsed':str(r.gasUsed),'blockNumber':r.blockNumber,
                         'transactionMs':None,'logs':[{'address':l.address,'topics':[t.hex() for t in l.topics],'data':l.data.hex()} for l in r.logs]}
                record['receipt_recovered_after_interruption']=True
            stage='verification'
            verify_start=time.perf_counter()
            fetched=timed('ipfs_retrieval_ms',lambda:self.ipfs.cat(cid))
            recovered=decrypt(fetched,key)
            state=self.chain.call('evidence',evidenceId=eid)
            hash_ok=hx(sha256_hex(recovered))==state['sha256Digest'] and hx(keccak256_hex(recovered))==state['keccakDigest']
            event_topic=Web3.keccak(text='EvidenceRegistered(bytes32,bytes32,bytes32,string)').hex().removeprefix('0x')
            event_ok=any(l['topics'][0].removeprefix('0x')==event_topic and l['topics'][1].lower().removeprefix('0x')==eid[2:] for l in receipt['logs'])
            tampered=bytes([raw[0]^1])+raw[1:] if raw else b'x'
            integrity={'sample_size':n,'evidence_id':eid,'hash_fidelity':hash_ok,'tamper_detected':sha256_hex(tampered)!=sha and keccak256_hex(tampered)!=kek,
              'registration_event':event_ok,'ipfs_retrieval_success':fetched==blob,'onchain_offchain_consistency':hash_ok and state['cid']==cid,'evidence_type':'measured'}
            elapsed['verification_ms']=(time.perf_counter()-verify_start)*1000
            transaction=self.web3.eth.get_transaction(receipt['transactionHash'])
            surfaces={'calldata':transaction['input'].hex(),'state':state,'logs':receipt['logs']}
            scan=scan_pii(surfaces,[s for s in extract_pii(raw) if len(s.encode('utf-8'))>=8])
            if not all(integrity[k] for k in FIELDS): raise ValueError('Integrity observation failed')
            if not scan['passed']: raise ValueError('PII scan found candidate matches; inspect hashed findings before continuing')
            elapsed['end_to_end_registration_ms']=(time.perf_counter()-start)*1000
            meta.update({'artifact_index':i,'sample_size':n,'custodian':sha256_hex(self.salt+a.custodian.encode()),'source_relative_path_hash':sha256_hex(a.source_relative_path.encode()),
                         'attachment_index':a.attachment_index,'metadata_commitment':commitment,'custodian_did_hash':did,'retention_until':0,'encrypted_artifact_path':'IPFS:'+cid,
                         'ipfs_cid':cid,'selection_seed':42,'evidence_type':'measured'})
            record.update({'state':'success','transaction_hash':receipt['transactionHash'],'registration_tx_hash':receipt['transactionHash'],'gas_used':int(receipt['gasUsed']),'registration_gas_used':int(receipt['gasUsed']),'registration_latency_ms':receipt.get('transactionMs'),'receipt':receipt,
              'latencies_ms':{**record.get('latencies_ms',{}),**elapsed},'integrity':integrity,'metadata':meta,'pii_scan':scan,'onchain_export':surfaces,
              'retrieval_verified':bool(fetched==blob),'hash_verified':bool(hash_ok),'elapsed_seconds':time.perf_counter()-start})
            append_record(journal,record)
            return record
        except Exception as error:
            failure={'stable_id':a.stable_id,'stable_artifact_id':a.stable_id,'sample_size':n,'workload_size':n,'stage':stage,'exception_class':type(error).__name__,'exception_type':type(error).__name__,'error_message':str(error),
                     'timestamp':datetime.now(timezone.utc).isoformat(),'state':'failure'}
            append_record(self.cp/'artifact_failures.jsonl',failure)
            append_record(journal,{**record,**failure})
            if isinstance(error,(ConnectionError,RuntimeError)) or stage in ('registration','ipfs_add') or 'PII' in str(error): raise
            return {**record,**failure}

    def workload(self,n):
        t=time.perf_counter();selected=select_artifacts(self.candidates,n,42);selection=time.perf_counter()-t
        m=manifest(self.dataset_root,self.candidates,selected,42)
        m.pop('generation_timestamp',None)
        repeat=manifest(self.dataset_root,self.candidates,select_artifacts(self.candidates,n,42),42);repeat.pop('generation_timestamp',None)
        if json.dumps(m,sort_keys=True)!=json.dumps(repeat,sort_keys=True): raise RuntimeError('Deterministic manifest mismatch')
        m['manifest_sha256']=sha256_hex(json.dumps(m,sort_keys=True).encode())
        m['deterministic_selection_verified']=True
        atomic_json(self.out/f'manifest_{n}.json',m)
        records=latest_records(self.cp/f'workload_{n}.jsonl')
        valid_ids={a.stable_id for a in selected}
        if set(records)-valid_ids: raise RuntimeError('Checkpoint artifacts outside current selection')
        # Verify each completed identity against persisted ledger before skipping it.
        for a in selected:
            r=records.get(a.stable_id,{})
            if r.get('state')=='success':
                current=a.read_bytes()
                if sha256_hex(current)!=r.get('sha256_digest') or keccak256_hex(current)!=r.get('keccak256_digest'):
                    raise RuntimeError(f'Checkpoint source hash changed for {a.stable_id}; refusing to skip registration')
                state=self.chain.call('evidence',evidenceId=r['evidence_id'])
                if state['cid']!=r['ipfs_cid'] or state['sha256Digest']!=hx(r['sha256_digest']): raise RuntimeError('Checkpoint anchor no longer matches ledger')
        ws=self.session['workloads'].setdefault(str(n),{'dataset_preprocessing_seconds':self.preprocessing_seconds,'dataset_selection_seconds':selection,'segments':[]})
        if ws.get('complete') and len(records)==n and all(r['state']=='success' for r in records.values()):
            print(f'{n}: checkpoint already complete; verified and skipped all {n} registrations',flush=True);return selected
        begin=time.perf_counter();new_count=0
        for i,a in enumerate(selected):
            if records.get(a.stable_id,{}).get('state')=='success': continue
            records[a.stable_id]=self.record_artifact(a,i,n,records.get(a.stable_id))
            new_count+=1
            done=sum(r.get('state')=='success' for r in records.values());failed=sum(r.get('state')=='failure' for r in records.values())
            if new_count%100==0 or i==len(selected)-1 or self.args.resume_test:
                elapsed=time.perf_counter()-begin;rate=new_count/elapsed
                print(f'{n}: processed={done+failed}/{n} remaining={n-done-failed} success={done} failures={failed} elapsed={elapsed:.1f}s ETA={(n-done-failed)/rate:.1f}s',flush=True)
                atomic_json(self.cp/'progress.json',{'workload':n,'successful':done,'failed':failed,'remaining':n-done-failed,'elapsed_seconds':elapsed})
            if self.args.stop_after and new_count>=self.args.stop_after:
                ws['segments'].append(time.perf_counter()-begin);atomic_json(self.session_path,self.session)
                print('Intentional checkpoint test pause; no final results generated',flush=True);return None
        ws['segments'].append(time.perf_counter()-begin);ws['complete']=len(records)==n
        ws['successful']=sum(r['state']=='success' for r in records.values());ws['failed']=n-ws['successful']
        atomic_json(self.session_path,self.session)
        self.export_workload(n,selected,records,ws)
        return selected

    def export_workload(self,n,selected,records,ws):
        success=[records[a.stable_id] for a in selected if records[a.stable_id]['state']=='success']
        write_csv(self.out/f'metadata_{n}.csv',[r['metadata'] for r in success])
        sim_start=time.perf_counter()
        workload=generate_workload([r['evidence_id'] for r in success],42,self.choices['access_allow_ratio'],self.choices['redaction_probability'],self.choices['deletion_probability'])
        write_csv(self.out/f'simulated_lifecycle_{n}.csv',[{**r,'evidence_type':'simulation-derived'} for r in workload])
        simulation=time.perf_counter()-sim_start
        execution=sum(ws['segments'])+simulation
        total=ws['dataset_selection_seconds']+ws['dataset_preprocessing_seconds']+execution
        gs=summarize(r['gas_used'] for r in success)
        row={'sample_size':n,'selected_artifact_count':n,'successful_registrations':len(success),'failed_registrations':n-len(success),
             'dataset_selection_seconds':ws['dataset_selection_seconds'],'dataset_preprocessing_seconds':ws['dataset_preprocessing_seconds'],
             'experiment_execution_seconds':execution,'total_wall_clock_seconds':total,'throughput_artifacts_per_second':len(success)/total,
             'metadata_bytes':(self.out/f'metadata_{n}.csv').stat().st_size,'encrypted_payload_bytes':sum(r['encrypted_payload_bytes'] for r in success),
             'onchain_event_count':sum(len(r['receipt']['logs']) for r in success),'simulated_lifecycle_event_count':len(workload),
             'event_simulation_seconds':simulation,'peak_python_memory_bytes':psutil.Process().memory_info().peak_wset if os.name=='nt' else psutil.Process().memory_info().rss,
             'gas_mean':gs['mean'],'gas_p95':gs['p95'],'evidence_type':'measured',
             'timing_definition':'Selection + candidate preprocessing/validation + active execution segments incl checkpoint fsync and privacy checks; excludes paused downtime. Workload1 bears initial candidate parsing, later rows report cache validation.'}
        for name,metrics in {'hashing_seconds':['hash_sha256_ms','hash_keccak_ms'],'encryption_seconds':['encryption_ms'],'ipfs_ingestion_seconds':['ipfs_add_ms'],
                             'blockchain_registration_seconds':['blockchain_registration_ms'],'verification_seconds':['verification_ms']}.items():
            row[name]=sum(r['latencies_ms'].get(k,0) for r in success for k in metrics)/1000
        atomic_json(self.cp/f'workload_{n}_summary.json',row)

    def load_all(self):
        self.gas=defaultdict(list);self.latency=defaultdict(list);self.metadata=[];self.integrity=[];self.scale=[]
        for n in [1000,5000,10000]:
            for r in latest_records(self.cp/f'workload_{n}.jsonl').values():
                if r['state']!='success':continue
                self.metadata.append(r['metadata']);self.integrity.append(r['integrity'])
                for name,value in r['latencies_ms'].items():self.latency[name].append(value)
                self.pii['fields_checked']+=3;self.pii['plaintext_pii_matches']+=r['pii_scan']['finding_count']
                self.pii['plaintext_pii_bytes']+=sum(f.get('matched_bytes',0) for f in r['pii_scan']['findings'])
                self.pii['findings'].extend(r['pii_scan']['findings'])
            self.scale.append(json.loads((self.cp/f'workload_{n}_summary.json').read_text()))
        self.receipts=read_records(self.out/'transaction_receipts.jsonl')
        for r in self.receipts:
            self.gas[r['operation']].append(int(r['gasUsed']))
            if r.get('transactionMs') is not None:self.latency['transaction_submission_to_receipt_ms'].append(r['transactionMs'])

    def items(self,selected,n,count):
        records=latest_records(self.cp/f'workload_{n}.jsonl')
        return [{'eid':records[a.stable_id]['evidence_id'],'cid':records[a.stable_id]['ipfs_cid'],
                 'key':(self.secret_dir/(records[a.stable_id]['evidence_id'][2:]+'.key')).read_bytes(),
                 'raw':a.read_bytes(),'sha':records[a.stable_id]['sha256_digest']} for a in selected[:count]]

    def complete(self,selected):
        self.load_all()
        failures=read_records(self.cp/'artifact_failures.jsonl')
        write_csv(self.out/'artifact_failures.csv',failures,['stable_id','sample_size','stage','exception_class','error_message','timestamp','state'])
        items=self.items(selected,10000,500)
        from full_benchmarks import run_benchmarks
        run_benchmarks(self,items)
        # Dedicated seeded sample, independently recomputed from raw selected artifacts.
        tamper=[]
        records=latest_records(self.cp/'workload_10000.jsonl')
        for a in random.Random(42).sample(selected,200):
            raw=a.read_bytes();mutated=bytes([raw[0]^1])+raw[1:] if raw else b'x';r=records[a.stable_id]
            tamper.append({'evidence_id':r['evidence_id'],'sha_reject':sha256_hex(mutated)!=r['sha256_digest'],'keccak_reject':keccak256_hex(mutated)!=r['keccak256_digest'],'evidence_type':'measured'})
        write_csv(self.out/'e1_tamper_sample.csv',tamper)
        from ipfs_recovery import run_recovery
        recovery=run_recovery(ROOT,items[450:460],self.out)
        self.summary['E7']=recovery
        atomic_json(self.out/'e7_reliability_summary.json',recovery)
        write_csv(self.out/'e7_reliability_results.csv',[{'scenario':'owned Kubo restart',**{k:v for k,v in recovery.items() if not isinstance(v,(dict,list))}}])
        self.summary['linkability']=run_linkability(self.out,pairs=10000,seed=42)
        threats=yaml.safe_load((ROOT/'configs/threats.yaml').read_text())['threats']
        for r in threats:r['evidence_type']='analytical'
        write_csv(self.out/'e0_threat_coverage.csv',threats)
        self.summary['status']='completed'
        self.summary['failed_artifacts']=len(failures)
        self.summary['E1_tamper_sample']={'count':200,'tamper_detection_rate':sum(r['sha_reject'] and r['keccak_reject'] for r in tamper)/200,'evidence_type':'measured'}
        self.write_aggregates()
        from finalize_full import finalize_outputs
        finalize_outputs(self.out,self.summary)
        destination=ROOT/'results'/('final_privledger_full_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
        shutil.copytree(self.out,destination)
        self.session['final_directory']=str(destination);atomic_json(self.session_path,self.session)
        print(f'FINAL COMPLETED OUTPUT: {destination}',flush=True)

    def write_aggregates(self):
        def rate(rows,key): return sum(bool(r[key]) for r in rows)/len(rows) if rows else None
        e1={'count':len(self.integrity),'hash_fidelity_rate':rate(self.integrity,'hash_fidelity'),'tamper_detection_rate':rate(self.integrity,'tamper_detected'),
            'registration_event_completeness':rate(self.integrity,'registration_event'),'ipfs_retrieval_success':rate(self.integrity,'ipfs_retrieval_success'),
            'onchain_offchain_consistency':rate(self.integrity,'onchain_offchain_consistency'),'evidence_type':'measured'}
        e2={'count':len(self.e2),'correct_decisions':sum(r['correct'] for r in self.e2),'incorrect_decisions':sum(not r['correct'] for r in self.e2),
            'controlled_policy_correctness':rate(self.e2,'correct'),'evidence_type':'measured'}
        e4={'redaction_count':len(self.redactions),'deletion_count':len(self.deletions),'redaction_traceability_rate':rate(self.redactions,'event_emitted'),
            'proof_reference_availability':rate(self.redactions+self.deletions,'proof_reference_available'),'deletion_event_completeness':rate(self.deletions,'event_emitted'),
            'local_unpin_success':rate(self.deletions,'local_unpin_success'),'lineage_validation_rate':rate(self.redactions,'lineage_valid'),'evidence_type':'measured'}
        for name,rows in [('e1_integrity_results',self.integrity),('e2_access_results',self.e2),('e4_redaction_results',self.redactions),('e4_deletion_results',self.deletions),('scalability_results',self.scale)]:write_csv(self.out/(name+'.csv'),rows)
        for name,data in [('e1_integrity_summary',e1),('e2_access_summary',e2),('e3_pii_scan',self.pii),('e4_summary',e4)]:atomic_json(self.out/(name+'.json'),data)
        gas_rows=[{'operation':op,**summarize(v),'evidence_type':'measured'} for op,v in self.gas.items()]
        latency_rows=[{'metric':op,**summarize(v),'unit':'ms','evidence_type':'measured'} for op,v in self.latency.items()]
        write_csv(self.out/'gas_results.csv',gas_rows);write_csv(self.out/'latency_results.csv',latency_rows)
        (self.out/'gas-reports').mkdir(exist_ok=True)
        write_csv(self.out/'gas-reports/transactions.csv',[{k:r.get(k) for k in ('operation','transactionHash','gasUsed','blockNumber','transactionMs','evidence_type')} for r in self.receipts])
        write_csv(self.out/'gas-reports/summary.csv',gas_rows)
        analytical=[]
        for op,count in [('registration',1),('access',1),('redaction',3),('deletion',2)]:
            stats=summarize(self.latency[f'end_to_end_{op}_ms']);delay=self.choices['confirmation_assumption_seconds']*1000
            analytical.append({'operation':op,'measured_local_mean_ms':stats['mean'],'assumed_transaction_count':count,
                'confirmation_assumption_seconds':delay/1000,'analytical_mean_ms':stats['mean']+delay*count,'evidence_type':'analytical'})
        write_csv(self.out/'analytical_latency.csv',analytical)
        self.summary.update({'E1':e1,'E2':e2,'E3':{'pii':self.pii,'linkability':self.summary['linkability']},'E4':e4,'E5':{'gas':gas_rows,'latency':latency_rows},'scalability':self.scale})
        atomic_json(self.out/'summary.json',self.summary)

def main(args):
    exp=ResumableExperiment(args)
    try:
        if exp.session.get('final_directory'):
            print('Completed output already exists: '+exp.session['final_directory']);return 0
        exp.load_candidates()
        sizes=[4] if args.resume_test else ([args.workload] if args.workload else [1000,5000,10000])
        selected=None
        for n in sizes:
            selected=exp.workload(n)
            if selected is None:return 0
        if args.resume_test:return 0
        if all(exp.session['workloads'].get(str(n),{}).get('complete') for n in (1000,5000,10000)) and not args.workload:
            exp.complete(select_artifacts(exp.candidates,10000,42))
        else: print('Requested workloads checkpointed. Run --mode full --resume to continue all and finalize.',flush=True)
        return 0
    finally:exp.chain.close()
