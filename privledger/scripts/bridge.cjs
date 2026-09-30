// Long-lived JSON-lines worker: no secret values or request bodies are logged.
console.log=(...args)=>process.stderr.write(args.join(' ')+'\n');
const fs=require('fs'),path=require('path'),{ethers}=require('ethers'),zk=require('./zk.cjs');
process.chdir(path.join(__dirname,'..'));
const provider=new ethers.JsonRpcProvider(process.env.PRIVLEDGER_RPC_URL||'http://127.0.0.1:8545',undefined,{cacheTimeout:-1,batchMaxCount:1});provider.pollingInterval=10;
let ledger;const deployed='abi/deployment.json';
function artifact(name){return JSON.parse(fs.readFileSync(name==='Groth16Verifier'?'artifacts/contracts/generated/Groth16Verifier.sol/Groth16Verifier.json':`artifacts/contracts/${name}.sol/${name}.json`));}
async function load(){if(!ledger){const d=JSON.parse(fs.readFileSync(deployed));ledger=new ethers.Contract(d.address,artifact('PrivLedger').abi,await provider.getSigner(0));}return ledger;}
function plain(v){return JSON.parse(JSON.stringify(v,(_,x)=>typeof x==='bigint'?x.toString():x));}
async function receipt(tx,start){const r=await tx.wait();return {transactionHash:r.hash,gasUsed:r.gasUsed.toString(),blockNumber:r.blockNumber,transactionMs:performance.now()-start,logs:r.logs.map(l=>({address:l.address,topics:l.topics,data:l.data}))};}
async function dispatch(q){
 if(q.op==='attach'){if(!(await provider.getCode(q.address)).startsWith('0x')||(await provider.getCode(q.address))==='0x')throw Error('No deployed code at address');ledger=new ethers.Contract(q.address,artifact('PrivLedger').abi,await provider.getSigner(0));return {address:q.address};}
 if(q.op==='advanceEpoch'){if((await provider.getNetwork()).chainId!==31337n)throw Error('Clock manipulation restricted to local research chain');const block=await provider.getBlock('latest');const target=q.epoch*86400;if(target>block.timestamp){await provider.send('evm_setNextBlockTimestamp',[target]);await provider.send('evm_mine',[]);}return {epoch:Math.floor((await provider.getBlock('latest')).timestamp/86400)};}
 if(q.op==='status')return {chainId:(await provider.getNetwork()).chainId.toString(),blockNumber:await provider.getBlockNumber(),epoch:Math.floor((await provider.getBlock('latest')).timestamp/86400)};
 if(q.op==='deploy'){
  const signer=await provider.getSigner(0),addresses={};for(const name of ['Groth16Verifier','ZKAdapter','PrivLedger']){const a=artifact(name);const f=new ethers.ContractFactory(a.abi,a.bytecode,signer);const c=await f.deploy(...(name==='Groth16Verifier'?[]:[addresses[name==='ZKAdapter'?'Groth16Verifier':'ZKAdapter']]));await c.waitForDeployment();addresses[name]=await c.getAddress();if(name==='PrivLedger')ledger=c;}
  fs.mkdirSync('abi',{recursive:true});fs.writeFileSync('abi/PrivLedger.json',JSON.stringify(artifact('PrivLedger').abi,null,2));const d={address:addresses.PrivLedger,addresses,chainId:31337};fs.writeFileSync(deployed,JSON.stringify(d,null,2));return d;
 }
 if(q.op==='commitment')return {credentialCommitment:await zk.commitment(q.secret,q.role,q.expiry)};
 if(q.op==='prove'){q.epoch??=Math.floor((await provider.getBlock('latest')).timestamp/86400);return zk.prove(q);}
 const c=await load();let tx;const t=performance.now();
 switch(q.op){
 case 'address':return {address:await c.getAddress()};
 case 'credential':{const x=await c.credentials(q.credentialCommitment);return {role:x.role,expiry:x.expiry,issued:x.issued,revoked:x.revoked};}
 case 'verifyPaid':{const valid=await c.verifyProof(await c.CIRCUIT_ID(),q.publicSignals,q.proof);tx=await c.verifyProof.send(await c.CIRCUIT_ID(),q.publicSignals,q.proof);return {...await receipt(tx,t),valid};}
 case 'issue': {const commitment=q.credentialCommitment||await zk.commitment(q.secret,q.role,q.expiry);tx=await c.issueCredential(commitment,q.role,q.expiry);return {...await receipt(tx,t),credentialCommitment:commitment};}
 case 'register':tx=await c.registerEvidence(q.evidenceId,q.sha256Digest,q.keccakDigest,q.zkCommitment||ethers.ZeroHash,q.cid,q.retentionUntil||0,q.custodianDidHash||ethers.ZeroHash);break;
 case 'access':tx=await c.requestAccess(q.evidenceId,q.action||1,q.credentialCommitment,q.nullifierHash,q.proof);{const r=await receipt(tx,t);const event=r.logs.map(l=>{try{return c.interface.parseLog(l);}catch{return null;}}).find(e=>e?.name==='AccessDecision');return {...r,allowed:event.args.allowed};}
 case 'revoke':tx=await c.revokeCredential(q.credentialCommitment,q.reasonHash||ethers.id('research revocation'));break;
 case 'redact':tx=await c.recordRedaction(q.parentEvidenceId,q.childEvidenceId,q.cid,q.storageAttestationHash,q.proofRef);break;
 case 'delete':tx=await c.recordDeletion(q.evidenceId,q.storageAttestationHash,q.proofRef);break;
 case 'evidence':{const e=await c.evidence(q.evidenceId);return {sha256Digest:e.sha256Digest,keccakDigest:e.keccakDigest,zkCommitment:e.zkCommitment,cid:e.cid,retentionUntil:e.retentionUntil,custodianDidHash:e.custodianDidHash,parent:e.parent,state:e.state};}
 case 'logs':return provider.getLogs({address:await c.getAddress(),fromBlock:q.fromBlock||0,toBlock:'latest'});
 default:throw Error('Unknown operation');}
 return receipt(tx,t);
}
const rl=require('readline').createInterface({input:process.stdin,crlfDelay:Infinity});
(async()=>{for await(const line of rl){if(!line.trim())continue;let q;try{q=JSON.parse(line);const result=await dispatch(q);process.stdout.write(JSON.stringify(plain({id:q.id,ok:true,result}))+'\n');}catch(e){process.stdout.write(JSON.stringify({id:q?.id,ok:false,error:e.shortMessage||e.message})+'\n');}}process.exit(0);})();
