// Local research setup. Never use its toxic waste assumptions for production.
const fs=require('fs'),path=require('path'),cp=require('child_process');
async function main(){
 process.chdir(path.join(__dirname,'..'));fs.mkdirSync('circuits/build',{recursive:true});
 cp.execFileSync(process.execPath,['scripts/circom_compile.cjs'],{stdio:'inherit'});
 require('os').cpus=()=>[{},{}]; const snark=require('snarkjs');const b='circuits/build/';
 const digest=f=>require('crypto').createHash('sha256').update(fs.readFileSync(f)).digest('hex');
 const previous=fs.existsSync(b+'setup_manifest.json')?JSON.parse(fs.readFileSync(b+'setup_manifest.json')):null;
 const matches=previous && ['access_authorization.r1cs','access_final.zkey'].every(f=>fs.existsSync(b+f)&&previous.hashes[f]===digest(b+f));
 if(!matches){
  const {getCurveFromName}=require(require.resolve('ffjavascript',{paths:[require.resolve('snarkjs')]}));const curve=await getCurveFromName('bn128',true);
  await snark.powersOfTau.newAccumulator(curve,12,b+'pot_0000.ptau');await curve.terminate();
  await snark.powersOfTau.contribute(b+'pot_0000.ptau',b+'pot_0001.ptau','local research contribution',require('crypto').randomBytes(64).toString('hex'));
  await snark.powersOfTau.preparePhase2(b+'pot_0001.ptau',b+'pot_final.ptau');
  await snark.zKey.newZKey(b+'access_authorization.r1cs',b+'pot_final.ptau',b+'access_0000.zkey');
  await snark.zKey.contribute(b+'access_0000.zkey',b+'access_final.zkey','local research phase 2',require('crypto').randomBytes(64).toString('hex'));
 }
 const vk=await snark.zKey.exportVerificationKey(b+'access_final.zkey');fs.writeFileSync(b+'verification_key.json',JSON.stringify(vk,null,2));
 const template=fs.readFileSync(path.join(path.join(path.dirname(require.resolve('snarkjs')),'..'),'templates','verifier_groth16.sol.ejs'),'utf8');
 fs.writeFileSync('contracts/generated/Groth16Verifier.sol',await snark.zKey.exportSolidityVerifier(b+'access_final.zkey',{groth16:template}));
 const hashes={};for(const f of ['access_authorization.r1cs','access_final.zkey','verification_key.json','pot_final.ptau'])hashes[f]=require('crypto').createHash('sha256').update(fs.readFileSync(b+f)).digest('hex');
 fs.writeFileSync(b+'setup_manifest.json',JSON.stringify({generatedAt:new Date().toISOString(),source:'locally generated single-party research setup; not production trusted ceremony',hashes},null,2));
 console.log('ZK build complete');process.exit(0);
}main().catch(e=>{console.error(e);process.exit(1)});


