const fs=require('fs'),path=require('path');require('os').cpus=()=>[{},{}];
const snark=require('snarkjs'),{ethers}=require('ethers');
const FIELD=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
let poseidon;async function hash(v){poseidon??=await require('circomlibjs').buildPoseidon();return poseidon.F.toString(poseidon(v.map(BigInt)));}
function hex(v){return ethers.toBeHex(BigInt(v),32);}
async function commitment(secret,role,expiry){return hex(await hash([secret,role,expiry]));}
async function prove({secret,role,expiry,evidenceId,action=1,epoch,credentialCommitment,requiredRole}){
 const b=path.join(__dirname,'../circuits/build');
 const c=credentialCommitment||await commitment(secret,role,expiry);
 const nullifier=hex(await hash([secret,BigInt(evidenceId)%FIELD,action,epoch]));
 const inputs={credentialCommitment:BigInt(c).toString(),requiredRole:String(requiredRole??role),evaluationEpoch:String(epoch),evidenceIdField:(BigInt(evidenceId)%FIELD).toString(),actionCode:String(action),nullifierHash:BigInt(nullifier).toString(),credentialSecret:String(secret),credentialRole:String(role),expiryEpoch:String(expiry)};
 const start=performance.now();const {proof,publicSignals}=await snark.groth16.fullProve(inputs,path.join(b,'access_authorization_js/access_authorization.wasm'),path.join(b,'access_final.zkey'),undefined,undefined,{singleThread:true});const generationMs=performance.now()-start;
 const v=performance.now();const valid=await snark.groth16.verify(JSON.parse(fs.readFileSync(path.join(b,'verification_key.json'))),publicSignals,proof);const verificationMs=performance.now()-v;
 const p=JSON.parse('['+await snark.groth16.exportSolidityCallData(proof,publicSignals)+']');
 return {credentialCommitment:c,nullifierHash:nullifier,proof:ethers.AbiCoder.defaultAbiCoder().encode(['uint256[2]','uint256[2][2]','uint256[2]'],p.slice(0,3)),publicSignals,generationMs,verificationMs,valid};
}
module.exports={hash,hex,commitment,prove,FIELD};
