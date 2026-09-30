// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import './interfaces/IZKVerifier.sol';
interface IGroth16 { function verifyProof(uint[2] calldata a,uint[2][2] calldata b,uint[2] calldata c,uint[6] calldata inputs) external view returns(bool); }
contract ZKAdapter is IZKVerifier {
 IGroth16 public immutable verifier;
 constructor(address v){verifier=IGroth16(v);}
 function verify(uint256[] calldata inputs,bytes calldata proof) external view returns(bool){
  if(inputs.length!=6 || proof.length!=256) return false;
  (uint[2] memory a,uint[2][2] memory b,uint[2] memory c)=abi.decode(proof,(uint[2],uint[2][2],uint[2]));
  uint[6] memory p; for(uint i=0;i<6;i++)p[i]=inputs[i];
  try verifier.verifyProof(a,b,c,p) returns(bool ok){return ok;}catch{return false;}
 }
}
