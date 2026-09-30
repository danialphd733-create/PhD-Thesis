// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import '@openzeppelin/contracts/access/AccessControl.sol';
import '@openzeppelin/contracts/utils/Pausable.sol';
import './interfaces/IZKVerifier.sol';
contract PrivLedger is AccessControl, Pausable {
 uint256 public constant FIELD=21888242871839275222246405745257275088548364400416034343698204186575808495617;
 bytes32 public constant REGISTRAR_ROLE=keccak256('REGISTRAR');
 bytes32 public constant LEGAL_ROLE=keccak256('LEGAL');
 bytes32 public constant ISSUER_ROLE=keccak256('ISSUER');
 bytes32 public constant CIRCUIT_ID=keccak256('privledger.access.v1');
 struct Evidence {bytes32 sha256Digest;bytes32 keccakDigest;bytes32 zkCommitment;string cid;uint64 retentionUntil;bytes32 custodianDidHash;bytes32 parent;uint8 state;}
 struct Credential {uint8 role;uint64 expiry;bool issued;bool revoked;}
 mapping(bytes32=>Evidence) public evidence;
 mapping(bytes32=>Credential) public credentials;
 mapping(bytes32=>bool) public nullifiers;
 mapping(uint8=>uint8) public requiredRoles;
 IZKVerifier public immutable verifier;
 event EvidenceRegistered(bytes32 indexed evidenceId,bytes32 sha256Digest,bytes32 keccakDigest,string cid);
 event AccessDecision(bytes32 indexed evidenceId,uint8 actionCode,bytes32 credentialCommitment,bytes32 nullifierHash,bool allowed);
 event CredentialIssued(bytes32 indexed credentialCommitment,uint8 role,uint64 expiry);
 event CredentialRevoked(bytes32 indexed credentialCommitment,bytes32 revocationReasonHash);
 event EvidenceRedacted(bytes32 indexed parentEvidenceId,bytes32 indexed childEvidenceId,string replacementCid,bytes32 storageAttestationHash,bytes32 proofRef);
 event EvidenceDeletionRecorded(bytes32 indexed evidenceId,bytes32 storageAttestationHash,bytes32 proofRef);
 constructor(address v){require(v.code.length>0,'verifier');verifier=IZKVerifier(v);_grantRole(DEFAULT_ADMIN_ROLE,msg.sender);_grantRole(REGISTRAR_ROLE,msg.sender);_grantRole(LEGAL_ROLE,msg.sender);_grantRole(ISSUER_ROLE,msg.sender);requiredRoles[1]=1;requiredRoles[2]=2;requiredRoles[3]=3;}
 function pause(bool paused) external onlyRole(DEFAULT_ADMIN_ROLE){if(paused)_pause();else _unpause();}
 function issueCredential(bytes32 c,uint8 role,uint64 expiry) external onlyRole(ISSUER_ROLE){require(c!=0&&uint(c)<FIELD&&role>0&&role<=5,'credential');require(!credentials[c].issued,'issued');require(expiry>=block.timestamp/1 days,'expired');credentials[c]=Credential(role,expiry,true,false);emit CredentialIssued(c,role,expiry);}
 function registerEvidence(bytes32 id,bytes32 sha,bytes32 kek,bytes32 zk,string calldata cid,uint64 retention,bytes32 did) external onlyRole(REGISTRAR_ROLE) whenNotPaused {require(id!=0&&sha!=0&&kek!=0&&bytes(cid).length>0,'input');require(evidence[id].state==0,'duplicate');evidence[id]=Evidence(sha,kek,zk,cid,retention,did,0,1);emit EvidenceRegistered(id,sha,kek,cid);}
 function revokeCredential(bytes32 c,bytes32 reason) external onlyRole(ISSUER_ROLE){require(credentials[c].issued,'unknown credential');credentials[c].revoked=true;emit CredentialRevoked(c,reason);}
 function requestAccess(bytes32 id,uint8 action,bytes32 credential,bytes32 nullifier,bytes calldata proof) external whenNotPaused returns(bool allowed){
  Credential memory c=credentials[credential]; uint epoch=block.timestamp/1 days;
  if(evidence[id].state==1&&c.issued&&!c.revoked&&c.expiry>=epoch&&requiredRoles[action]!=0&&c.role==requiredRoles[action]&&!nullifiers[nullifier]){
   uint[] memory inputs=new uint[](6);inputs[0]=uint(credential);inputs[1]=requiredRoles[action];inputs[2]=epoch;inputs[3]=uint(id)%FIELD;inputs[4]=action;inputs[5]=uint(nullifier);
   allowed=verifier.verify(inputs,proof);if(allowed)nullifiers[nullifier]=true;
  }emit AccessDecision(id,action,credential,nullifier,allowed);
 }
 function recordRedaction(bytes32 parent,bytes32 child,string calldata cid,bytes32 attestation,bytes32 proofRef) external onlyRole(LEGAL_ROLE) whenNotPaused {
  require(evidence[parent].state==1,'parent inactive');require(child!=parent&&evidence[child].state==1&&evidence[child].parent==0,'child invalid');require(keccak256(bytes(evidence[child].cid))==keccak256(bytes(cid)),'cid');require(attestation!=0&&proofRef!=0,'attestation');evidence[child].parent=parent;evidence[parent].state=2;emit EvidenceRedacted(parent,child,cid,attestation,proofRef);
 }
 function recordDeletion(bytes32 id,bytes32 attestation,bytes32 proofRef) external onlyRole(LEGAL_ROLE) whenNotPaused {require(evidence[id].state==1||evidence[id].state==2,'inactive');require(attestation!=0&&proofRef!=0,'attestation');evidence[id].state=3;emit EvidenceDeletionRecorded(id,attestation,proofRef);}
 function verifyProof(bytes32 circuitId,uint[] calldata publicSignals,bytes calldata proof) external view returns(bool){return circuitId==CIRCUIT_ID&&verifier.verify(publicSignals,proof);}
}
