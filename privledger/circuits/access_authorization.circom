pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
template Authorization() {
 signal input credentialCommitment; signal input requiredRole; signal input evaluationEpoch;
 signal input evidenceIdField; signal input actionCode; signal input nullifierHash;
 signal input credentialSecret; signal input credentialRole; signal input expiryEpoch;
 component commitment = Poseidon(3);
 commitment.inputs[0] <== credentialSecret; commitment.inputs[1] <== credentialRole; commitment.inputs[2] <== expiryEpoch;
 commitment.out === credentialCommitment;
 credentialRole === requiredRole;
 component epochBits = Num2Bits(64); epochBits.in <== evaluationEpoch;
 component expiryBits = Num2Bits(64); expiryBits.in <== expiryEpoch;
 component valid = LessEqThan(64); valid.in[0] <== evaluationEpoch; valid.in[1] <== expiryEpoch; valid.out === 1;
 component nullifier = Poseidon(4);
 nullifier.inputs[0] <== credentialSecret; nullifier.inputs[1] <== evidenceIdField;
 nullifier.inputs[2] <== actionCode; nullifier.inputs[3] <== evaluationEpoch;
 nullifier.out === nullifierHash;
}
component main {public [credentialCommitment,requiredRole,evaluationEpoch,evidenceIdField,actionCode,nullifierHash]} = Authorization();

