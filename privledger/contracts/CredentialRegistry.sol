// Credential interface; credential state is enforced by PrivLedger.sol.
pragma solidity ^0.8.28;
interface CredentialRegistry { function revokeCredential(bytes32,bytes32) external; }
