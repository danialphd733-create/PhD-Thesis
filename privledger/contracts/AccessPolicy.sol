// Access-policy interface; policy state is enforced by PrivLedger.sol.
pragma solidity ^0.8.28;
interface AccessPolicy { function requiredRoles(uint8) external view returns (uint8); }
