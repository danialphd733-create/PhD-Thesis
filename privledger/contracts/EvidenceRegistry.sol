// The controlled prototype keeps the registry in PrivLedger.sol. This file is
// an intentionally thin interface for consumers that import the named layer.
pragma solidity ^0.8.28;
interface EvidenceRegistry {
    function registerEvidence(bytes32,bytes32,bytes32,bytes32,string calldata,uint64,bytes32) external;
}
