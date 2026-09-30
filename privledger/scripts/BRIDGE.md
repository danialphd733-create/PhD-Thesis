# Python / Node integration

Start `node scripts/bridge.cjs` with cwd project root. Keep it alive, send one JSON object + newline, flush, read one JSON line response. Every request has `id` and `op`; response `{id,ok,result}` or `{id,ok:false,error}`. Requests processed serially. No secrets are printed. Send secrets only via stdin, never shell arguments. `PRIVLEDGER_RPC_URL` defaults to localhost:8545. Start Hardhat with `node node_modules/hardhat/internal/cli/cli.js node` first. Compile via same CLI `compile`. ZK setup `node scripts/build_zk.cjs`.

Operations and required fields:

* `status`: returns chainId, blockNumber, epoch = chain timestamp / 86400 floored.
* `deploy`: deploys real verifier, adapter, ledger; saves abi/deployment.json and abi/PrivLedger.json. Returns address and addresses.
* `issue`: secret (decimal string), role (1 investigator, 2 auditor, 3 legal, 4 custodian, 5 admin), expiry (epoch integer). Returns credentialCommitment plus receipt.
* `commitment`: secret, role, expiry; returns credentialCommitment, no transaction.
* `prove`: secret, role, expiry, evidenceId (0x 32 bytes), action (1 read/investigator,2 audit/auditor,3 legal), optional epoch (defaults current chain), optional credentialCommitment and requiredRole for negative tests. Returns credentialCommitment, nullifierHash, proof, publicSignals, generationMs, verificationMs, valid. Wrong secret/role/expiry fail witness construction.
* `register`: evidenceId, sha256Digest, keccakDigest, cid; optional zkCommitment/custodianDidHash (zero default), retentionUntil (Unix seconds default 0).
* `access`: evidenceId, action, credentialCommitment, nullifierHash, proof. Returns allowed plus receipt. Denials emit events and do not revert; denied nullifiers remain unconsumed.
* `revoke`: credentialCommitment, optional reasonHash.
* `redact`: parentEvidenceId, childEvidenceId, cid, storageAttestationHash, proofRef. Child MUST already be registered with its own replacement hashes/CID. Parent becomes state 2, child stores parent lineage.
* `delete`: evidenceId, storageAttestationHash, proofRef. State becomes 3; legal role required.
* `evidence`: evidenceId; returns named fields including state (0 unknown,1 active,2 redacted,3 deleted).
* `logs`: optional fromBlock; returns raw logs.

Mutation receipt: transactionHash, gasUsed (decimal string), blockNumber, transactionMs, logs. Bytes32 arguments must be 0x-prefixed length 66. Use cryptographically random field secret < BN254 prime. Replay protection means same secret/evidence/action/day only succeeds once. Repeated benchmark accesses should use separate evidence or credential secrets. Retention is metadata; legal deletion is authorized but retention enforcement is outside this prototype policy. Attestations are hashes supplied by storage orchestrator, not on-chain verification of IPFS deletion.
