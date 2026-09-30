# Implementation decisions

The supplied PDF is the scientific reference. The pasted text is an engineering specification, not existing code. The initial workspace had no repository or source files. No original material was overwritten.

1. **Evidence boundary.** Thesis chapters 4-6 distinguish design properties, simulations, analytical assumptions, and future work. New live results are labelled measured; synthetic linkability and lifecycle workloads simulated; four-second confirmations analytical. Reference numbers are stored separately.
2. **Local stack.** Hardhat automining plus real isolated Kubo, encrypted payloads, actual receipts and a Circom/Groth16 authorization circuit. Local trusted setup is research-only. No mainnet finality inference.
3. **Dataset.** Official CMU 2015 archive; extract only the three thesis custodians. CMU states this release has no attachments. MIME attachment extraction remains supported and tested with synthetic fixtures, but no attachment population is claimed for CMU data. Raw bytes are preserved for forensic hashing; only structured metadata is Unicode-normalized.
4. **Lifecycle scale.** All selected artifacts undergo real hash/encrypt/IPFS/register/retrieve verification. The full seeded 1-5 access and optional redaction/deletion event mix is a simulation. A bounded live benchmark executes and observes these workflows in the controlled local prototype. Counts and timings are kept distinct; simulated events are never counted as transactions.
5. **Defaults.** Seed 42, quick 25 messages, smoke 5 synthetic messages, 20% redaction and 10% deletion probability, 50% simulated access allow ratio, and live sample limits of 10 (smoke), 50 (quick), and 200 (full) are implementation choices. Sample sizes 1000/5000/10000, custodians, seed and 10000 balanced linkability pairs follow the thesis.
6. **Privacy.** No raw bodies or credentials/secrets in public results. Source stable identifiers in the local manifest are needed for reproducibility and are not sent on-chain. Local AES keys stay in ignored secrets. DID rotation in the adversarial simulation does not remove linkability of a reused on-chain credential or transaction account.
7. **Deletion.** Local unpin and append-only logical deletion do not prove global physical erasure. Retention policy and proof references are explicit. Ring signatures, production credential infrastructure, registration correctness circuits, and physical non-existence proofs are outside the implemented authorization circuit.
8. **Governance.** Local test accounts administer the controlled prototype. Independent audit, institutional multisignature/dispute governance, and production upgrades are not evaluated.

Sources: thesis sections 3.9-3.19, 4.7-4.17, chapters 5-6; https://www.cs.cmu.edu/~enron/ .
