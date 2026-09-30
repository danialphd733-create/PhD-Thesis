# PrivLedger controlled prototype

The repository contains scripts and locked dependencies for reproducing the controlled-prototype experiments. Hardhat is the local EVM, Kubo is real loopback IPFS, and Circom/snarkjs builds a local research-only Groth16 setup. E6 anomaly scoring and E8 usability remain future work.

## Reproduce

PowerShell: `./scripts/reproduce.ps1 -Mode smoke`, then `./scripts/reproduce.ps1 -Mode quick`, then `./scripts/reproduce.ps1 -Mode full`.

Linux/macOS: `./scripts/reproduce.sh smoke`, `./scripts/reproduce.sh quick`, `./scripts/reproduce.sh full`.

The official CMU archive can be downloaded with `python scripts/download_enron.py`; it extracts only `lay-k`, `skilling-j`, and `kaminski-v`. Set `ENRON_DATASET_DIR` to the extracted `maildir` when it is outside `data/raw/enron/maildir`. The selected CMU release contains email messages without original attachment payloads.

The runner starts loopback IPFS/Hardhat, compiles contracts and the circuit, executes tests, hashes/encrypts/pins/registers each selected artifact, runs a bounded proof-backed lifecycle benchmark, produces seeded lifecycle and linkability simulations, and writes `results/run_<timestamp>`. Measurement and simulation result rows carry an `evidence_type` field; thesis-reference values remain in `configs/thesis_reference_results.yaml`.

For a completed run, `REPORT.md` and `figures/` are the primary outputs. Stop owned services with `python scripts/infrastructure.py stop`.
