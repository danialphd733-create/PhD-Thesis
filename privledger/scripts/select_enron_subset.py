"""Select real email/attachment artifacts; write local manifest and safe hashes."""
import argparse
import csv
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from privledger.hashing import sha256_hex, keccak256_hex, metadata_commitment
from privledger.ingestion import find_dataset, build_candidates, select_artifacts, manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset")
    parser.add_argument("--size", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=ROOT / "data/processed")
    parser.add_argument("--reproducible-public-salt", action="store_true")
    args = parser.parse_args()
    root = find_dataset(ROOT, args.dataset)
    candidates = build_candidates(root)
    selected = select_artifacts(candidates, args.size, args.seed)
    args.output.mkdir(parents=True, exist_ok=True)
    if args.reproducible_public_salt:
        print("Research mode: public fixed salt provides no secret-salt privacy.")
        salt = b"PrivLedger-public-research-salt-v1"
    else:
        secret_file = ROOT / "secrets/metadata_salt.bin"
        secret_file.parent.mkdir(exist_ok=True)
        if not secret_file.exists():
            try:
                with secret_file.open("xb") as out:
                    out.write(os.urandom(32))
                if os.name != "nt":
                    secret_file.chmod(0o600)
            except FileExistsError:
                pass
        salt = secret_file.read_bytes()
    manifest_data = manifest(root, candidates, selected, args.seed)
    manifest_data["evidence_type"] = "measured"
    manifest_data["metadata_salt_mode"] = "public-research" if args.reproducible_public_salt else "local-secret"
    (args.output / "manifest.json").write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    fields = ["artifact_index", "evidence_id", "custodian", "artifact_type", "source_relative_path_hash",
              "attachment_index", "byte_length", "sha256_digest", "keccak256_digest", "metadata_commitment",
              "custodian_did_hash", "retention_until", "encrypted_artifact_path", "ipfs_cid", "selection_seed"]
    with (args.output / "metadata.csv").open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for index, artifact in enumerate(selected):
            raw = artifact.read_bytes()
            row = {"artifact_index": index, "evidence_id": sha256_hex(artifact.stable_id.encode()),
                   "custodian": sha256_hex(artifact.custodian.encode()), "artifact_type": artifact.artifact_type,
                   "source_relative_path_hash": sha256_hex(artifact.source_relative_path.encode()),
                   "attachment_index": artifact.attachment_index, "byte_length": len(raw),
                   "sha256_digest": sha256_hex(raw), "keccak256_digest": keccak256_hex(raw),
                   "selection_seed": args.seed}
            row["metadata_commitment"] = metadata_commitment(row, salt)
            writer.writerow(row)
    print(f"Selected {len(selected)} of {len(candidates)} artifacts; local outputs: {args.output.resolve()}")


if __name__ == "__main__":
    main()
