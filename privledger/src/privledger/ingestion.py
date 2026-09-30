"""Deterministic maildir candidate enumeration including MIME attachments."""
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
import os
import platform
import random
from .hashing import sha256_hex, canonical_json

CUSTODIANS = ("lay-k", "skilling-j", "kaminski-v")


@dataclass(frozen=True)
class Artifact:
    stable_id: str
    custodian: str
    source_relative_path: str
    artifact_type: str
    attachment_index: int
    source: Path

    def read_bytes(self):
        raw = self.source.read_bytes()
        if self.artifact_type == "email":
            return raw
        message = BytesParser(policy=policy.default).parsebytes(raw)
        for index, part in enumerate(_attachments(message)):
            if index == self.attachment_index:
                return part.get_payload(decode=True) or b""
        raise ValueError("Selected attachment no longer exists")


def _attachments(message):
    return (part for part in message.walk() if not part.is_multipart()
            and (part.get_content_disposition() == "attachment" or part.get_filename()))


def find_dataset(project_root, explicit=None):
    root = Path(project_root)
    candidates = [explicit, os.environ.get("ENRON_DATASET_DIR"), root / "data/raw/enron/maildir"]
    candidates.extend(sorted(root.glob("**/maildir")))
    for candidate in candidates:
        if candidate and all((Path(candidate) / custodian).is_dir() for custodian in CUSTODIANS):
            return Path(candidate).resolve()
    raise FileNotFoundError("Enron maildir missing: set ENRON_DATASET_DIR to a maildir containing the three study custodians")


def build_candidates(root, custodians=CUSTODIANS):
    root = Path(root)
    candidates = []
    for custodian in custodians:
        if not (root / custodian).is_dir():
            raise FileNotFoundError(f"Missing required custodian directory: {custodian}")
        for source in sorted((root / custodian).rglob("*")):
            if not source.is_file() or source.is_symlink():
                continue
            relative = source.relative_to(root).as_posix()
            stable = canonical_json([custodian, relative, "email", -1]).decode("utf-8")
            candidates.append(Artifact(stable, custodian, relative, "email", -1, source))
            message = BytesParser(policy=policy.default).parsebytes(source.read_bytes())
            for index, part in enumerate(_attachments(message)):
                stable = canonical_json([custodian, relative, "attachment", index, part.get_filename() or ""]).decode("utf-8")
                candidates.append(Artifact(stable, custodian, relative, "attachment", index, source))
    return sorted(candidates, key=lambda a: a.stable_id)


def select_artifacts(candidates, n, seed=42):
    ordered = sorted(candidates, key=lambda a: a.stable_id)
    if len({a.stable_id for a in ordered}) != len(ordered):
        raise ValueError("Duplicate stable candidate identifiers")
    return random.Random(seed).sample(ordered, n)


def manifest(root, candidates, selected, seed=42, custodians=CUSTODIANS):
    identifiers = sorted(a.stable_id for a in candidates)
    selected_ids = [a.stable_id for a in selected]
    return {"seed": seed, "dataset_root_description": str(Path(root).resolve()),
            "dataset_root_fingerprint": sha256_hex(canonical_json(identifiers)),
            "fingerprint_scope": "Candidate stable identifiers (not content hashes)",
            "custodians": list(custodians), "candidate_count": len(candidates),
            "selected_count": len(selected), "sample_size": len(selected),
            "selection_algorithm": "random.Random(seed).sample(sorted candidates by stable_id, N)",
            "selected_stable_identifiers": selected_ids,
            "selection_fingerprint": sha256_hex(canonical_json(selected_ids)),
            "generation_timestamp": datetime.now(timezone.utc).isoformat(),
            "software": {"python": platform.python_version(), "privledger": "0.1.0"}}
