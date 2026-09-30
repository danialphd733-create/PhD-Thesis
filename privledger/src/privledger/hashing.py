"""Canonical commitments and Ethereum-compatible evidence hashes."""
import hashlib
import json
import unicodedata
from Crypto.Hash import keccak


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def keccak256_hex(data: bytes) -> str:
    return keccak.new(digest_bits=256, data=data).hexdigest()


def _normalize(value):
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("Metadata keys must be strings")
            key = _normalize(key)
            if key in result:
                raise ValueError("Duplicate normalized metadata key")
            result[key] = _normalize(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    return value


def canonical_json(value) -> bytes:
    return json.dumps(_normalize(value), sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def metadata_commitment(metadata: dict, salt: bytes) -> str:
    if len(salt) < 16:
        raise ValueError("Commitment salt requires at least 16 bytes")
    return sha256_hex(b"PrivLedger.metadata.v1\x00" + len(salt).to_bytes(4, "big") + salt + canonical_json(metadata))
