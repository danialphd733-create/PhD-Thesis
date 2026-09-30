"""Versioned AES-256-GCM binary envelopes; keys never enter envelope."""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"PLG1"


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    nonce = os.urandom(12)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, plaintext, MAGIC + associated_data)


def decrypt(envelope: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    if len(key) != 32 or len(envelope) < 32 or envelope[:4] != MAGIC:
        raise ValueError("Invalid key or encrypted envelope")
    return AESGCM(key).decrypt(envelope[4:16], envelope[16:], MAGIC + associated_data)
