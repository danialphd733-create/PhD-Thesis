"""Run with PRIVLEDGER_IPFS_TEST=1 and a disposable local Kubo daemon."""
import os
import pytest
from privledger.encryption import generate_key, encrypt, decrypt
from privledger.hashing import sha256_hex, keccak256_hex
from privledger.storage import KuboClient


@pytest.mark.skipif(os.environ.get("PRIVLEDGER_IPFS_TEST") != "1", reason="Requires explicitly enabled local Kubo integration")
def test_real_ipfs_encrypted_evidence_roundtrip():
    client = KuboClient(os.environ.get("IPFS_API_URL", "http://127.0.0.1:5001"))
    assert client.version()
    plaintext = b"synthetic integration evidence"
    key = generate_key()
    envelope = encrypt(plaintext, key)
    cid = client.add(envelope)
    try:
        retrieved = decrypt(client.cat(cid), key)
        assert sha256_hex(retrieved) == sha256_hex(plaintext)
        assert keccak256_hex(retrieved) == keccak256_hex(plaintext)
    finally:
        client.unpin(cid)
    # GC is intentionally not invoked against a shared daemon; unpin is local only.
