import random
from dataclasses import replace
from email.message import EmailMessage
import pytest
from cryptography.exceptions import InvalidTag
from privledger.hashing import sha256_hex, keccak256_hex, canonical_json, metadata_commitment
from privledger.encryption import generate_key, encrypt, decrypt
from privledger.credentials import CredentialAuthority
from privledger.identity import DIDRotator
from privledger.ingestion import build_candidates, select_artifacts, manifest
from privledger.metrics import summarize
from privledger.privacy import scan_pii, extract_pii
from privledger.policy import generate_workload, authorized


def test_hash_vectors():
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert keccak256_hex(b"") == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak256_hex(b"abc") == keccak256_hex(b"abc")


def test_canonical_metadata():
    assert canonical_json({"b": "e\u0301", "a": 1}) == b'{"a":1,"b":"\xc3\xa9"}'
    assert metadata_commitment({"x": 1}, b"a" * 32) != metadata_commitment({"x": 1}, b"b" * 32)
    with pytest.raises(ValueError):
        canonical_json({"é": 1, "e\u0301": 2})
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_aes_roundtrip_and_tamper():
    key = generate_key()
    envelope = encrypt(b"evidence", key, b"id")
    assert decrypt(envelope, key, b"id") == b"evidence"
    assert encrypt(b"evidence", key) != encrypt(b"evidence", key)
    with pytest.raises(InvalidTag):
        decrypt(envelope[:-1] + bytes([envelope[-1] ^ 1]), key, b"id")
    with pytest.raises(InvalidTag):
        decrypt(envelope, key, b"wrong-id")


def test_dataset_order_and_attachments(tmp_path):
    for custodian in ("lay-k", "skilling-j", "kaminski-v"):
        directory = tmp_path / custodian
        directory.mkdir()
        for i in range(3):
            msg = EmailMessage()
            msg.set_content("synthetic unit fixture")
            msg.add_attachment(bytes([i]), maintype="application", subtype="octet-stream", filename="test.bin")
            (directory / str(i)).write_bytes(msg.as_bytes())
    candidates = build_candidates(tmp_path)
    assert len(candidates) == 18
    assert len([a for a in candidates if a.artifact_type == "attachment"]) == 9
    assert select_artifacts(candidates, 10) == select_artifacts(list(reversed(candidates)), 10)
    assert select_artifacts(candidates, 10) == random.Random(42).sample(candidates, 10)
    assert {a.read_bytes() for a in candidates if a.artifact_type == "attachment"} == {b"\x00", b"\x01", b"\x02"}
    assert manifest(tmp_path, candidates, candidates[:2])["candidate_count"] == 18


def test_did_rotation():
    rotator = DIDRotator()
    assert len({rotator.next_did() for _ in range(100)}) == 100


def test_credentials_signature_expiry_revocation():
    issuer = CredentialAuthority()
    credential = issuer.issue("did:privledger:test", 1, 200, now=100)
    assert issuer.verify(credential, 100)
    assert not issuer.verify(credential, 99)
    assert not issuer.verify(credential, 200)
    assert not issuer.verify(replace(credential, payload={**credential.payload, "role": 2}), 101)
    assert not CredentialAuthority().verify(credential, 101)
    assert authorized(issuer, credential, 1, 101)
    assert not authorized(issuer, credential, 2, 101)
    issuer.revoke(credential)
    assert not issuer.verify(credential, 101)


def test_pii_scans_plain_and_calldata_without_echo():
    secret = "alice@example.org"
    result = scan_pii({"log": secret, "input": "0x" + secret.encode().hex(), "state": {"name": "Alice Jones"}}, ["Alice Jones"])
    assert result["finding_count"] == 3
    assert secret not in str(result)
    assert scan_pii({"state": "0x" + sha256_hex(secret.encode())})["passed"]


def test_statistics():
    summary = summarize([1, 2, 3, 4, 5])
    assert summary["mean"] == 3
    assert summary["p95"] == pytest.approx(4.8)
    assert summary["std"] == pytest.approx(1.5811388300841898)
    assert summarize([])["count"] == 0
    with pytest.raises(ValueError):
        summarize([float("inf")])


def test_pii_extractor_local_fields():
    message = EmailMessage()
    message["From"] = "Alice Jones <alice@example.org>"
    message["To"] = "Bob Smith <bob@example.org>"
    message["Subject"] = "Sensitive unit fixture subject"
    message.set_content("Sensitive synthetic email body fragment")
    message.add_attachment(b"fixture", maintype="application", subtype="octet-stream", filename="confidential.txt")
    terms = extract_pii(message.as_bytes())
    assert {"Alice Jones", "alice@example.org", "Bob Smith", "bob@example.org", "Sensitive unit fixture subject", "confidential.txt"} <= set(terms)
    assert not scan_pii({"calldata": "0x" + b"Alice Jones".hex()}, terms)["passed"]


def test_credential_expiry_boundary():
    issuer = CredentialAuthority()
    credential = issuer.issue("did:privledger:fixture", 1, 200, now=100)
    assert issuer.verify(credential, 199)
    assert not issuer.verify(credential, 200)


def test_credential_revocation():
    issuer = CredentialAuthority()
    credential = issuer.issue("did:privledger:fixture", 1, 200, now=100)
    issuer.revoke(credential)
    assert not issuer.verify(credential, 101)


def test_workload_bounds_order_seed():
    ids = [str(i) for i in range(100)]
    events = generate_workload(ids)
    assert events == generate_workload(ids)
    for evidence_id in ids:
        actions = [e["action"] for e in events if e["evidence_id"] == evidence_id]
        assert actions[0] == "REGISTER"
        assert 1 <= actions.count("ACCESS") <= 5
        assert actions.count("REDACTION") <= 1
        assert actions.count("DELETE") <= 1
        if "DELETE" in actions:
            assert actions[-1] == "DELETE"
