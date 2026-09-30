"""Local issuer-signed credentials with explicit expiry and revocation."""
from dataclasses import dataclass, asdict
import secrets
import time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .hashing import canonical_json, sha256_hex


@dataclass(frozen=True)
class Credential:
    payload: dict
    signature: str

    @property
    def commitment(self):
        return sha256_hex(canonical_json(asdict(self)))


class CredentialAuthority:
    def __init__(self, private_key=None):
        self._key = private_key or Ed25519PrivateKey.generate()
        self.public_key = self._key.public_key()
        self._revoked = set()

    def issue(self, subject: str, role: int, expires_at: int, now=None) -> Credential:
        now = int(time.time()) if now is None else int(now)
        if expires_at <= now or not 0 <= role <= 255:
            raise ValueError("Invalid credential role or expiry")
        payload = {"version": 1, "subject": subject, "role": role,
                   "issued_at": now, "expires_at": expires_at, "nonce": secrets.token_hex(32)}
        return Credential(payload, self._key.sign(canonical_json(payload)).hex())

    def verify(self, credential: Credential, now=None) -> bool:
        now = int(time.time()) if now is None else int(now)
        try:
            self.public_key.verify(bytes.fromhex(credential.signature), canonical_json(credential.payload))
            return (credential.commitment not in self._revoked
                    and credential.payload["issued_at"] <= now < credential.payload["expires_at"])
        except (InvalidSignature, ValueError, TypeError, KeyError):
            return False

    def revoke(self, credential: Credential):
        self._revoked.add(credential.commitment)
