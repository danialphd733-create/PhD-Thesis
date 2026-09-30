"""Event-scoped controlled DID pseudonyms (not a DID infrastructure)."""
import secrets


class DIDRotator:
    def __init__(self):
        self._used = set()

    def next_did(self) -> str:
        while True:
            did = "did:privledger:" + secrets.token_hex(32)
            if did not in self._used:
                self._used.add(did)
                return did
