"""Real Kubo HTTP RPC adapter. There is no filesystem storage fallback."""
import json
import requests


class KuboClient:
    def __init__(self, api_url="http://127.0.0.1:5001", timeout=60):
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def _post(self, command, **kwargs):
        response = self.session.post(self.api_url + "/api/v0/" + command,
                                     timeout=self.timeout, **kwargs)
        response.raise_for_status()
        return response

    def version(self):
        return self._post("version").json()["Version"]

    def add(self, payload: bytes, pin=True) -> str:
        return self._post("add", params={"pin": str(pin).lower(), "cid-version": "1"},
                          files={"file": ("encrypted.bin", payload, "application/octet-stream")}).json()["Hash"]

    def cat(self, cid: str) -> bytes:
        return self._post("cat", params={"arg": cid}).content

    def unpin(self, cid: str):
        return self._post("pin/rm", params={"arg": cid}).json()

    def gc(self):
        return [json.loads(line) for line in self._post("repo/gc").text.splitlines() if line.strip()]
