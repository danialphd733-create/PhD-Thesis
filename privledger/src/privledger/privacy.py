"""Scan exported chain data against local PII without echoing matched PII."""
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from .hashing import sha256_hex

EMAIL = re.compile(rb"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


def extract_pii(raw: bytes):
    """Local-only candidate strings; caller must never export this return value."""
    message = BytesParser(policy=policy.default).parsebytes(raw)
    values = {m.decode("ascii", errors="ignore") for m in EMAIL.findall(raw)}
    headers = []
    for field in ("From", "To", "Cc", "Bcc", "Reply-To", "Sender"):
        headers.extend(str(v) for v in message.get_all(field, []))
    for name, address in getaddresses(headers):
        values.update((name, address))
    if message.get("Subject"):
        values.add(str(message["Subject"]))
    for part in message.walk():
        if part.get_filename():
            values.add(part.get_filename())
        if part.get_content_type() == "text/plain":
            body = (part.get_payload(decode=True) or b"").decode(part.get_content_charset() or "utf-8", errors="replace")
            # Whole nontrivial lines detect leaked body fragments without retaining logs.
            values.update(line.strip() for line in body.splitlines() if len(line.strip()) >= 12)
    return sorted(value for value in values if len(value) >= 3)


def _bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return json.dumps(value, default=str, ensure_ascii=False).encode("utf-8")


def scan_pii(payloads, known_strings=()):
    """payloads maps labels to decoded logs/state/calldata; findings contain hashes only."""
    findings = []
    terms = sorted({_bytes(t) for t in known_strings if len(_bytes(t)) >= 3})
    for label, value in payloads.items():
        blob = _bytes(value)
        decoded = []
        for match in re.finditer(rb"(?:0x)?([0-9a-fA-F]{6,})", blob):
            raw = match.group(1)
            if len(raw) % 2 == 0:
                decoded.append(bytes.fromhex(raw.decode("ascii")))
        surfaces = [blob, *decoded]
        hits = set()
        for surface in surfaces:
            hits.update(EMAIL.findall(surface))
            hits.update(term for term in terms if term.lower() in surface.lower())
        for hit in sorted(hits):
            findings.append({"surface": str(label), "matched_value_sha256": sha256_hex(hit), "matched_bytes": len(hit), "finding": "plaintext_pii"})
    return {"passed": not findings, "finding_count": len(findings), "findings": findings,
            "scope": "Known local strings and email patterns in supplied state, logs and decoded calldata; not a proof of absence of all PII."}
