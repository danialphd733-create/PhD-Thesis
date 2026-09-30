"""Deterministic lifecycle workload and explicit local access decisions."""
import random


def generate_workload(evidence_ids, seed=42, access_allow_ratio=0.5,
                      redaction_probability=0.2, deletion_probability=0.1):
    for probability in (access_allow_ratio, redaction_probability, deletion_probability):
        if not 0 <= probability <= 1:
            raise ValueError("Probabilities must be within [0, 1]")
    rng = random.Random(seed)
    events = []
    for evidence_id in evidence_ids:
        events.append({"evidence_id": evidence_id, "action": "REGISTER"})
        for _ in range(rng.randint(1, 5)):
            events.append({"evidence_id": evidence_id, "action": "ACCESS", "expected_allow": rng.random() < access_allow_ratio})
        if rng.random() < redaction_probability:
            events.append({"evidence_id": evidence_id, "action": "REDACTION"})
        if rng.random() < deletion_probability:
            events.append({"evidence_id": evidence_id, "action": "DELETE"})
    return events


def authorized(authority, credential, required_role, now=None, deleted=False):
    return (not deleted and authority.verify(credential, now)
            and credential.payload.get("role") == required_role)
