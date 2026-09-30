import json
import pytest
from privledger.checkpoints import append_record, read_records, latest_records, atomic_json

def test_resume_preserves_completed_and_repairs_torn_tail(tmp_path):
    journal=tmp_path/'rows.jsonl'
    append_record(journal,{'stable_id':'a','state':'success','transaction_hash':'0x123'})
    with journal.open('ab') as out: out.write(b'{"stable_id":"b"')
    assert list(latest_records(journal)) == ['a']
    append_record(journal,{'stable_id':'b','state':'success'})
    assert len(read_records(journal)) == 2
    assert journal.with_suffix('.torn-tail').exists()

def test_middle_corruption_fails_closed(tmp_path):
    journal=tmp_path/'rows.jsonl'; journal.write_bytes(b'broken\n{}\n')
    with pytest.raises(ValueError,match='Corrupt checkpoint'): read_records(journal)

def test_atomic_replace_keeps_valid_json(tmp_path):
    path=tmp_path/'state.json'
    atomic_json(path,{'phase':'one'}); atomic_json(path,{'phase':'two'})
    assert json.loads(path.read_text()) == {'phase':'two'}
