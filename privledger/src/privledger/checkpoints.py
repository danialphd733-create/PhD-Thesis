"""Fsynced JSON-lines journal; ignore only an interrupted final record."""
import json
import os
from pathlib import Path

def read_records(path):
    path = Path(path)
    if not path.exists():
        return []
    lines = path.read_bytes().splitlines(keepends=True)
    records = []
    for i, line in enumerate(lines):
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            if i == len(lines)-1 and not line.endswith(b'\n'):
                break
            raise ValueError(f'Corrupt checkpoint record {i+1}: {path}')
        records.append(record)
    return records

def append_record(path, record):
    path = Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    # Remove only a torn last line after preserving it as a recovery artifact.
    if path.exists():
        with path.open('rb+') as stream:
            stream.seek(0,2)
            end = stream.tell()
            if end:
                stream.seek(end-1)
                if stream.read(1) != b'\n':
                    stream.seek(0)
                    data=stream.read()
                    cut=data.rfind(b'\n')+1
                    tail=data[cut:]
                    try:
                        json.loads(tail)
                    except (ValueError,UnicodeDecodeError):
                        with path.with_suffix('.torn-tail').open('ab') as recovery:
                            recovery.write(tail+b'\n')
                        stream.truncate(cut)
                    else:
                        stream.seek(0,2); stream.write(b'\n')
    encoded = (json.dumps(record,ensure_ascii=True,separators=(',',':'))+'\n').encode()
    with path.open('ab') as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())

def atomic_json(path, data):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix(path.suffix+'.tmp')
    with temporary.open('w',encoding='utf-8') as stream:
        json.dump(data,stream,indent=2,default=str)
        stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary,path)

def latest_records(path):
    return {r['stable_id']:r for r in read_records(path) if 'stable_id' in r}
