"""Restart a proven project-owned Kubo; verify decrypted evidence hashes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlparse
import psutil
import requests
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from privledger.encryption import decrypt
from privledger.hashing import sha256_hex, keccak256_hex
from privledger.storage import KuboClient


def wait_until(predicate, timeout, *, clock=time.perf_counter, sleep=time.sleep, interval=0.1):
    start = clock()
    while True:
        if predicate():
            return clock() - start
        elapsed = clock() - start
        if elapsed >= timeout:
            raise TimeoutError('Recovery condition did not become true before deadline')
        sleep(min(interval, timeout - elapsed))


def _api_available(api):
    try:
        response = requests.post(api + '/api/v0/version', timeout=1)
        return response.ok and bool(response.json().get('Version'))
    except (requests.RequestException, ValueError):
        return False


def _listens(process, port):
    return any(c.status == psutil.CONN_LISTEN and c.laddr.port == port
               for c in process.net_connections(kind='tcp'))


def _owned_process(root, api):
    repository = (root / '.runtime/ipfs').resolve()
    config = json.loads((repository / 'config').read_text(encoding='utf-8'))
    parsed = urlparse(api)
    if parsed.hostname != '127.0.0.1' or parsed.scheme != 'http':
        raise ValueError('Recovery requires project loopback Kubo API')
    port = parsed.port or 80
    if config['Addresses']['API'] != f'/ip4/127.0.0.1/tcp/{port}':
        raise ValueError('API URL does not match project repository configuration')
    state_path = root / '.runtime/processes.json'
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    matches = []
    for process in psutil.process_iter(['pid', 'name']):
        if (process.info['name'] or '').lower() not in ('ipfs', 'ipfs.exe'):
            continue
        try:
            command, environment = process.cmdline(), process.environ()
            if 'daemon' not in command or not _listens(process, port):
                continue
            owned_env = environment.get('IPFS_PATH')
            env_matches = bool(owned_env) and Path(owned_env).resolve() == repository
            persisted_matches = (state.get('ipfs') == process.pid
                                 and state.get('ipfs_repository') == str(repository)
                                 and state.get('ipfs_create_time') == process.create_time())
            if env_matches or persisted_matches:
                matches.append((process, command, environment))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if len(matches) != 1:
        raise RuntimeError('Cannot uniquely prove ownership of listening Kubo process')
    process, command, environment = matches[0]
    binary = Path(process.exe()).resolve()
    if os.environ.get('IPFS_BINARY') and Path(os.environ['IPFS_BINARY']).resolve() != binary:
        raise ValueError('IPFS_BINARY differs from verified running executable')
    if not binary.is_file():
        raise FileNotFoundError('Verified executable unavailable')
    return process, command, environment, binary, repository, port, state_path, state


def run_recovery(project_root, items, output_dir):
    """Items require eid,cid,key bytes,sha and keccak digest (or raw bytes)."""
    root, output = Path(project_root).resolve(), Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    selected = list(items)
    if len(selected) < 10 or len({item['cid'] for item in selected}) < 10:
        raise ValueError('Recovery requires at least ten distinct retained objects')
    api = os.environ.get('IPFS_API_URL', os.environ.get('IPFS_API', 'http://127.0.0.1:5001')).rstrip('/')
    old, command, environment, binary, repository, port, state_path, state = _owned_process(root, api)
    client = KuboClient(api)
    expected = []
    for item in selected:
        sha = item['sha'].removeprefix('0x').lower()
        keccak = item.get('keccak') or item.get('keccak256_digest')
        if keccak is None:
            if not isinstance(item.get('raw'), bytes):
                raise ValueError('Recorded Keccak digest or original raw bytes required')
            keccak = keccak256_hex(item['raw'])
        keccak = keccak.removeprefix('0x').lower()
        pins = client._post('pin/ls', params={'arg': item['cid'], 'type': 'recursive'}).json()['Keys']
        if item['cid'] not in pins:
            raise ValueError('Evidence is not recursively pinned')
        plaintext = decrypt(client.cat(item['cid']), item['key'])
        if sha256_hex(plaintext) != sha or keccak256_hex(plaintext) != keccak:
            raise ValueError('Pre-restart hashes do not match recorded evidence')
        expected.append((item, sha, keccak))
    result = {'evidence_type': 'measured', 'api_ready_seconds': None,
              'retrieval_ready_seconds': None, 'objects_tested': len(selected),
              'recovered': 0, 'hashes_unchanged': False, 'old_pid': old.pid,
              'new_pid': None, 'old_process_exited': False, 'api_observed_unavailable': False,
              'analytical_reference': {'evidence_type': 'thesis-reference', 'rpo': 0,
                                       'rto_target_seconds': 60, 'evidence_loss': 0}}
    started = time.perf_counter()
    try:
        try:
            requests.post(api + '/api/v0/shutdown', timeout=10).raise_for_status()
        except requests.ConnectionError:
            pass  # Exit and API disappearance below are still mandatory.
        old.wait(timeout=30)
        result['old_process_exited'] = True
        wait_until(lambda: not _api_available(api), 10)
        result['api_observed_unavailable'] = True
        result['shutdown_seconds'] = time.perf_counter() - started
        environment['IPFS_PATH'] = str(repository)
        flags = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
        with (root / '.runtime/ipfs-recovery.log').open('a', encoding='utf-8') as log:
            proc = subprocess.Popen([str(binary), *command[1:]], cwd=root, env=environment,
                                    stdout=log, stderr=subprocess.STDOUT, **flags)
        result['new_pid'] = proc.pid
        new = psutil.Process(proc.pid)
        state.update(ipfs=proc.pid, ipfs_create_time=new.create_time(), ipfs_repository=str(repository))
        state_path.write_text(json.dumps(state, indent=2), encoding='utf-8')
        def ready():
            if proc.poll() is not None:
                raise RuntimeError('Replacement Kubo exited before readiness')
            return _listens(new, port) and _api_available(api)
        wait_until(ready, 60)
        result['api_ready_seconds'] = time.perf_counter() - started
        checks = []
        for item, sha, keccak in expected:
            plaintext = decrypt(client.cat(item['cid']), item['key'])
            checks.append(sha256_hex(plaintext) == sha and keccak256_hex(plaintext) == keccak)
            result['recovered'] = sum(checks)
        if proc.poll() is not None:
            raise RuntimeError('Replacement Kubo exited during retrieval')
        result['retrieval_ready_seconds'] = time.perf_counter() - started
        result['recovered'] = sum(checks)
        result['hashes_unchanged'] = all(checks)
        result['status'] = 'passed' if all(checks) else 'failed'
    except Exception as error:
        result['status'] = 'failed'
        result['error_type'] = type(error).__name__
        result['elapsed_seconds'] = time.perf_counter() - started
    (output / 'e7_live_ipfs_recovery.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result
