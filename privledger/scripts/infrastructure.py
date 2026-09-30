"""Manage only the local research processes started by this package."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / '.runtime'

def hidden():
    return {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}

def healthy(url, rpc=False):
    try:
        data = b'{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' if rpc else b''
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers={'Content-Type':'application/json'}), timeout=2) as r:
            return r.status == 200
    except Exception:
        return False

def start():
    RUNTIME.mkdir(exist_ok=True)
    state = json.loads((RUNTIME/'processes.json').read_text()) if (RUNTIME/'processes.json').exists() else {}
    env = os.environ.copy()
    env['IPFS_PATH'] = str(RUNTIME/'ipfs')
    ipfs = os.environ.get('IPFS_BINARY') or shutil.which('ipfs')
    if not healthy('http://127.0.0.1:5001/api/v0/version'):
        if not ipfs:
            raise RuntimeError('Install Kubo or set IPFS_BINARY to its executable. No filesystem fallback is permitted.')
        if not (RUNTIME/'ipfs/config').exists():
            subprocess.run([ipfs,'init','--profile=test'], env=env, check=True, **hidden())
            subprocess.run([ipfs,'config','Addresses.API','/ip4/127.0.0.1/tcp/5001'],env=env,check=True,**hidden())
            subprocess.run([ipfs,'config','Addresses.Gateway','/ip4/127.0.0.1/tcp/8081'],env=env,check=True,**hidden())
        log = (RUNTIME/'ipfs.log').open('a')
        proc = subprocess.Popen([ipfs,'daemon','--offline'],cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,**hidden())
        state['ipfs'] = proc.pid
    if not healthy('http://127.0.0.1:8545',True):
        node = os.environ.get('NODE_BINARY') or shutil.which('node')
        if not node:
            raise RuntimeError('Node.js not found')
        log = (RUNTIME/'hardhat.log').open('a')
        proc = subprocess.Popen([node,str(ROOT/'node_modules/hardhat/internal/cli/cli.js'),'node','--hostname','127.0.0.1'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,**hidden())
        state['hardhat'] = proc.pid
    (RUNTIME/'processes.json').write_text(json.dumps(state))
    for _ in range(60):
        if healthy('http://127.0.0.1:5001/api/v0/version') and healthy('http://127.0.0.1:8545',True):
            print('Real Kubo and Hardhat ready on loopback interfaces')
            return
        time.sleep(1)
    raise RuntimeError('Infrastructure startup failed; inspect .runtime logs')

def stop():
    # Graceful Kubo shutdown addresses this package's fixed local test service.
    path = RUNTIME/'processes.json'
    if not path.exists():
        return
    state = json.loads(path.read_text())
    if 'ipfs' in state:
        try:
            urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:5001/api/v0/shutdown',data=b''),timeout=5).close()
        except Exception:
            pass
    # Hardhat is ephemeral. Only terminate the recorded owned PID after process identity check.
    if 'hardhat' in state:
        import psutil
        try:
            p = psutil.Process(state['hardhat'])
            if str(ROOT/'node_modules/hardhat/internal/cli/cli.js') in p.cmdline():
                p.terminate()
        except psutil.NoSuchProcess:
            pass
    path.unlink()

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('action',choices=['start','stop'])
    args = ap.parse_args()
    start() if args.action == 'start' else stop()
