"""Long-lived ethers/snarkjs bridge; secrets travel over stdin only."""
import json
import os
from pathlib import Path
import shutil
import subprocess

class Chain:
    def __init__(self, root, log):
        self.root = Path(root)
        self.counter = 0
        self.log = Path(log).open('a', encoding='utf-8')
        node = os.environ.get('NODE_BINARY') or shutil.which('node')
        flags = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
        self.proc = subprocess.Popen([node, 'scripts/bridge.cjs'], cwd=self.root, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=self.log, text=True, encoding='utf-8', **flags)
    def call(self, op, **kwargs):
        self.counter += 1
        self.proc.stdin.write(json.dumps({'id': self.counter, 'op': op, **kwargs})+'\n')
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError('Blockchain bridge exited; inspect bridge log')
        response = json.loads(line)
        if response['id'] != self.counter:
            raise RuntimeError('Bridge response sequence mismatch')
        if not response['ok']:
            raise RuntimeError(response['error'])
        return response['result']
    def close(self):
        if self.proc.poll() is None:
            self.proc.stdin.close()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.terminate()
        self.log.close()
