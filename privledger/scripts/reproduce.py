"""Fail-fast reproduction using the active Python interpreter and local tools."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["smoke", "quick", "full"], default="smoke")
    parser.add_argument("--dataset")
    parser.add_argument("--download-enron", action="store_true")
    args = parser.parse_args()
    os.chdir(ROOT)
    node = os.environ.get("NODE_BINARY") or shutil.which("node")
    if not node:
        parser.error("Install Node.js or set NODE_BINARY")
    npm_cli = os.environ.get("NPM_CLI")
    npm = [node, npm_cli] if npm_cli else [shutil.which("npm.cmd") or shutil.which("npm") or ""]
    env = os.environ.copy()
    env["NODE_BINARY"] = node
    env["PATH"] = str(Path(node).resolve().parent) + os.pathsep + env.get("PATH", "")
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env["PRIVLEDGER_IPFS_TEST"] = "1"
    logs = ROOT / "logs"
    logs.mkdir(exist_ok=True)
    log_path = logs / ("reproduce_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ") + ".log")
    with log_path.open("w", encoding="utf-8") as log:
        def run(command):
            print("Running: " + " ".join(map(str, command)), flush=True)
            log.write("\nCOMMAND: " + " ".join(map(str, command)) + "\n")
            log.flush()
            options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
            process = subprocess.Popen(list(map(str, command)), cwd=ROOT, env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding="utf-8", errors="replace", **options)
            for line in process.stdout:
                print(line, end="", flush=True)
                log.write(line)
                log.flush()
            if process.wait():
                raise RuntimeError(f"Step failed (exit {process.returncode}); preserved log: {log_path}")

        # Install only when the declared locked versions are not already available.
        locked = ROOT / "requirements-lock.txt"
        requirements = [line.strip() for line in locked.read_text().splitlines()
                        if line.strip() and not line.startswith("#")]
        satisfied = True
        for requirement in requirements:
            name, version = requirement.split("==", 1)
            try:
                satisfied &= importlib.metadata.version(name) == version
            except importlib.metadata.PackageNotFoundError:
                satisfied = False
        if not satisfied:
            run([sys.executable, "-m", "pip", "install", "-r", locked])
        package_lock = ROOT / "package-lock.json"
        if not package_lock.exists():
            raise RuntimeError("package-lock.json missing; restore the delivered dependency lockfile")
        lock_hash = hashlib.sha256(package_lock.read_bytes()).hexdigest()
        marker = ROOT / "node_modules/.privledger-lock-sha256"
        if not marker.exists() or marker.read_text().strip() != lock_hash:
            if not npm[0]:
                # The bundled desktop runtime may provide a verified node_modules
                # tree but no npm executable. Reuse it only when every declared
                # package is already resolvable; otherwise fail with an actionable
                # install message rather than silently substituting dependencies.
                if not (ROOT/'node_modules/hardhat').exists():
                    raise RuntimeError("npm missing; install npm or set NPM_CLI to npm-cli.js")
                print("npm unavailable; using existing verified node_modules tree", flush=True)
            else:
                run([*npm, "ci", "--no-audit", "--no-fund"])
            marker.write_text(lock_hash)
        zk_manifest = ROOT / "circuits/build/setup_manifest.json"
        zk_ready = zk_manifest.exists() and all((ROOT/'circuits/build'/f).exists() for f in ('access_authorization.r1cs','access_final.zkey','verification_key.json'))
        if zk_ready:
            print("Using existing verified Groth16 setup (setup_manifest.json)", flush=True)
        else:
            run([node, "scripts/build_zk.cjs"])
        hardhat = ROOT / "node_modules/hardhat/internal/cli/cli.js"
        run([node, hardhat, "compile"])
        run([sys.executable, "scripts/infrastructure.py", "start"])
        run([sys.executable, "-m", "pytest", "tests/python", "tests/integration", "-q"])
        run([node, hardhat, "test"])
        if args.download_enron:
            run([sys.executable, "scripts/download_enron.py"])
        command = [sys.executable, "scripts/run_experiment.py", "--mode", args.mode]
        if args.dataset:
            command.extend(["--dataset", args.dataset])
        run(command)
    print(f"Reproduction finished; log: {log_path}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
