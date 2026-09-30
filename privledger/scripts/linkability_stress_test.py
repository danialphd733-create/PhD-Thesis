from pathlib import Path
import argparse
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from privledger.linkability import run_linkability

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--output-dir', required=True)
    p.add_argument('--pairs', type=int, default=10000)
    p.add_argument('--seed', type=int, default=42)
    a = p.parse_args()
    print(run_linkability(a.output_dir, pairs=a.pairs, seed=a.seed))
