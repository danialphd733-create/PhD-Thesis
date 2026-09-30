"""Regenerate plots and report from a completed run directory."""
from pathlib import Path
import argparse, json, sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from privledger.reporting import generate_plots, generate_report

def main():
    p=argparse.ArgumentParser(); p.add_argument('run_dir'); a=p.parse_args()
    run=Path(a.run_dir); summary=json.loads((run/'summary.json').read_text())
    generate_plots(run); generate_report(run,summary); print(run/'REPORT.md')

if __name__ == '__main__':
    main()
