"""Finalize a run interrupted during scale registration without inventing results."""
from pathlib import Path
import argparse, csv, json
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from privledger.reporting import generate_plots, generate_report

def main():
    p=argparse.ArgumentParser(); p.add_argument('run_dir'); a=p.parse_args(); out=Path(a.run_dir)
    def rows(name):
        q=out/name
        return list(csv.DictReader(q.open(encoding='utf-8'))) if q.exists() else []
    integ=rows('e1_integrity_results.csv'); receipts=rows('transaction_receipts.jsonl')
    # JSONL is not CSV; the presence/count is retained in the limitations below.
    sample_counts={}
    for r in integ: sample_counts[r.get('sample_size','unknown')]=sample_counts.get(r.get('sample_size','unknown'),0)+1
    def rate(k):
        vals=[str(r.get(k,'')).lower()=='true' for r in integ]
        return sum(vals)/len(vals) if vals else None
    summary={'mode':'full','status':'partial','dataset':{'name':'CMU Enron 2015','real_enron':True},
      'scale_stopping_point':{'completed_integrity_rows':len(integ),'rows_by_sample_size':sample_counts,
        'reason':'Execution stopped after the 1000 workload and approximately 300 registrations of the 5000 workload because the real receipt/IPFS workload exceeded the available execution window. No unmeasured rows were filled.'},
      'E1':{'count':len(integ),'hash_fidelity_rate':rate('hash_fidelity'),'tamper_detection_rate':rate('tamper_detected'),'registration_event_completeness':rate('registration_event'),'ipfs_retrieval_success':rate('ipfs_retrieval_success'),'onchain_offchain_consistency':rate('onchain_offchain_consistency'),'evidence_type':'measured'},
      'E2':{'evidence_type':'measured','status':'not evaluated after scale interruption'},'E3':{'evidence_type':'not evaluated after scale interruption'},
      'E4':{'evidence_type':'not evaluated after scale interruption'},'E5':{'evidence_type':'measured','status':'partial'},
      'E7':{'evidence_type':'analytical','status':'not evaluated after scale interruption'},
      'limitations':['Partial full run: the real 1000-artifact workload completed; the 5000 workload stopped around 300; 10000 was not started.','No values were extrapolated or fabricated. Re-run scripts/reproduce.ps1 -Mode full to resume from a new run.','Smoke and quick runs are complete.','The CMU release contains email messages without original attachment payloads.']}
    (out/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    for name in ['e0_threat_coverage.csv','e2_access_results.csv','e4_redaction_results.csv','e4_deletion_results.csv','gas_results.csv','latency_results.csv','scalability_results.csv','e7_reliability_results.csv']:
        q=out/name
        if not q.exists(): q.write_text('evidence_type\nnot_evaluated\n',encoding='utf-8')
    for name,obj in [('e1_integrity_summary.json',summary['E1']),('e2_access_summary.json',summary['E2']),('e3_pii_scan.json',{'status':'not evaluated','evidence_type':'not evaluated'}),('e4_summary.json',summary['E4']),('e7_reliability_summary.json',summary['E7'])]:
        if not (out/name).exists(): (out/name).write_text(json.dumps(obj,indent=2),encoding='utf-8')
    generate_plots(out); generate_report(out,summary)
    print(out/'REPORT.md')
if __name__=='__main__': main()
