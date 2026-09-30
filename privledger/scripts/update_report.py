from pathlib import Path
import argparse, csv, json
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from privledger.reporting import generate_plots, generate_report

def main():
 p=argparse.ArgumentParser();p.add_argument('run_dir');a=p.parse_args();d=Path(a.run_dir)
 s=json.loads((d/'summary.json').read_text())
 rec=json.loads((d/'e7_live_ipfs_recovery.json').read_text()) if (d/'e7_live_ipfs_recovery.json').exists() else None
 if rec: s['E7']={'measured_ipfs_recovery_ms':rec['recovery_time_ms'],'retrievable_count':rec['retrievable_count'],'selected_count':rec['selected_count'],'hashes_unchanged':rec['hashes_unchanged'],'evidence_type':'measured','analytical_reference':rec['analytical_reference']}
 refs={'hash_fidelity':1.0,'registration_event_completeness':1.0,'static_linkability_roc_auc':1.0,'rotated_linkability_roc_auc':0.909,'rotated_linkability_accuracy':0.877,'rotated_linkability_f1':0.890,'privledger_register_gas':750000,'privledger_delete_gas':420000}
 ours={'hash_fidelity':s.get('E1',{}).get('hash_fidelity_rate'),'registration_event_completeness':s.get('E1',{}).get('registration_event_completeness')}
 link=s.get('linkability',{}).get('results',[])
 for r in link:
  if r.get('condition')=='static' and r.get('ablation')=='all': ours['static_linkability_roc_auc']=r.get('roc_auc')
  if r.get('condition')=='rotated' and r.get('ablation')=='all': ours['rotated_linkability_roc_auc']=r.get('roc_auc');ours['rotated_linkability_accuracy']=r.get('accuracy');ours['rotated_linkability_f1']=r.get('f1')
 gas={r['operation']:r.get('mean') for r in csv.DictReader((d/'gas_results.csv').open())} if (d/'gas_results.csv').exists() else {}
 for k,op in [('privledger_register_gas','register'),('privledger_delete_gas','delete')]: ours[k]=gas.get(op)
 rows=[]
 for k,v in refs.items():
  ov=ours.get(k); diff=(ov-v) if isinstance(ov,(int,float)) else None
  rows.append({'metric':k,'our_value':ov,'thesis_value':v,'our_evidence_type':s.get('E1',{}).get('evidence_type','measured') if k.startswith(('hash','registration')) else 'measured','thesis_evidence_type':'thesis-reference','difference':diff,'percent_difference':(diff/v*100 if diff is not None and v else None),'interpretation':'Reference comparison; values are not combined or tuned.'})
 with (d/'measured_vs_thesis.csv').open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
 (d/'summary.json').write_text(json.dumps(s,indent=2))
 generate_plots(d);generate_report(d,s)
main()
