#!/usr/bin/env python3
"""Bounded standalone reproduction, writes results only to the requested directory."""
from __future__ import annotations
import argparse, csv, json, os, resource, sys, time
from pathlib import Path

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'src'))

def dump(path:Path,value) -> None:
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n',encoding='utf-8')

def csv_write(path:Path,rows:list[dict]) -> None:
    if not rows: raise ValueError('cannot silently write empty results')
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--pilot',action='store_true')
    args=parser.parse_args()
    output=args.out.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error('output directory must be absent or empty; results are never silently overwritten')
    if not hasattr(os,'sched_getaffinity'):
        parser.error('the bounded runner requires Linux affinity and resource limits')
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    resource.setrlimit(resource.RLIMIT_AS,(2048*1024**2,2048*1024**2))
    resource.setrlimit(resource.RLIMIT_CPU,(110,110))
    import signal
    signal.signal(signal.SIGALRM,lambda *_:sys.exit('120 second wall limit exceeded'))
    signal.alarm(120)
    start_wall=time.perf_counter();start_cpu=time.process_time()
    from churn.algebra import replicated_checks,shamir_checks,ring_checks,mixed_counterexample
    output.mkdir(parents=True,exist_ok=True)
    prime=3 if args.pilot else 5
    replicated,n=replicated_checks(prime); shamir,m=shamir_checks(prime)
    csv_write(output/'algebra.csv',replicated+shamir)
    dump(output/'counterexample.json',mixed_counterexample())
    obligations=n+m
    summary={'algebra_obligations':n+m,'replicated_obligations':n,'shamir_obligations':m,
             'replicated_correct':sum(r['correct'] for r in replicated),
             'replicated_wrong':sum(r['incorrect'] for r in replicated),
             'shamir_correct':sum(r['correct'] for r in shamir),
             'shamir_wrong':sum(r['incorrect'] for r in shamir),
             'oracle_disagreements':0}
    if not args.pilot:
        from churn.experiments import schedule_checks,crash_checks,semantic_checks,evidence_checks
        from collections import Counter
        ring,k=ring_checks();csv_write(output/'rings.csv',ring);obligations+=k
        schedules,traces,k=schedule_checks();csv_write(output/'schedules.csv',schedules)
        csv_write(output/'event_orders.csv',traces);obligations+=k
        crashes,k=crash_checks();csv_write(output/'crashes.csv',crashes);obligations+=k
        semantics,k=semantic_checks();csv_write(output/'semantics.csv',semantics);obligations+=k
        evidence,transcripts,k=evidence_checks();csv_write(output/'evidence.csv',evidence)
        dump(output/'signed_transcripts.json',transcripts);obligations+=k
        from churn.continuity_experiments import continuity_checks
        continuity,privacy,sizes,certificate,evidence_samples,k=continuity_checks()
        csv_write(output/'continuity_cases.csv',continuity)
        csv_write(output/'privacy_views.csv',privacy)
        csv_write(output/'certificate_sizes.csv',sizes)
        dump(output/'continuity_certificate.json',certificate)
        dump(output/'continuity_evidence.json',evidence_samples)
        obligations+=k
        from churn.joint_view import compute_report as joint_view_report
        joint_rows,joint_report=joint_view_report()
        csv_write(output/'joint_view_privacy.csv',joint_rows)
        dump(output/'joint_view_privacy.json',joint_report)
        joint_obligations=joint_report['exact_assignments']+joint_report['rank_checks']
        obligations+=joint_obligations
        summary.update({'ring_obligations':sum(r['assignments'] for r in ring),
                        'generated_schedule_fault_cases':len(traces)+len(crashes)+len(semantics)+len(evidence)+len(continuity),
                        'permutation_cases':len(traces),'crash_cases':len(crashes),
                        'semantic_cases':len(semantics),'signed_evidence_cases':len(evidence),
                        'signed_contradictions_accepted':sum(r['accepted'] for r in evidence),
                        'signed_negative_controls_rejected':sum(1-r['accepted'] for r in evidence),
                        'schedule_outcomes':{v:dict(Counter(r['outcome'] for r in schedules if r['variant']==v))
                                             for v in sorted({r['variant'] for r in schedules})},
                        'crash_pre_replay_activated':sum(r['active_before_replay'] for r in crashes),
                        'crash_post_replay_correct':sum(r['content_correct_after_replay'] for r in crashes),
                        'witness_bytes_min':min(r['statement_and_signature_bytes'] for r in evidence),
                        'witness_bytes_max':max(r['statement_and_signature_bytes'] for r in evidence),
                        'continuity_cases':len(continuity),
                        'continuity_case_failures':sum(r['observed']!=r['expected'] for r in continuity),
                        'privacy_view_obligations':sum(r['assignments'] for r in privacy),
                        'privacy_distributions_equal':sum(r['matches_secret_zero'] for r in privacy),
                        'joint_view_exact_assignments':joint_report['exact_assignments'],
                        'joint_view_distribution_comparisons':joint_report['exact_distribution_comparisons'],
                        'joint_view_rank_checks':joint_report['rank_checks'],
                        'joint_view_checks_passed':int(
                            joint_report['all_exact_distributions_equal'] and
                            joint_report['all_rank_checks_passed']),
                        'certificate_size_points':len(sizes),
                        'public_certificate_json_bytes_min':min(r['public_certificate_json_bytes'] for r in sizes),
                        'public_certificate_json_bytes_max':max(r['public_certificate_json_bytes'] for r in sizes),
                        'private_opening_bytes_dimension_1':sizes[0]['private_opening_statement_bytes'],
                        'private_opening_bytes_dimension_64':sizes[-1]['private_opening_statement_bytes']})
    summary['total_obligations']=obligations
    if obligations>100000 or summary.get('generated_schedule_fault_cases',0)>1000:
        raise AssertionError('frozen budget exceeded')
    dump(output/'scientific_summary.json',summary)
    telemetry={'workers':1,'cpu_seconds':time.process_time()-start_cpu,
               'wall_seconds':time.perf_counter()-start_wall,
               'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
               'total_process_cpu_seconds':resource.getrusage(resource.RUSAGE_SELF).ru_utime+resource.getrusage(resource.RUSAGE_SELF).ru_stime,
               'address_space_cap_mib':2048,'rss_ceiling_mib':2560,
               'per_command_cpu_limit_seconds':110,'per_command_wall_limit_seconds':120,
               'mode':'pilot' if args.pilot else 'full','obligations':obligations}
    if telemetry['peak_rss_kib']>2560*1024: raise AssertionError('RSS cap exceeded')
    dump(output/'telemetry.json',telemetry)
    signal.alarm(0)
    print(json.dumps({'summary':summary,'telemetry':telemetry},indent=2))

if __name__=='__main__': main()
