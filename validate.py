#!/usr/bin/env python3
"""Bounded unit and offline signed-corpus validation, with explicit telemetry."""
from __future__ import annotations
import argparse, contextlib, io, json, os, resource, signal, sys, time, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--transcripts',type=Path,default=ROOT/'results/full/signed_transcripts.json')
    a=p.parse_args();out=a.out.resolve()
    if out.exists() and any(out.iterdir()):p.error('output must be absent or empty')
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    resource.setrlimit(resource.RLIMIT_AS,(2048*1024**2,2048*1024**2))
    resource.setrlimit(resource.RLIMIT_CPU,(110,110))
    signal.signal(signal.SIGALRM,lambda *_:sys.exit('wall limit exceeded'))
    signal.alarm(120);start=time.perf_counter()
    sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'src'))
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'))
    text=io.StringIO();result=unittest.TextTestRunner(stream=text,verbosity=2).run(suite)
    if not result.wasSuccessful():raise SystemExit(text.getvalue())
    import check_evidence
    old_argv=sys.argv;capture=io.StringIO()
    try:
        sys.argv=['check_evidence.py','--authorization',str(ROOT/'inputs/authorized_signers.json'),'--transcripts',str(a.transcripts.resolve())]
        with contextlib.redirect_stdout(capture):check_evidence.main()
    finally:sys.argv=old_argv
    evidence=json.loads(capture.getvalue())
    usage=resource.getrusage(resource.RUSAGE_SELF)
    report={'unit_tests':result.testsRun,'unit_failures':len(result.failures),'unit_errors':len(result.errors),
            'evidence':evidence,'counted_obligations':result.testsRun+evidence['cases'],
            'total_process_cpu_seconds':usage.ru_utime+usage.ru_stime,
            'wall_region_seconds':time.perf_counter()-start,'peak_rss_kib':usage.ru_maxrss,'workers':1}
    if report['peak_rss_kib']>2560*1024:raise AssertionError('RSS ceiling')
    out.mkdir(parents=True,exist_ok=True)
    (out/'validation.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    (out/'unit-tests.txt').write_text(text.getvalue())
    print(json.dumps(report,indent=2));signal.alarm(0)
if __name__=='__main__':main()
