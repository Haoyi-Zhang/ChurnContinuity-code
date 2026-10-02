#!/usr/bin/env python3
"""Replay the local signed corpus against a separately supplied trust anchor.

This command checks fixture verdicts; it neither accuses a live service nor
establishes that a supplied authorization file is genuine.
"""
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
from dataclasses import fields
sys.path.insert(0,str(Path(__file__).resolve().parent/'src'))
from churn.evidence import Binding,Signed,verify_contradiction

def reject_duplicates(pairs):
    result={}
    for k,v in pairs:
        if k in result:raise ValueError('duplicate JSON key')
        result[k]=v
    return result

def load(path:Path):
    if path.stat().st_size>2*1024**2:raise ValueError('input exceeds the 2 MiB local replay bound')
    return json.loads(path.read_text(),object_pairs_hook=reject_duplicates,
                      parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite JSON constant')))

def decode(raw:dict)->Signed:
    if set(raw)!={'statement','signature_hex'}:raise ValueError('invalid signed envelope')
    s=dict(raw['statement'])
    if set(s)!={f.name for f in fields(Binding)}:raise ValueError('invalid binding schema')
    for name in ('service','content','attempt','generation','phase','signer','root'):
        if not isinstance(s[name],str) or not 0<len(s[name])<=128:raise ValueError('invalid bounded label')
    for name in ('epoch','cut'):
        if type(s[name]) is not int or not 0<=s[name]<2**63:raise ValueError('invalid integer')
    if not isinstance(s['membership'],list) or not 1<=len(s['membership'])<=24:raise ValueError('invalid membership')
    if any(not isinstance(x,str) or not 0<len(x)<=128 for x in s['membership']):raise ValueError('invalid member label')
    if len(set(s['membership']))!=len(s['membership']):raise ValueError('duplicate members')
    s['membership']=tuple(s['membership'])
    sig=bytes.fromhex(raw['signature_hex'])
    if len(sig)!=64:raise ValueError('invalid Ed25519 signature length')
    return Signed(Binding(**s),sig)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--authorization',type=Path,required=True)
    ap.add_argument('--transcripts',type=Path,required=True)
    a=ap.parse_args();trusted=load(a.authorization);transcripts=load(a.transcripts)
    if not isinstance(trusted,list) or len(trusted)>1000:raise ValueError('invalid trust-anchor corpus')
    auth={}
    for entry in trusted:
        service,epoch,members,signer=entry['context'];ctx=(service,epoch,tuple(members),signer)
        key=bytes.fromhex(entry['public_key_hex'])
        if len(key)!=32 or ctx in auth:raise ValueError('duplicate or invalid trust anchor')
        auth[ctx]=key
    if not isinstance(transcripts,list) or len(transcripts)>1000:raise ValueError('invalid transcript corpus')
    accepted=0
    for row in transcripts:
        verdict=verify_contradiction(decode(row['left']),decode(row['right']),auth)
        if type(row['expected']) is not bool or verdict!=row['expected']:
            raise AssertionError('fixture verdict disagreement: '+str(row['case']))
        accepted+=verdict
    print(json.dumps({'cases':len(transcripts),'accepted':accepted,'rejected':len(transcripts)-accepted,
                      'disagreements':0,'trust_anchor':'separate explicitly supplied authorization file'}))
if __name__=='__main__':main()
