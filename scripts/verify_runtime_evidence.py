"""Verify bounded causal replay using harmless synthetic records in the backend image."""
import json
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
PROGRAM=r'''
import json,sys
sys.path.insert(0,'/app/tests')
from runtime_fixtures import events,SCOPE,START,END
from porygon_api.runtime_evidence import build_bundle
from porygon_api.evidence_features import extract_features
from porygon_api.model_registry import predict
source=events();first=build_bundle(source,SCOPE,START,END,{'/usr/bin/python'})
assert first==build_bundle(list(reversed(source)),SCOPE,START,END,{'/usr/bin/python'})
assert any(row['rule_id']=='POR-EVD-CHILD-NET' for row in first['findings'])
assert not build_bundle(source,SCOPE,START,END,{'/usr/bin/python','/tmp/helper'})['findings']
for row in source:row['process_start_ns']=None
assert not build_bundle(source,SCOPE,START,END,set())['findings']
assert predict(extract_features(first),None)['status']=='model_unavailable'
print(json.dumps({'passed':True,'fixture_kind':'synthetic-software-verification','causal_support':'verified','negative_controls':'verified','missing_metadata':'abstains','replay':'identical','model':'unavailable'}))
'''


def main():
    result=subprocess.run(['docker','compose','exec','-T','backend','python','-c',PROGRAM],cwd=ROOT,capture_output=True,text=True,timeout=30,check=True)
    print(json.dumps(json.loads(result.stdout)))


if __name__=='__main__':main()
