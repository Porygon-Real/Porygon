import hashlib
from collections import Counter
import pytest
from experiments import confirmatory
from experiments.artifacts import ArtifactError
from test_split_consumption import policy


def manifest():
    return {'workloads':[{'id':'WL-NGX','versions':['WL-NGX-V1','WL-NGX-V2'],'modes':['idle','steady_http','burst_http','alternate_read_only_config']}],
        'runtime_scenario_ids':['SCN-EXEC','SCN-LOW','SCN-FLOOD','SCN-CONTEXT'],
        'hard_negatives':{'WL-NGX':list(confirmatory.real.HARD_NEGATIVES['WL-NGX'])}}


def test_stratified_hash_order_and_exact_allocations():
    candidates=['run-'+str(index) for index in range(12)]
    assigned=confirmatory.stratified_assign(candidates,{'fit':2,'calibration':2,'pilot':5,'confirmatory':3})
    ordered=sorted(candidates,key=lambda identifier:hashlib.sha256(('porygon.research.protocol.v1:20260820:'+identifier).encode()).hexdigest())
    assert [assigned[item] for item in ordered]==['fit']*2+['calibration']*2+['pilot']*5+['confirmatory']*3


def test_matrix_retains_benign_hard_negatives_and_scenario_labels():
    rows=confirmatory.enumerate_entries('test-run',manifest(),45,policy())
    strata={row['stratum'] for row in rows}
    for stratum in strata:
        selected=[row for row in rows if row['stratum']==stratum];counts=Counter(row['split'] for row in selected)
        assert counts['pilot']==5 and counts['confirmatory']==45
        if selected[0]['hard_negative_id'] is not None:assert all(row['ground_truth_class']=='benign' for row in selected)
        elif selected[0]['scenario_id']=='SCN-NONE' and selected[0]['tag_drift_stage']!='drift-v2':assert counts['fit']==10 and counts['calibration']==10
        elif selected[0]['tag_drift_stage']=='drift-v2':assert counts['fit']==0 and counts['calibration']==0
        else:assert all(row['ground_truth_class']=='controlled-positive' for row in selected)


def test_missing_approval_stops_before_any_docker_call(monkeypatch,tmp_path):
    calls=[]
    monkeypatch.setattr(confirmatory,'validate_plan',lambda *args,**kwargs:(_ for _ in ()).throw(ArtifactError('review missing')))
    monkeypatch.setattr(confirmatory.real,'docker',lambda *args,**kwargs:calls.append(args))
    with pytest.raises(ArtifactError):confirmatory.collect({},tmp_path/'new','http://127.0.0.1')
    assert calls==[] and not (tmp_path/'new').exists()


def test_direct_trial_context_cannot_relabel_pilot_records():
    with pytest.raises((ArtifactError,KeyError)):
        confirmatory.validate_collection_authorization({'plan':{}},'pilot','trial')
