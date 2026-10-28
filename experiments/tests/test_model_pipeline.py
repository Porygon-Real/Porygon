import json
from pathlib import Path
import sys
import pytest
ROOT=Path(__file__).resolve().parents[2]
if str(ROOT/'backend/src') not in sys.path:sys.path.insert(0,str(ROOT/'backend/src'))
from experiments.models.train import train
from experiments.models.evaluate import evaluate
from porygon_api.evidence_features import CONTRACT,FEATURE_NAMES
from porygon_api.model_registry import ModelArtifact


def run(identifier,split,label,family,day):
    return {'run_id':identifier,'split':split,'label':label,'label_source':'independent-controller','ground_truth_sha256':'e'*64,
        'family':family,'host_id':'host','release':'release','day':day,'image_digest':'fixture@sha256:'+'d'*64,'container_hours':1.0,
        'features':{name:float(label=='attack') for name in FEATURE_NAMES},
        'observations':{'memfd_execution':'not_observed','writable_execution':'not_observed'},'identity_coverage':{'unavailable_identity_events':0}}


def dataset():
    rows=[run('fit-'+label,'fit',label,'training','2027-01-01') for label in ('benign','attack')]
    rows += [run('calibration-'+label,'calibration',label,'training','2027-01-02') for label in ('benign','attack')]
    heldout=[{key:value for key,value in run('heldout-'+label,'test',label,'heldout','2027-02-01').items() if key in ('run_id','family','host_id','release','day','image_digest')} for label in ('benign','attack')]
    return {'feature_contract':CONTRACT,'data_kind':'synthetic-fixture','runs':rows,'heldout_plan':heldout}


def test_training_is_deterministic_and_cannot_consume_heldout_outcomes(tmp_path):
    source=tmp_path/'training.json';source.write_text(json.dumps(dataset()))
    first=train(source);assert first==train(source);ModelArtifact.model_validate(first)
    assert set(first['provenance']['class_balance'])=={'fit','calibration'}
    value=dataset();value['heldout_plan'][0]['label']='attack';source.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='outcome'):train(source)


def test_corrupt_artifact_and_heldout_family_leakage_are_refused(tmp_path):
    source=tmp_path/'training.json';source.write_text(json.dumps(dataset()));artifact=train(source)
    artifact['weights'][0]+=1
    with pytest.raises(ValueError):ModelArtifact.model_validate(artifact)
    value=dataset();value['heldout_plan'][0]['family']='training';source.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='family'):train(source)


def test_synthetic_evaluation_never_promotes_and_binds_actual_test_data(tmp_path):
    source=tmp_path/'training.json';source.write_text(json.dumps(dataset()));artifact=train(source)
    model=tmp_path/'model.json';model.write_text(json.dumps(artifact))
    rows=[]
    for label in ('benign','attack'):
        row=run('heldout-'+label,'test',label,'heldout','2027-02-01')
        row.update(collection_started_at='2027-02-01T00:00:00+00:00',collection_finished_at='2027-02-01T01:00:00+00:00');rows.append(row)
    test=tmp_path/'heldout.json';test.write_text(json.dumps({'feature_contract':CONTRACT,'data_kind':'synthetic-fixture','runs':rows}))
    report=evaluate(test,model)
    assert report['data_kind']=='synthetic-fixture' and report['promotion_eligible'] is False
    assert report['test_dataset_sha256']!=artifact['provenance']['training_dataset_sha256']
