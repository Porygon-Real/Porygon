"""Evaluate complete heldout runs; synthetic fixtures never support model promotion."""
import argparse
import json
import math
from datetime import datetime,timezone
from pathlib import Path
from experiments.models.common import load_dataset,digest,FEATURE_NAMES
from experiments.artifacts import atomic_write_json


def evaluate(dataset_path,model_path):
    from porygon_api.model_registry import ModelArtifact,predict
    dataset,groups=load_dataset(dataset_path)
    if Path(model_path).stat().st_size>4*1024*1024:raise ValueError('Model exceeds bounded size')
    model=ModelArtifact.model_validate(json.loads(Path(model_path).read_text()))
    actual_plan=[{key:row[key] for key in ('run_id','family','host_id','release','day','image_digest')} for row in groups['test']]
    expected={row['run_id']:row for row in model.provenance['heldout_plan']}
    if {row['run_id']:row for row in actual_plan}!=expected:
        raise ValueError('Actual heldout collection differs from the predeclared immutable plan')
    if set(row['family'] for row in groups['test']) & set(row['family'] for row in model.provenance['training_groups']):
        raise ValueError('Heldout family leakage')
    records=[]
    for row in groups['test']:
        result=predict({'contract':model.feature_contract,'values':row['features'],
            'identity_coverage':row['identity_coverage'],'observations':row['observations']},model.model_dump())
        records.append({'run_id':row['run_id'],'family':row['family'],'label':row['label'],
            'probability':result['probability'],'positive':result['positive'],'container_hours':row['container_hours'],'ground_truth_sha256':row['ground_truth_sha256']})
    def metrics(rows):
        tp=sum(row['positive'] and row['label']=='attack' for row in rows)
        fp=sum(row['positive'] and row['label']=='benign' for row in rows)
        attacks=sum(row['label']=='attack' for row in rows)
        benign_hours=sum(row['container_hours'] for row in rows if row['label']=='benign')
        return {'precision':tp/(tp+fp) if tp+fp else None,'recall':tp/attacks if attacks else None,
            'false_alerts_per_container_hour':fp/benign_hours if benign_hours else None,
            'brier':sum((row['probability']-int(row['label']=='attack'))**2 for row in rows)/len(rows),
            'log_loss':-sum(math.log(max(1e-12,row['probability'] if row['label']=='attack' else 1-row['probability'])) for row in rows)/len(rows),
            'independent_runs':len(rows),'abstention':0,'coverage':1.0}
    return {'contract':'porygon.model-evaluation','artifact_sha256':model.artifact_sha256,
        'data_kind':dataset['data_kind'],'test_dataset_sha256':digest(dataset),
        'first_test_collection_at':min(datetime.fromisoformat(row['collection_started_at']).astimezone(timezone.utc) for row in groups['test']).isoformat(),
        'last_test_collection_at':max(datetime.fromisoformat(row['collection_finished_at']).astimezone(timezone.utc) for row in groups['test']).isoformat(),
        'test_run_ids':[row['run_id'] for row in records],
        'split_manifest_sha256':model.provenance['split_manifest_sha256'],'metrics':metrics(records),
        'by_family':{family:metrics([row for row in records if row['family']==family]) for family in sorted({row['family'] for row in records})},
        'records':records,'passed_validation':True,'promotion_eligible':False,'promotion_status':'requires-predeclared-quality-comparison-and-human-review'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--dataset',type=Path,required=True)
    parser.add_argument('--model',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();report=evaluate(args.dataset,args.model);atomic_write_json(args.output,report)
    print(json.dumps({'report_sha256':digest(report),'promotion_eligible':report['promotion_eligible']}))


if __name__=='__main__':main()
