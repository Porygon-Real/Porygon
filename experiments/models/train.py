"""Fit a deterministic run-level linear model and independent calibration map."""
import argparse
import json
import math
from pathlib import Path
import platform
from experiments.models.common import load_dataset,digest,fit_logistic,FEATURE_NAMES,CONTRACT
from experiments.artifacts import atomic_write_json


def train(path,seed=1729):
    dataset,groups=load_dataset(path,for_training=True)
    vectors=[[math.log1p(float(row['features'][key])) for key in FEATURE_NAMES] for row in groups['fit']]
    means=[sum(row[i] for row in vectors)/len(vectors) for i in range(len(FEATURE_NAMES))]
    scales=[max(1e-9,math.sqrt(sum((row[i]-means[i])**2 for row in vectors)/len(vectors))) for i in range(len(FEATURE_NAMES))]
    normalized=[[(x-means[i])/scales[i] for i,x in enumerate(row)] for row in vectors]
    weights,intercept=fit_logistic(normalized,[int(row['label']=='attack') for row in groups['fit']])
    calibration=[]
    for row in groups['calibration']:
        values=[(math.log1p(float(row['features'][key]))-means[i])/scales[i] for i,key in enumerate(FEATURE_NAMES)]
        calibration.append([intercept+sum(a*b for a,b in zip(values,weights))])
    slope,cal_intercept=fit_logistic(calibration,[int(row['label']=='attack') for row in groups['calibration']],steps=500)
    splits={row['run_id']:row['split'] for row in dataset['runs']} | {row['run_id']:'test' for row in dataset['heldout_plan']}
    model={'kind':'run-logistic','feature_contract':CONTRACT,'feature_names':list(FEATURE_NAMES),
        'means':means,'scales':scales,'weights':weights,'intercept':intercept,
        'calibration_slope':slope[0],'calibration_intercept':cal_intercept,'threshold':0.5,
        'provenance':{'fit_run_ids':[row['run_id'] for row in groups['fit']],
            'calibration_run_ids':[row['run_id'] for row in groups['calibration']],
            'heldout_run_ids':[row['run_id'] for row in dataset['heldout_plan']],
            'heldout_plan':dataset['heldout_plan'],'heldout_plan_sha256':digest(dataset['heldout_plan']),
            'training_groups':[{key:row[key] for key in ('run_id','family','day','host_id','release','image_digest')} for row in dataset['runs']],
            'split_manifest_sha256':digest(splits),'label_source':'independent-controller',
            'training_dataset_sha256':digest(dataset),'seed':seed,'dependencies':{'python':platform.python_version()},
            'evaluation_status':'not-promoted','data_kind':dataset['data_kind'],
            'hyperparameters':{'steps':1000,'learning_rate':0.05,'l2':0.001},
            'class_balance':{split:{label:sum(row['label']==label for row in records) for label in ('benign','attack')} for split,records in groups.items() if split!='test'}}}
    return dict(model,artifact_sha256=digest(model))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--dataset',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--seed',type=int,default=1729)
    args=parser.parse_args();model=train(args.dataset,args.seed);atomic_write_json(args.output,model)
    print(json.dumps({'artifact_sha256':model['artifact_sha256'],'promoted':False}))


if __name__=='__main__':main()
