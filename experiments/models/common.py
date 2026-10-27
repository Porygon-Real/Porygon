"""Prospective run-level fitting: heldout plans contain no outcome data."""
import json
import math
import re
from datetime import date,datetime
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
if str(ROOT/'backend/src') not in sys.path:sys.path.insert(0,str(ROOT/'backend/src'))
from porygon_api.evidence_features import CONTRACT,FEATURE_NAMES


def digest(value):
    from porygon_api.vulnerability import sha256_document
    return sha256_document(value)


def validate_group(row):
    for key in ('run_id','family','host_id','release'):
        if not isinstance(row.get(key),str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',row[key]):
            raise ValueError('Invalid bounded run/group identifier')
    if not isinstance(row.get('day'),str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}',row['day']):raise ValueError('Run day required')
    date.fromisoformat(row['day'])
    if not re.fullmatch(r'[^\s@]+@sha256:[a-f0-9]{64}',str(row.get('image_digest',''))):raise ValueError('Immutable image required')


def load_dataset(path,*,for_training=False):
    from porygon_api.evidence_features import EvidenceFeatureDocument
    if Path(path).stat().st_size>64*1024*1024:raise ValueError('Dataset exceeds bounded size')
    value=json.loads(Path(path).read_text());rows=value.get('runs')
    if (value.get('feature_contract')!=CONTRACT or not isinstance(rows,list) or not 1<=len(rows)<=100000 or
            value.get('data_kind') not in {'synthetic-fixture','independent-measured'}):raise ValueError('Unsupported dataset')
    groups={split:[] for split in ('fit','calibration','test')};seen={}
    for row in rows:
        if not isinstance(row,dict):raise ValueError('Run must be object')
        validate_group(row)
        split=row.get('split')
        if split not in groups or (for_training and split=='test') or (not for_training and split!='test'):
            raise ValueError('Training consumes fit/calibration only; evaluation consumes heldout only')
        if row['run_id'] in seen:raise ValueError('Run IDs must be unique')
        seen[row['run_id']]=split
        if row.get('label') not in {'benign','attack'} or row.get('label_source')!='independent-controller':raise ValueError('Independent controller labels required')
        if not re.fullmatch(r'[a-f0-9]{64}',str(row.get('ground_truth_sha256',''))):raise ValueError('Ground truth digest required')
        hours=row.get('container_hours')
        if not isinstance(hours,(int,float)) or isinstance(hours,bool) or not math.isfinite(hours) or not 0<hours<=8784:raise ValueError('Finite exposure required')
        EvidenceFeatureDocument.model_validate({'contract':CONTRACT,'values':row.get('features'),
            'observations':row.get('observations'),'identity_coverage':row.get('identity_coverage')})
        if row['identity_coverage']['unavailable_identity_events'] or 'unavailable' in row['observations'].values():raise ValueError('Unavailable features require declared abstention outside model fit')
        if split=='test':
            started=row.get('collection_started_at')
            if not isinstance(started,str):raise ValueError('Actual test collection time required')
            instant=datetime.fromisoformat(started)
            if instant.tzinfo is None or instant.date().isoformat()!=row['day']:raise ValueError('Test collection date/zone mismatch')
        groups[split].append(row)
    if for_training:
        plan=value.get('heldout_plan')
        if not isinstance(plan,list) or not plan or len(plan)>100000:raise ValueError('Prospective heldout plan required')
        plan_ids=set()
        for item in plan:
            if set(item)!={'run_id','family','host_id','release','day','image_digest'}:raise ValueError('Heldout plan cannot contain labels/features/outcomes')
            validate_group(item)
            if item['run_id'] in seen or item['run_id'] in plan_ids:raise ValueError('Heldout plan leakage')
            plan_ids.add(item['run_id'])
        training=groups['fit']+groups['calibration']
        if {row['family'] for row in training}&{row['family'] for row in plan}:raise ValueError('Heldout family leakage')
        if max(row['day'] for row in training)>=min(row['day'] for row in plan):raise ValueError('Heldout runs must be prospectively later')
        if not all(groups[key] and len({row['label'] for row in groups[key]})==2 for key in ('fit','calibration')):raise ValueError('Fit and calibration need both classes')
    physical={}
    for row in rows:
        key=(row['family'],row['release'],row['host_id'],row['day'])
        if key in physical and physical[key]!=row['split']:raise ValueError('Physical deployment group leakage')
        physical[key]=row['split']
    return value,groups


def sigmoid(value):return 1/(1+math.exp(-max(-700,min(700,value))))


def fit_logistic(vectors,labels,steps=1000,rate=0.05):
    weights=[0.0]*len(vectors[0]);intercept=0.0
    for _ in range(steps):
        gradient=[0.0]*len(weights);bias=0.0
        for vector,label in zip(vectors,labels):
            error=sigmoid(intercept+sum(a*b for a,b in zip(vector,weights)))-label;bias+=error
            for index,x in enumerate(vector):gradient[index]+=error*x
        intercept-=rate*bias/len(vectors)
        weights=[w-rate*(g/len(vectors)+0.001*w) for w,g in zip(weights,gradient)]
    return weights,intercept
