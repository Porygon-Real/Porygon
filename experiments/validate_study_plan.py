"""Validate a prospective design separately from permission to collect outcomes."""
import argparse
from datetime import date,datetime,timezone
import json
import math
from pathlib import Path
import re
from urllib.parse import urlsplit

PRIMARY_HOSTS={'www.seclab.cs.sunysb.edu','www.ndss-symposium.org','tetragon.io','falco.org','arxiv.org'}


def validate(plan,*,for_collection=False,check_sources=False):
    if plan.get('contract')!='porygon.runtime-evidence-study':raise ValueError('Unsupported prospective contract')
    if plan.get('independent_unit')!='whole-collection-run' or plan.get('split_before_window_extraction') is not True:
        raise ValueError('Independent complete runs must be assigned before extraction')
    if set(plan.get('split_groups',[]))!={'run_id','family','release','host_id','day'}:raise ValueError('All leakage groups must be declared')
    if len(set(plan.get('workload_families',[])))<3 or plan.get('releases_per_family',0)<2:raise ValueError('Declared workload/release diversity required')
    if not {'startup','steady','burst','backup','update','admin','debug'}<=set(plan.get('benign_intervals',[])):raise ValueError('Benign change/maintenance controls required')
    scenarios=plan.get('scenarios',[])
    if not scenarios or len({row['id'] for row in scenarios})!=len(scenarios):raise ValueError('Unique scenarios required')
    if any(not row.get('negative_control') or not row.get('required_fields') for row in scenarios):raise ValueError('Every scenario needs a negative control and observed-field contract')
    if plan.get('ground_truth')!='independent-controller-with-corroborating-evidence':raise ValueError('Detector output cannot define labels')
    if not plan.get('primary_endpoint') or len(plan.get('primary_contrast',[]))!=2 or not plan.get('multiplicity'):raise ValueError('Primary contrast and multiplicity policy required')
    groups={};ids=set()
    for run in plan.get('runs',[]):
        if run.get('split') not in ('fit','calibration','test') or run['run_id'] in ids:raise ValueError('Invalid or duplicate assigned whole run')
        ids.add(run['run_id']);date.fromisoformat(run['day'])
        if run.get('label_source')!='independent-controller':raise ValueError('Independent label provenance required')
        key=tuple(run[key] for key in ('family','release','host_id','day'))
        if key in groups and groups[key]!=run['split']:raise ValueError('Physical deployment group crosses splits')
        groups[key]=run['split']
    if plan.get('runs'):
        cohorts={split:[row for row in plan['runs'] if row['split']==split] for split in ('fit','calibration','test')}
        if not all(cohorts.values()):raise ValueError('Fit/calibration/test partitions required')
        if 'family-held-out' in plan.get('evaluations',[]):
            if {row['family'] for row in cohorts['test']}&{row['family'] for row in cohorts['fit']+cohorts['calibration']}:raise ValueError('Heldout family leakage')
        if 'forward-in-time' in plan.get('evaluations',[]):
            if max(row['day'] for row in cohorts['fit']+cohorts['calibration'])>=min(row['day'] for row in cohorts['test']):raise ValueError('Forward-time leakage')
    for image in plan.get('images',[]):
        if not re.fullmatch(r'[^\s@]+@sha256:[a-f0-9]{64}',image.get('reference','')):raise ValueError('All images require immutable digests')
    if check_sources:
        sources=plan.get('sources',[])
        if len({row['id'] for row in sources})<6:raise ValueError('Primary-source matrix incomplete')
        for row in sources:
            url=urlsplit(row['url']);date.fromisoformat(row['accessed'])
            if url.scheme!='https' or url.hostname not in PRIMARY_HOSTS or not row.get('supports'):raise ValueError('Recorded primary source coordinates required')
    if any(not row.get('test') and not row.get('source') for row in plan.get('claims',[])):raise ValueError('Every planned claim needs a source or explicit empirical test')
    blockers=[]
    if not plan.get('sample_size'):blockers.append('independent pilot and sample-size lock missing')
    if not plan.get('precollection_lock'):blockers.append('reviewed precollection lock missing')
    if not plan.get('images'):blockers.append('image identity matrix missing')
    if not plan.get('runs'):blockers.append('immutable run assignments missing')
    if for_collection:
        if blockers:raise ValueError('Collection design remains incomplete')
        lock=plan['precollection_lock'];instant=datetime.fromisoformat(lock['locked_at'])
        if instant.tzinfo is None or instant>datetime.now(timezone.utc):raise ValueError('Actual aware precollection lock time required')
        if not lock.get('approved_by') or not re.fullmatch(r'[a-f0-9]{64}',lock.get('protocol_sha256','')) or not re.fullmatch(r'[a-f0-9]{64}',lock.get('analysis_sha256','')):raise ValueError('Reviewed immutable protocol/analysis identities required')
        from experiments.artifacts import sha256_json
        protocol={key:value for key,value in plan.items() if key not in {'precollection_lock','status'}}
        analysis={key:plan[key] for key in ('primary_contrast','primary_endpoint','recall_noninferiority_margin','comparators','ablations','missingness','multiplicity')}
        if lock['protocol_sha256']!=sha256_json(protocol) or lock['analysis_sha256']!=sha256_json(analysis):raise ValueError('Lock differs from actual protocol/analysis')
        images={row['reference'] for row in plan['images']}
        if any(row.get('image_reference') not in images for row in plan['runs']):raise ValueError('Every planned run must bind an enumerated immutable image')
        for row in plan['runs']:
            start=datetime.fromisoformat(row['planned_start_at'])
            if start.tzinfo is None or start<=instant:raise ValueError('Every planned collection must follow the real lock')
        sample=plan['sample_size']
        if type(sample.get('independent_runs_per_cell')) is not int or sample['independent_runs_per_cell']<1 or type(sample.get('power')) not in (int,float) or not math.isfinite(sample['power']) or not 0<sample['power']<=1:
            raise ValueError('Feasible independently justified run-level sample size required')
    return {'design_valid':True,'collection_ready':bool(for_collection and not blockers),'blockers':blockers,
        'source_check':'recorded primary-source coordinates only; no network retrieval' if check_sources else 'not-requested'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--plan',type=Path,required=True);parser.add_argument('--check-sources',action='store_true');parser.add_argument('--for-collection',action='store_true');args=parser.parse_args()
    if args.plan.stat().st_size>4*1024*1024:raise ValueError('Plan exceeds bounded size')
    print(json.dumps(validate(json.loads(args.plan.read_text()),for_collection=args.for_collection,check_sources=args.check_sources),sort_keys=True))


if __name__=='__main__':main()
