"""Preauthorized frozen matrix collection and network-free immutable replay.

All reviews, sample-size feasibility, image coordinates and analysis choices are
validated before pulling an image or creating a network/container. Pilot records
are never promoted by editing their split or eligibility fields.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import urllib.request
from experiments import conformance,real,sample_size
from experiments.artifacts import ArtifactError,atomic_write_json,sha256_file,sha256_json
from experiments.frozen_analysis import evaluate_trials,validate_policy
from scripts.private_api import open_api

ROOT=Path(__file__).resolve().parents[1]
ASSIGNMENT_POLICY='frozen-stratified-preconstructed'
SPLIT_SEED=20260820
_COLLECTION_AUTHORIZATION=object()


def read_document(path,limit=64*1024*1024):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>limit:raise ArtifactError('Missing or unbounded regular artifact')
    return json.loads(path.read_text())


def confined(run_dir,name):
    if not isinstance(name,str) or not name or Path(name).is_absolute() or '..' in Path(name).parts:raise ArtifactError('Artifact path escapes run directory')
    root=Path(run_dir).resolve();candidate=root/name
    part=root
    for token in Path(name).parts:
        part=part/token
        if part.is_symlink():raise ArtifactError('Artifact symlinks are forbidden')
    if not candidate.resolve().is_relative_to(root):raise ArtifactError('Artifact path escapes run directory')
    return candidate


def aware(value):
    parsed=datetime.fromisoformat(value)
    if parsed.tzinfo is None:raise ArtifactError('Timezone-aware artifact timestamp required')
    return parsed.astimezone(timezone.utc)


def validate_gates(lock,policy,*,now=None,recorded_state=None,source_tree_sha256=None):
    now=now or datetime.now(timezone.utc)
    manifest=conformance.load_protocol_manifest()
    state=recorded_state if recorded_state is not None else sample_size._load_review_gate().gate_state()
    if not state.get('confirmatory_permitted') or manifest['protocol_status']!='frozen':
        raise ArtifactError('Frozen protocol and independent security/methodology approvals are required')
    validate_policy(policy)
    if (lock.get('reviewer_approval_status')!='approved' or lock.get('reviewer_approvals')!=state or
        lock.get('protocol_sha256')!=manifest['protocol_sha256'] or
        lock.get('enumeration_code_sha256')!=sha256_file(Path(sample_size.__file__)) or
        aware(lock['created_at_utc'])>now):raise ArtifactError('Sample lock is stale, incomplete or future-dated')
    inputs=lock['inputs'];contrasts=inputs.get('contrasts',{})
    expected={entry[0] for entry in sample_size.PRIMARY_CONTRASTS}
    if set(contrasts)!=expected:raise ArtifactError('All three co-primary contrasts are required')
    for contrast in contrasts.values():
        if (type(contrast.get('discordant_successes')) is not int or type(contrast.get('discordant_trials')) is not int or
            not 0<=contrast['discordant_successes']<=contrast['discordant_trials'] or contrast['discordant_trials']<1 or
            type(contrast.get('baseline_fpr')) not in (float,int) or not math.isfinite(contrast['baseline_fpr']) or not 0<contrast['baseline_fpr']<1):
            raise ArtifactError('Invalid independent pilot inputs')
    if not isinstance(inputs.get('reference_recall'),(int,float)) or not math.isfinite(inputs['reference_recall']) or not 0<inputs['reference_recall']<=1:
        raise ArtifactError('Finite independently measured pilot recall required')
    calculated=sample_size.build_sample_size_lock(
        {name:(row['discordant_successes'],row['discordant_trials']) for name,row in contrasts.items()},
        {name:row['baseline_fpr'] for name,row in contrasts.items()},inputs['reference_recall'])
    if sample_size.lock_to_dict(calculated)!=lock.get('lock') or calculated.feasibility_failure or calculated.locked_per_cell_count is None:
        raise ArtifactError('A matching feasible pre-collection power enumeration is required')
    if not 1<=calculated.locked_per_cell_count<=120:raise ArtifactError('Locked sample size outside frozen search')
    if inputs.get('analysis_policy_sha256')!=sha256_json(policy):
        raise ArtifactError('Sample/review package must bind the exact justified analysis policy before collection')
    review=inputs.get('analysis_review',{})
    if source_tree_sha256 is None:
        from scripts.source_identity import source_identity
        source_tree_sha256=source_identity()['tree_sha256']
    reviewer=review.get('reviewer_name','')
    normalized=' '.join(reviewer.casefold().split()) if isinstance(reviewer,str) else ''
    if (review.get('decision')!='approved' or review.get('human_recorded') is not True or
        not normalized or normalized in {'anurup r krishnan','replace with your name'} or
        any(term in normalized for term in ('codex','chatgpt','claude','assistant')) or
        not isinstance(review.get('reference'),str) or not review['reference'].strip() or
        review.get('policy_sha256')!=sha256_json(policy) or review.get('source_tree_sha256')!=source_tree_sha256 or
        review.get('sample_result_sha256')!=sha256_json(lock['lock']) or
        aware(review['reviewed_at'])>aware(lock['created_at_utc'])):
        raise ArtifactError('Exact analysis policy/source/power result needs an independent recorded human review before locking')
    return manifest,state,calculated.locked_per_cell_count


def stratified_assign(candidates,counts):
    if sum(counts.values())!=len(candidates) or len(set(candidates))!=len(candidates):raise ArtifactError('Assignment accounting mismatch')
    ordered=sorted(candidates,key=lambda identifier:hashlib.sha256(f'porygon.research.protocol.v1:{SPLIT_SEED}:{identifier}'.encode()).hexdigest())
    assigned={};offset=0
    for split in ('fit','calibration','pilot','confirmatory'):
        for identifier in ordered[offset:offset+counts.get(split,0)]:assigned[identifier]=split
        offset+=counts.get(split,0)
    return assigned


def enumerate_entries(run_id,manifest,count,policy):
    entries=[]
    def add_stratum(workload,mode,scenario,variant,counts,ground_truth,hard_negative=None,alias=None,tag_stage=None):
        stratum='|'.join((workload,mode,scenario,variant,hard_negative or 'none',alias or 'frozen-human-tag'))
        prefix=hashlib.sha256((run_id+':'+stratum).encode()).hexdigest()[:16]
        ids=[run_id+'-'+prefix+'-'+str(index).zfill(4) for index in range(sum(counts.values()))]
        assigned=stratified_assign(ids,counts)
        for index,identifier in enumerate(ids):
            entries.append({'trial_id':identifier,'workload_id':workload,'mode':mode,'scenario_id':scenario,
                'variant':variant,'replica':index%3,'stratum':stratum,'split':assigned[identifier],
                'ground_truth_class':ground_truth,'hard_negative_id':hard_negative,'alias':alias,'tag_drift_stage':tag_stage,'fit_use':'contamination-sensitivity-only' if ground_truth=='controlled-positive' and assigned[identifier]=='fit' else 'primary'})
    for workload in manifest['workloads']:
        for version in workload['versions']:
            for mode in workload['modes']:
                add_stratum(version,mode,real.BENIGN_SENTINEL,'baseline',{'fit':policy['minimum_fit_runs'],
                    'calibration':policy['minimum_calibration_runs'],'pilot':5,'confirmatory':max(30,count)},'benign')
            family=real.family_of(version);mode=real.default_mode(family)
            for scenario in manifest['runtime_scenario_ids']:
                variant='no_new_privileges' if scenario=='SCN-CONTEXT' else 'baseline'
                add_stratum(version,mode,scenario,variant,{'fit':10,'calibration':0,'pilot':5,'confirmatory':max(20,count)},'controlled-positive')
            for hard_negative in manifest['hard_negatives'][family]:
                if hard_negative not in real.HARD_NEGATIVES[family]:raise ArtifactError('Frozen hard-negative generator missing')
                add_stratum(version,mode,hard_negative,'baseline',{'fit':0,'calibration':0,'pilot':5,'confirmatory':max(30,count)},'benign',hard_negative)
    for workload in manifest['workloads']:
        family=workload['id'];repository={'WL-NGX':'nginx','WL-RDS':'redis','WL-PG':'postgres'}[family]
        alias='porygon-study/'+repository+':mutable';mode=real.default_mode(family)
        add_stratum(family+'-V1',mode,real.BENIGN_SENTINEL,'baseline',{'fit':policy['minimum_fit_runs'],'calibration':policy['minimum_calibration_runs'],'pilot':5,'confirmatory':max(30,count)},'benign',alias=alias,tag_stage='fit-v1')
        add_stratum(family+'-V2',mode,real.BENIGN_SENTINEL,'baseline',{'fit':0,'calibration':0,'pilot':5,'confirmatory':max(30,count)},'benign',alias=alias,tag_stage='drift-v2')
    return entries


def build_plan(run_id,lock,policy):
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{2,60}',run_id):raise ArtifactError('Bounded descriptive run ID required')
    manifest,state,count=validate_gates(lock,policy)
    entries=enumerate_entries(run_id,manifest,count,policy)
    from scripts.source_identity import source_identity
    identity=source_identity();identity={key:value for key,value in identity.items() if key!='files'}
    document={'contract':'porygon.frozen-collection-plan','run_id':run_id,'created_at':datetime.now(timezone.utc).isoformat(),
        'assignment_policy':ASSIGNMENT_POLICY,'assignment_seed':SPLIT_SEED,'protocol_sha256':manifest['protocol_sha256'],
        'sample_lock':lock,'analysis_policy':policy,'review_state':state,'images':manifest['image_coordinates'],
        'source':identity,'entries':entries,'analysis_only_scenarios':manifest['analysis_only_scenario_ids']}
    return dict(document,plan_sha256=sha256_json(document))


def validate_plan(plan,*,online_gates=True):
    raw={key:value for key,value in plan.items() if key!='plan_sha256'}
    if (plan.get('contract')!='porygon.frozen-collection-plan' or plan.get('assignment_policy')!=ASSIGNMENT_POLICY or
        sha256_json(raw)!=plan.get('plan_sha256')):raise ArtifactError('Invalid immutable collection plan')
    manifest,_,count=validate_gates(plan['sample_lock'],plan['analysis_policy'],now=aware(plan['created_at']),recorded_state=plan['review_state'],source_tree_sha256=plan['source']['tree_sha256'])
    if plan['protocol_sha256']!=manifest['protocol_sha256'] or plan['entries']!=enumerate_entries(plan['run_id'],manifest,count,plan['analysis_policy']):
        raise ArtifactError('Plan omits or changes frozen assignment cells')
    if online_gates:
        expected=build_plan(plan['run_id'],plan['sample_lock'],plan['analysis_policy'])
        for key in ('entries','protocol_sha256','analysis_policy','images','source'):
            if expected[key]!=plan[key]:raise ArtifactError('Collection plan drifted from current reviewed matrix/source')
    ids=[row['trial_id'] for row in plan['entries']]
    if len(set(ids))!=len(ids):raise ArtifactError('Duplicate planned run identity')
    if aware(plan['sample_lock']['created_at_utc'])>=aware(plan['created_at']):raise ArtifactError('Power/analysis lock must predate collection plan')
    return plan


def validate_collection_authorization(context,run_id,trial_id):
    plan=context['plan']
    raw={key:value for key,value in plan.items() if key!='plan_sha256'}
    if context.get('_validated_plan') is not _COLLECTION_AUTHORIZATION or sha256_json(raw)!=plan['plan_sha256']:
        raise ArtifactError('Trial must be dispatched by the gated collection runner')
    if context['plan_sha256']!=plan['plan_sha256'] or plan['run_id']!=run_id:
        raise ArtifactError('Collection authorization scope mismatch')
    if context['entry'] not in plan['entries'] or context['entry']['trial_id']!=trial_id:
        raise ArtifactError('Trial was not preconstructed in the immutable matrix')


def operator_snapshot(base_url,trial):
    value=os.environ.get('PORYGON_OPERATOR_API_TOKEN')
    path=os.environ.get('PORYGON_OPERATOR_API_TOKEN_FILE')
    if path:value=Path(path).read_text().strip()
    if not value:
        from experiments.study import _token
        value=_token('PORYGON_OPERATOR_API_TOKEN')
    if not value:raise ArtifactError('Operator credential unavailable for bounded offline snapshot')
    body={'docker_host_id':trial['docker_host_id'],'container_id':trial['container_id'],'image_digest':trial['image']['reference'],
        'start':trial['timeline']['setup_started_at_utc'],'end':trial['timeline']['cleanup_finished_at_utc'],'max_events':100000}
    request=urllib.request.Request(base_url.rstrip('/')+'/operator/v1/evaluation-snapshots',data=json.dumps(body).encode(),
        headers={'Content-Type':'application/json','X-Porygon-Operator-Token':value},method='POST')
    with open_api(request,timeout=60) as response:return json.load(response)


def collect(plan,run_dir,base_url):
    validate_plan(plan) # No Docker call is reachable before this gate.
    run_dir=Path(run_dir)
    if run_dir.exists():raise ArtifactError('Collection requires a fresh run directory; no pilot relabel or overwrite')
    run_dir.mkdir(mode=0o700,parents=True)
    atomic_write_json(run_dir/'plan.json',plan)
    from scripts.source_identity import source_identity
    from experiments.artifacts import atomic_write_bytes,canonical_json
    source_files=source_identity()['files']
    # Dedicated metadata: only relative source coordinates and SHA-256 digests, no file contents.
    if any(Path(name).is_absolute() or '..' in Path(name).parts or not re.fullmatch(r'[a-f0-9]{64}',digest) for name,digest in source_files.items()):
        raise ArtifactError('Invalid source identity metadata')
    atomic_write_bytes(run_dir/'source-files.json',(canonical_json(source_files)+'\n').encode())
    images={}
    for workload,coordinate in plan['images'].items():
        image=real.pull_pinned_image(coordinate['index_digest_ref']);image['human_tag']=coordinate['human_tag'];images[workload]=image
    atomic_write_json(run_dir/'images.json',images)
    from experiments.environment import run_environment
    atomic_write_json(run_dir/'environment.json',run_environment())
    network='porygon-exp-'+plan['run_id'];created=False;aliases={};last_alias={}
    try:
        real.docker('network','create','--label',f'{real.LABEL_RUN}={plan["run_id"]}',network);created=True
        order={'fit':0,'calibration':1,'pilot':2,'confirmatory':3}
        for entry in sorted(plan['entries'],key=lambda row:(order[row['split']],row['trial_id'])):
            image=dict(images[entry['workload_id']])
            alias=entry.get('alias')
            if alias:
                inspected=subprocess.run(['docker','image','inspect',alias],capture_output=True,text=True)
                current=json.loads(inspected.stdout)[0]['Id'] if inspected.returncode==0 else None
                if alias not in aliases:aliases[alias]=current
                elif current!=last_alias.get(alias):raise ArtifactError('Controlled alias changed concurrently')
                real.docker('tag',image['local_image_id'],alias);last_alias[alias]=image['local_image_id']
                image['human_tag']=alias
                resolved=json.loads(real.docker('image','inspect',alias))[0]['Id']
                if resolved!=image['local_image_id']:raise ArtifactError('Controlled alias resolved to the wrong immutable image')
            record=real.run_trial(run_id=plan['run_id'],trial_id=entry['trial_id'],workload_id=entry['workload_id'],
                mode=entry['mode'],scenario_id=entry['scenario_id'],variant=entry['variant'],replica=entry['replica'],
                image=image,network=network,base_url=base_url,seed=20260821,
                warmup_seconds=3,operations=40,settle_seconds=plan['analysis_policy']['scenario_horizon_seconds'],
                collection_context={'plan':plan,'plan_sha256':plan['plan_sha256'],'entry':entry,'_validated_plan':_COLLECTION_AUTHORIZATION})
            if record['status']=='completed':
                try:
                    snapshot=operator_snapshot(base_url,record)
                    atomic_write_json(confined(run_dir,'snapshots/'+entry['trial_id']+'.json'),snapshot)
                except (ArtifactError,OSError,ValueError):
                    record['snapshot_status']='unavailable';record['status']='failed';record['failure_reason']='bounded snapshot unavailable'
            record['stratum']=entry['stratum'];record['fit_use']=entry['fit_use']
            if alias:record.update(alias=alias,tag_drift_stage=entry['tag_drift_stage'],resolved_digest=image['reference'],resolved_local_image_id=image['local_image_id'])
            atomic_write_json(confined(run_dir,'trials/'+entry['trial_id']+'.json'),record)
    finally:
        for alias,previous in aliases.items():
            inspected=subprocess.run(['docker','image','inspect',alias],capture_output=True,text=True)
            current=json.loads(inspected.stdout)[0]['Id'] if inspected.returncode==0 else None
            if current==last_alias.get(alias):
                if previous:real.docker('tag',previous,alias)
                else:real.docker('image','rm',alias)
        if created:real.remove_network(network,plan['run_id'])
        write_manifest(run_dir,final=False)
    report=replay(run_dir,compare=False)
    atomic_write_json(run_dir/'analysis.json',report)
    atomic_write_json(run_dir/'claim-results.json',{'contract':'porygon.claim-results','claims':[{'claim_id':'profile-scope-primary','status':'not-evaluated','result_path':'analysis.json',
        'result_sha256':sha256_file(run_dir/'analysis.json'),'metric_coordinates':'result_tables.primary_contrasts',
        'scope_boundary':'controlled Docker workload matrix; scientific claim review pending'}]})
    write_manifest(run_dir)
    return report


def write_manifest(run_dir,final=True):
    files={}
    for path in sorted(Path(run_dir).rglob('*')):
        if path.is_symlink():raise ArtifactError('Symlink in collected artifact set')
        if path.is_file() and path.name not in {'artifact-manifest.json','collection-manifest.json'}:
            files[str(path.relative_to(run_dir))]=sha256_file(path)
    name='artifact-manifest.json' if final else 'collection-manifest.json'
    return atomic_write_json(Path(run_dir)/name,{'contract':'porygon.frozen-artifact-manifest','files':files})


def replay(run_dir,*,compare=True):
    run_dir=Path(run_dir).resolve()
    manifest_path=confined(run_dir,'artifact-manifest.json')
    if not manifest_path.exists() and not compare:manifest_path=confined(run_dir,'collection-manifest.json')
    if not manifest_path.exists():raise ArtifactError('Complete artifact manifest required')
    manifest=read_document(manifest_path);files=manifest['files']
    actual={str(path.relative_to(run_dir)) for path in run_dir.rglob('*') if path.is_file() and path.name not in {'artifact-manifest.json','collection-manifest.json'}}
    if set(files)!=actual:raise ArtifactError('Manifest omits or invents collected files')
    for name,digest in files.items():
        if sha256_file(confined(run_dir,name))!=digest:raise ArtifactError('Collected artifact hash mismatch')
    plan=validate_plan(read_document(confined(run_dir,'plan.json')),online_gates=False)
    # Pure analysis code/configuration must match the recorded collection implementation.
    source_files=read_document(confined(run_dir,'source-files.json'))
    tree_hash=hashlib.sha256(json.dumps(source_files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if tree_hash!=plan['source']['tree_sha256']:raise ArtifactError('Source inventory differs from locked tree')
    for name,digest in source_files.items():
        if (name.startswith(('experiments/','backend/src/','docs/research/')) or name=='scripts/review_gate.py') and sha256_file(confined(ROOT,name))!=digest:
            raise ArtifactError('Analysis implementation drift; replay with the recorded source tree')
    trials=[];snapshots={}
    for entry in plan['entries']:
        name='trials/'+entry['trial_id']+'.json';path=confined(run_dir,name)
        if path.exists():
            trial=read_document(path)
            if trial.get('split')!=entry['split'] or trial.get('collection_plan_sha256')!=plan['plan_sha256']:
                raise ArtifactError('Trial is not an original authorized collection record')
        else:trial=dict(entry,status='failed',ground_truth_class=entry['ground_truth_class'])
        trials.append(trial)
        snapshot=confined(run_dir,'snapshots/'+entry['trial_id']+'.json')
        if snapshot.exists():snapshots[entry['trial_id']]=read_document(snapshot)
    report=evaluate_trials(trials,snapshots,{row['trial_id']:row['split'] for row in plan['entries']},plan['analysis_policy'])
    from experiments.frozen_statistics import summarize
    report['result_tables']=summarize(report)
    report['plan_sha256']=plan['plan_sha256'];report['collection_accounting']={'planned':len(plan['entries']),'completed':sum(row.get('status')=='completed' for row in trials),'failed_or_missing':sum(row.get('status')!='completed' for row in trials)}
    recorded=confined(run_dir,'analysis.json')
    if compare and (not recorded.exists() or sha256_json(read_document(recorded))!=sha256_json(report)):
        raise ArtifactError('Offline analysis differs from recorded result')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__);subs=parser.add_subparsers(dest='command',required=True)
    planning=subs.add_parser('plan');planning.add_argument('--run-id',required=True);planning.add_argument('--sample-lock',type=Path,required=True);planning.add_argument('--analysis-policy',type=Path,required=True);planning.add_argument('--output',type=Path,required=True)
    collecting=subs.add_parser('collect');collecting.add_argument('--plan',type=Path,required=True);collecting.add_argument('--run-dir',type=Path,required=True);collecting.add_argument('--base-url',default='http://127.0.0.1:8000')
    replaying=subs.add_parser('replay');replaying.add_argument('run_dir',type=Path)
    args=parser.parse_args()
    if args.command=='plan':
        document=build_plan(args.run_id,read_document(args.sample_lock),read_document(args.analysis_policy));atomic_write_json(args.output,document)
        print(json.dumps({'planned_runs':len(document['entries']),'plan_sha256':document['plan_sha256']}))
    elif args.command=='collect':collect(read_document(args.plan),args.run_dir,args.base_url)
    else:
        report=replay(args.run_dir);print(json.dumps({'replay':'matched','planned_test_runs':report['planned_test_runs']}))


def collection_conformance(run_dir):
    """Structural collection completeness, separate from favorable detector results."""
    run_dir=Path(run_dir)
    plan=validate_plan(read_document(confined(run_dir,'plan.json')),online_gates=False)
    completed=[];failures=[]
    for entry in plan['entries']:
        path=confined(run_dir,'trials/'+entry['trial_id']+'.json')
        if not path.exists():failures.append(entry['trial_id']);continue
        trial=read_document(path)
        if (trial.get('status')!='completed' or trial.get('split')!=entry['split'] or
            trial.get('ground_truth_class')!=entry['ground_truth_class'] or not trial.get('research_eligible') or
            trial.get('collection_plan_sha256')!=plan['plan_sha256']):failures.append(entry['trial_id']);continue
        if not re.fullmatch(r'[a-f0-9]{64}',trial.get('container_id','')):raise ArtifactError('Exact collected container identity missing')
        if aware(trial['timeline']['setup_started_at_utc'])<aware(plan['created_at']):raise ArtifactError('Trial collection predates immutable plan')
        truth=trial.get('ground_truth',{})
        if truth.get('canary_sequences_planned')!=truth.get('canary_sequences_executed'):raise ArtifactError('Failed action cannot be a completed evaluation run')
        if not confined(run_dir,'snapshots/'+entry['trial_id']+'.json').is_file():failures.append(entry['trial_id']);continue
        completed.append(trial)
    cells={};replicas={}
    for row in completed:
        key=(row['workload_id'],row['mode'],row['split'])
        if row['ground_truth_class']=='benign' and row['split'] in ('fit','calibration'):
            cells[key]=cells.get(key,0)+1;replicas.setdefault(key,set()).add(row['container_id'])
    insufficient=[]
    manifest=conformance.load_protocol_manifest()
    for workload in manifest['workloads']:
        for version in workload['versions']:
            for mode in workload['modes']:
                for split in ('fit','calibration'):
                    key=(version,mode,split)
                    if cells.get(key,0)<plan['analysis_policy']['minimum_'+split+'_runs'] or len(replicas.get(key,set()))<3:
                        insufficient.append('|'.join(key))
    return {'valid':not failures and not insufficient,'planned':len(plan['entries']),'completed':len(completed),
        'failed_or_missing':failures,'insufficient_clean_strata':insufficient,'plan_sha256':plan['plan_sha256']}


if __name__=='__main__':main()
