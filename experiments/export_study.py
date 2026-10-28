"""Prepare a local rights-reviewed CC BY 4.0 event dataset; never upload it."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from experiments.confirmatory import replay,read_document,confined
from experiments.artifacts import ArtifactError,atomic_write_json,sha256_file
from experiments.frozen_analysis import evaluate_trials
from experiments.frozen_statistics import summarize


def validate_rights(rights):
    if rights.get('dataset_license')!='CC-BY-4.0' or rights.get('dataset_rights')!='owned-or-permission-recorded' or not rights.get('approved_by') or not rights.get('approval_reference'):
        raise ArtifactError('Recorded permission and CC BY 4.0 dataset approval required')
    inventory=rights.get('third_party')
    if not isinstance(inventory,list) or not inventory:raise ArtifactError('Third-party software/image license inventory required')
    for item in inventory:
        if not item.get('name') or not item.get('license') or not item.get('source') or type(item.get('redistributed')) is not bool:
            raise ArtifactError('Complete third-party rights coordinates required')
        if item['redistributed'] and not item.get('redistribution_permission_reference'):
            raise ArtifactError('Third-party redistribution needs its own rights record')
    return rights


def export(run_dir,output,rights):
    validate_rights(rights);original=replay(run_dir)
    run_dir=Path(run_dir);output=Path(output)
    if output.exists():raise ArtifactError('Use a fresh public export directory')
    plan=read_document(confined(run_dir,'plan.json'));trials=[];snapshots={}
    pseudonym=lambda kind,value:hashlib.sha256((kind+':'+str(value)).encode()).hexdigest()
    from porygon_api.vulnerability import sha256_document
    allowed=('trial_id','status','ground_truth_class','image','human_tag','mode','scenario_id','runtime_context_hash','stratum','split','timeline','docker_host_id','container_id','ground_truth')
    for entry in plan['entries']:
        path=confined(run_dir,'trials/'+entry['trial_id']+'.json')
        if not path.exists():trials.append(dict(entry,status='failed'));continue
        raw=read_document(path);trial={key:deepcopy(raw[key]) for key in allowed if key in raw}
        if 'ground_truth' in trial:
            trial['ground_truth']={key:raw['ground_truth'][key] for key in ('expected_outcome','action_started_at_utc','action_finished_at_utc','action_started_monotonic_ns','action_finished_monotonic_ns','command_template_sha256') if key in raw['ground_truth']}
        # Only protocol-pinned image identity is exported; no arbitrary container inspect data.
        trial['image']={key:raw['image'][key] for key in ('reference','human_tag') if key in raw['image']}
        if 'docker_host_id' in trial:trial['docker_host_id']=pseudonym('host',trial['docker_host_id'])
        if 'container_id' in trial:trial['container_id']=pseudonym('container',trial['container_id'])
        trials.append(trial)
        snapshot_path=confined(run_dir,'snapshots/'+entry['trial_id']+'.json')
        if not snapshot_path.exists():continue
        snapshot=deepcopy(read_document(snapshot_path));snapshot.pop('sha256',None)
        snapshot['scope']['docker_host_id']=trial['docker_host_id'];snapshot['scope']['container_id']=trial['container_id']
        for rows in snapshot['events'].values():
            for row in rows:
                row['docker_host_id']=trial['docker_host_id'];row['container_id']=trial['container_id']
        snapshot['sha256']=sha256_document(snapshot);snapshots[entry['trial_id']]=snapshot
    assignments={row['trial_id']:row['split'] for row in plan['entries']}
    transformed=evaluate_trials(trials,snapshots,assignments,plan['analysis_policy']);transformed['result_tables']=summarize(transformed)
    if transformed['result_tables']!=original['result_tables']:raise ArtifactError('De-identification changed declared result semantics')
    document={'contract':'porygon.public-study-dataset','dataset_license':'CC-BY-4.0','analysis_policy':plan['analysis_policy'],
        'assignments':assignments,'trials':trials,'snapshots':snapshots,'result_tables':transformed['result_tables'],
        'source_plan_sha256':plan['plan_sha256'],'rights':rights,
        'transformations':['exact frozen-field whitelist at capture','no raw argv or container inspect payload','deterministic host/container pseudonyms','event IDs/order and relative timing preserved'],
        'software_and_images':'not redistributed by this dataset; retain their own license terms'}
    output.mkdir(mode=0o700,parents=True)
    atomic_write_json(output/'dataset.json',document)
    atomic_write_json(output/'export-manifest.json',{'contract':'porygon.public-export-manifest','files':{'dataset.json':sha256_file(output/'dataset.json')},'source_analysis_sha256':sha256_file(run_dir/'analysis.json')})
    return {'prepared':True,'published':False,'dataset_sha256':sha256_file(output/'dataset.json')}


def replay_public(output):
    output=Path(output);manifest=read_document(confined(output,'export-manifest.json'))
    if manifest.get('contract')!='porygon.public-export-manifest' or set(manifest['files'])!={'dataset.json'}:raise ArtifactError('Invalid public export inventory')
    if sha256_file(confined(output,'dataset.json'))!=manifest['files']['dataset.json']:raise ArtifactError('Public dataset hash mismatch')
    value=read_document(output/'dataset.json');validate_rights(value['rights'])
    report=evaluate_trials(value['trials'],value['snapshots'],value['assignments'],value['analysis_policy'])
    if summarize(report)!=value['result_tables']:raise ArtifactError('Public offline replay changed result tables')
    return {'replay':'matched','published':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    prepare=sub.add_parser('prepare');prepare.add_argument('--run-dir',type=Path,required=True);prepare.add_argument('--output',type=Path,required=True);prepare.add_argument('--rights',type=Path,required=True)
    replaying=sub.add_parser('replay');replaying.add_argument('output',type=Path)
    args=parser.parse_args()
    result=export(args.run_dir,args.output,read_document(args.rights)) if args.command=='prepare' else replay_public(args.output)
    print(json.dumps(result))


if __name__=='__main__':main()
