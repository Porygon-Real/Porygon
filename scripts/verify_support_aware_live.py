#!/usr/bin/env python3
"""Score one exact owned-container window under the support-aware contract.

This verifier reads existing profiles and selected telemetry only. It creates no
profile, score, detection run, model promotion, or response action.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.runtime_binding import resolve_runtime_binding  # noqa: E402


QUERY = r'''
import json,sys
from datetime import datetime,timezone
from sqlalchemy import select
from porygon_api.db import SessionLocal
from porygon_api.models import BehaviorProfile,ProcessExecEvent,RuntimeEvent
from porygon_api.baseline import build_profile_document,SUPPORT_AWARE_SCHEMA
from porygon_api.scoring import get_scoring_config,score_feature_documents
from porygon_api.vulnerability import is_local_image_identity
request=json.load(sys.stdin)
start=datetime.fromisoformat(request['start']).astimezone(timezone.utc)
end=datetime.fromisoformat(request['end']).astimezone(timezone.utc)
with SessionLocal() as db:
    profile=db.get(BehaviorProfile,request['profile_id'])
    if profile is None or profile.image_digest!=request['image_digest']:
        raise SystemExit('Selected support-aware profile is unavailable for this image')
    provenance=profile.training_manifest.get('managed_provenance') or {}
    if profile.feature_schema_version!=SUPPORT_AWARE_SCHEMA or provenance.get('docker_host_id')!=request['host'] or provenance.get('container_id')!=request['container']:
        raise SystemExit('Support-aware baseline must be managed for this exact host/container')
    intervals=provenance.get('intervals') or []
    if not intervals or any(item.get('label')!='benign' for item in intervals):
        raise SystemExit('Support-aware baseline must contain explicitly labeled benign intervals')
    if not profile.quality.get('passed') or profile.process_event_count<20 or profile.training_manifest.get('nonempty_window_count',0)<3:
        raise SystemExit('Support-aware baseline lacks minimum benign sample support')
    if start<profile.training_end and end>profile.training_start:
        raise SystemExit('Observation overlaps baseline training time')
    process=list(db.scalars(select(ProcessExecEvent).where(
        ProcessExecEvent.docker_host_id==request['host'],ProcessExecEvent.container_id==request['container'],
        (ProcessExecEvent.image_id==request['image_digest'].removeprefix('local:') if is_local_image_identity(request['image_digest']) else ProcessExecEvent.image_digest==request['image_digest']),ProcessExecEvent.correlation_status=='resolved',
        ProcessExecEvent.occurred_at>=start,ProcessExecEvent.occurred_at<end
    ).order_by(ProcessExecEvent.occurred_at,ProcessExecEvent.event_id).limit(10001)).all())
    runtime=list(db.scalars(select(RuntimeEvent).where(
        RuntimeEvent.docker_host_id==request['host'],RuntimeEvent.container_id==request['container'],
        (RuntimeEvent.image_id==request['image_digest'].removeprefix('local:') if is_local_image_identity(request['image_digest']) else RuntimeEvent.image_digest==request['image_digest']),RuntimeEvent.occurred_at>=start,RuntimeEvent.occurred_at<end
    ).order_by(RuntimeEvent.occurred_at,RuntimeEvent.event_id).limit(10001)).all())
    if len(process)+len(runtime)>10000:
        raise SystemExit('Selected observation exceeds the 10000-event verifier bound')
    features,quality,manifest,_=build_profile_document(
        image_digest=request['image_digest'],start_at=start,end_at=end,
        window_seconds=profile.window_seconds,process_events=process,runtime_events=runtime,
        minimum_process_events=0,minimum_nonempty_windows=0,
        feature_schema_version=SUPPORT_AWARE_SCHEMA,include_temporal_windows=True)
    config=get_scoring_config(SUPPORT_AWARE_SCHEMA)
    score,band,components,explanation=score_feature_documents(
        baseline_features=profile.features,observation_features=features,
        algorithm_version=config['algorithm_version'])
    output={'contract':'porygon.live-support-aware-verification','scope':{
        'docker_host_id':request['host'],'container_id':request['container'],
        'image_digest':request['image_digest'],'window_start':start.isoformat(),'window_end':end.isoformat()},
        'profile_id':profile.profile_id,'profile_schema':profile.feature_schema_version,
        'profile_model_hash':profile.model_hash,
        'baseline_support':{'process_event_count':profile.process_event_count,
            'nonempty_window_count':profile.training_manifest.get('nonempty_window_count'),
            'quality':profile.quality,'feature_support':profile.features.get('feature_support')},
        'selected_event_ids':{'process':[e.event_id for e in process],'runtime':[e.event_id for e in runtime]},
        'observation':{'quality':quality,'feature_support':features.get('feature_support'),
            'coverage':features.get('observation_coverage'),'temporal_windows':features.get('temporal_windows'),
            'feature_document_sha256':manifest.get('feature_document_sha256'),'manifest':manifest},
        'support_aware_score':{'config':config,'score':score,'band':band,
            'components':components,'explanation':explanation},
        'model_promotion':'not_requested','containment':'disabled'}
    legacy_id=request.get('legacy_profile_id')
    if legacy_id:
        legacy=db.get(BehaviorProfile,legacy_id)
        if legacy is None or legacy.image_digest!=request['image_digest'] or legacy.feature_schema_version not in ('porygon.behaviour.v1','porygon.behaviour.command-lineage') or not legacy.quality.get('passed'):
            raise SystemExit('Explicit legacy comparison profile is unavailable or incompatible')
        legacy_config=get_scoring_config(legacy.feature_schema_version)
        legacy_features,_,_,_=build_profile_document(
            image_digest=request['image_digest'],start_at=start,end_at=end,
            window_seconds=legacy.window_seconds,process_events=process,runtime_events=runtime,
            minimum_process_events=0,minimum_nonempty_windows=0,
            feature_schema_version=legacy.feature_schema_version)
        legacy_score,legacy_band,legacy_components,legacy_explanation=score_feature_documents(
            baseline_features=legacy.features,observation_features=legacy_features,
            algorithm_version=legacy_config['algorithm_version'])
        output['explicit_legacy_comparison']={'profile_id':legacy.profile_id,
            'feature_schema':legacy.feature_schema_version,'algorithm':legacy_config['algorithm_version'],
            'score':legacy_score,'band':legacy_band,'components':legacy_components,
            'explanation':legacy_explanation}
print(json.dumps(output,sort_keys=True,default=str))
'''


def _run(binding, *argv: str, data: str | None = None) -> str:
    result = subprocess.run(binding.docker_argv(*argv), input=data, text=True,
                            capture_output=True, timeout=45, check=False)
    if result.returncode:
        raise RuntimeError("Owned backend verification query failed")
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose-project', required=True)
    parser.add_argument('--docker-context', required=True)
    parser.add_argument('--api-origin', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--container', required=True)
    parser.add_argument('--image-digest', required=True)
    parser.add_argument('--profile-id', required=True, help='Managed support-aware benign baseline for this exact target')
    parser.add_argument('--legacy-profile-id', help='Optional explicit historical profile comparison')
    parser.add_argument('--start', required=True, help='ISO-8601 observed window start with timezone')
    parser.add_argument('--end', required=True, help='ISO-8601 observed window end with timezone')
    args = parser.parse_args()
    if args.compose_project != 'porygon-service-trust':
        parser.error('only the isolated service-trust project is permitted')
    if not re.fullmatch(r'[a-f0-9]{64}', args.container):
        parser.error('container must be an exact 64-character ID')
    if not args.host or len(args.host) > 128:
        parser.error('host identity is required')
    try:
        start, end = datetime.fromisoformat(args.start), datetime.fromisoformat(args.end)
    except ValueError:
        parser.error('start/end must be ISO-8601 timestamps')
    if start.tzinfo is None or end.tzinfo is None or end <= start:
        parser.error('start/end require timezone offsets and a positive interval')
    if (end - start).total_seconds() > 3600:
        parser.error('verification windows are limited to one hour')
    binding = resolve_runtime_binding(args.compose_project, args.docker_context, args.api_origin)
    if args.host != binding.daemon_id:
        parser.error('host identity must match the inspected isolated Docker daemon')
    inspection = json.loads(_run(binding, 'inspect', args.container))[0]
    labels = (inspection.get('Config') or {}).get('Labels') or {}
    mounts = inspection.get('Mounts') or []
    run_id = labels.get('io.porygon.attack-control.run')
    networks = inspection.get('NetworkSettings', {}).get('Networks') or {}
    network_name = 'porygon-attack-control-' + str(run_id)
    if (not run_id or network_name not in networks or mounts
            or inspection.get('State', {}).get('Status') != 'running'
            or inspection.get('HostConfig', {}).get('Privileged')
            or 'ALL' not in (inspection.get('HostConfig', {}).get('CapDrop') or [])):
        parser.error('container must be a running, owned disposable target without mounts')
    network = json.loads(_run(binding, 'network', 'inspect', network_name))[0]
    if not network.get('Internal') or (network.get('Labels') or {}).get(
        'io.porygon.attack-control.run'
    ) != run_id:
        parser.error('target must use its owned internal attack-control network')
    payload = {key: getattr(args, key) for key in (
        'host', 'container', 'image_digest', 'profile_id', 'start', 'end')}
    payload['legacy_profile_id'] = args.legacy_profile_id
    result = _run(binding, 'exec', '-i', binding.services['backend']['container_id'],
                  'python', '-c', QUERY, data=json.dumps(payload))
    print(result)
    return 0


if __name__ == '__main__':
    sys.exit(main())
