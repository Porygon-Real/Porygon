#!/usr/bin/env python3
"""List bounded process event IDs/timestamps for one inspected owned target."""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments.runtime_binding import resolve_runtime_binding  # noqa: E402


QUERY = r'''
import json,sys
from collections import Counter
from datetime import datetime,timezone
import math
from sqlalchemy import select
from porygon_api.db import SessionLocal
from porygon_api.models import ProcessExecEvent
from porygon_api.vulnerability import is_local_image_identity
q=json.load(sys.stdin)
start=datetime.fromisoformat(q['start']).astimezone(timezone.utc)
end=datetime.fromisoformat(q['end']).astimezone(timezone.utc)
with SessionLocal() as db:
 rows=db.scalars(select(ProcessExecEvent).where(
  ProcessExecEvent.docker_host_id==q['host'],ProcessExecEvent.container_id==q['container'],
  (ProcessExecEvent.image_id==q['image_digest'].removeprefix('local:') if is_local_image_identity(q['image_digest']) else ProcessExecEvent.image_digest==q['image_digest']),ProcessExecEvent.correlation_status=='resolved',
  ProcessExecEvent.occurred_at>=start,ProcessExecEvent.occurred_at<end
 ).order_by(ProcessExecEvent.occurred_at,ProcessExecEvent.event_id).limit(5001)).all()
 if len(rows)>5000: raise SystemExit('Selected event list exceeds the 5000-row bound')
 buckets=Counter(math.floor((e.occurred_at-start).total_seconds()/5) for e in rows)
 print(json.dumps({'selected_event_ids':[e.event_id for e in rows],
  'events':[{'event_id':e.event_id,'occurred_at':e.occurred_at.isoformat()} for e in rows],
  'five_second_bucket_counts':dict(sorted(buckets.items())),
  'nonempty_five_second_buckets':len(buckets)},sort_keys=True))
'''


def run(binding, *argv: str, data: str | None = None) -> str:
    result = subprocess.run(binding.docker_argv(*argv), input=data, text=True,
                            capture_output=True, timeout=45, check=False)
    if result.returncode:
        raise RuntimeError('Owned backend event query failed')
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose-project', required=True)
    parser.add_argument('--docker-context', required=True)
    parser.add_argument('--api-origin', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--container', required=True)
    parser.add_argument('--image-digest', required=True)
    parser.add_argument('--start', required=True)
    parser.add_argument('--end', required=True)
    args = parser.parse_args()
    if args.compose_project != 'porygon-service-trust':
        parser.error('only the isolated service-trust project is permitted')
    if not re.fullmatch(r'[a-f0-9]{64}', args.container):
        parser.error('container must be an exact 64-character ID')
    try:
        start, end = datetime.fromisoformat(args.start), datetime.fromisoformat(args.end)
    except ValueError:
        parser.error('start/end must be ISO-8601 timestamps')
    if start.tzinfo is None or end.tzinfo is None or end <= start:
        parser.error('start/end require timezone offsets and a positive interval')
    if (end - start).total_seconds() > 3600:
        parser.error('event inspection windows are limited to one hour')
    binding = resolve_runtime_binding(args.compose_project, args.docker_context, args.api_origin)
    if args.host != binding.daemon_id:
        parser.error('host identity must match the inspected isolated Docker daemon')
    inspect = json.loads(run(binding, 'inspect', args.container))[0]
    labels = (inspect.get('Config') or {}).get('Labels') or {}
    run_id = labels.get('io.porygon.attack-control.run')
    network_name = 'porygon-attack-control-' + str(run_id)
    if (not run_id or network_name not in (inspect.get('NetworkSettings', {}).get('Networks') or {})
            or inspect.get('Mounts') or inspect.get('State', {}).get('Status') != 'running'):
        parser.error('container must be a running owned disposable target without mounts')
    network = json.loads(run(binding, 'network', 'inspect', network_name))[0]
    if (not network.get('Internal') or (network.get('Labels') or {}).get(
        'io.porygon.attack-control.run'
    ) != run_id):
        parser.error('target must use its owned internal attack-control network')
    request = {key: getattr(args, key) for key in (
        'host', 'container', 'image_digest', 'start', 'end')}
    print(run(binding, 'exec', '-i', binding.services['backend']['container_id'],
              'python', '-c', QUERY, data=json.dumps(request)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
