#!/usr/bin/env python3
"""Real isolated syscalls, outage recovery and replay isolation acceptance.

Creates only a disposable unprivileged-capability container. Writes occur inside
its own layer, never a host mount. Backend and telemetry are briefly stopped in
sequence, then restored even on failure. No evidence rows are deleted.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import time
from uuid import uuid4
import urllib.request

from private_api import open_backend

from porygon_scan import _load_env, request

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'artifacts/local/kernel-runtime-validation/acceptance.json'


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True, cwd=ROOT, stderr=subprocess.DEVNULL).strip()


def main():
    _load_env()
    base = 'http://127.0.0.1:' + os.getenv('BACKEND_PORT', '8000')
    target = None
    stopped = set()
    run_id = uuid4().hex
    def restore(service):
        docker('compose', 'up', '--detach', '--no-deps', '--wait', service)
        stopped.discard(service)
    try:
        target = docker('run', '--detach', '--name', 'porygon-kernel-' + run_id,
            '--user', '0', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--label', 'com.porygon.test=kernel-runtime', '--entrypoint', 'python',
            'porygon-backend', '-c', 'import time; time.sleep(900)')
        networks = json.loads(docker('inspect', target))[0]['NetworkSettings']['Networks']
        ip = next(network['IPAddress'] for network in networks.values() if network.get('IPAddress'))
        code = '''import os,socket,threading
listener=socket.socket(); listener.bind(('0.0.0.0',0)); listener.listen(4)
port=listener.getsockname()[1]
def accept():
    for _ in range(2):
        connection,_=listener.accept(); connection.close()
threading.Thread(target=accept,daemon=True).start()
for host in (ADDRESS,'127.0.0.1'):
    connection=socket.create_connection((host,port),timeout=5); connection.close()
fd=os.memfd_create(NAME); os.close(fd)
with open(PATH,'w') as stream: stream.write('porygon controlled kernel verification\\n')
listener.close()
'''
        def generate(label):
            name = 'porygon-' + run_id + '-' + label
            source = code.replace('ADDRESS', repr(ip)).replace('NAME', repr(name)).replace('PATH', repr('/etc/' + name))
            docker('exec', target, 'python', '-c', source)
            return name
        def await_events(name):
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                events = request('GET', base + '/api/v1/kernel-events?container_id=' + target + '&limit=1000')
                chosen = [event for event in events if name in (event.get('command_line') or '')]
                actions = {event['runtime_action'] for event in chosen}
                if actions == {'net_outbound','memfd_create','file_write_open','file_write'}:
                    assert all(event.get('remote_address') == ip for event in chosen if event['runtime_action'] == 'net_outbound')
                    assert any(event.get('memory_name') == name for event in chosen)
                    assert any(event.get('file_path') == '/etc/' + name and event['return_value'] > 0 for event in chosen if event['runtime_action'] == 'file_write')
                    return chosen
                time.sleep(2)
            raise AssertionError('Missing kernel syscall families for ' + name)
        results = {}
        first = generate('normal')
        results['normal'] = await_events(first)
        for service, label in [('telemetry','adapter-outage'), ('backend','backend-outage')]:
            docker('compose', 'stop', '--timeout', '20', service)
            stopped.add(service)
            name = generate(label)
            time.sleep(3)
            restore(service)
            results[label] = await_events(name)
        events = results['normal']
        accepted = {
            'event_id','sensor_instance_id','sensor_hostname','source','rule_name','priority',
            'occurred_at','time_nano','event_number','event_type','runtime_action','return_value',
            'reported_docker_host_id','reported_container_id','process_pid','process_name',
            'executable','command_line','user_uid','remote_address','remote_port','local_address',
            'local_port','file_path','memory_name','output_fields','raw_event'
        }
        replay_request = urllib.request.Request(base + '/internal/v1/kernel-events/batch',
            data=json.dumps({'events': [{key:value for key,value in event.items() if key in accepted} for event in events]}).encode(),
            headers={'Content-Type':'application/json', 'X-Porygon-Internal-Token':os.environ['PORYGON_INTERNAL_API_TOKEN']}, method='POST')
        with open_backend(replay_request) as response:
            replay = json.load(response)
        assert replay['inserted'] == 0 and replay['duplicates'] == len(events)
        legacy = request('GET', base + '/api/v1/process-events?container_id=' + target + '&limit=1000')
        legacy_events = legacy if isinstance(legacy,list) else legacy.get('events', [])
        assert all(event['event_type'] in ('execve','execveat') for event in legacy_events)
        worker = request('GET', base + '/api/v1/reconciliation/status')
        assert worker['running'] and not worker['last_error']
        result = dict(run_id=run_id, container_id=target,
            cases={label: {'events':len(rows),'actions':sorted({row['runtime_action'] for row in rows})} for label,rows in results.items()},
            replay_duplicates=replay['duplicates'], legacy_exec_events=len(legacy_events),
            loopback_excluded=True, reconciliation_healthy=True)
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
    finally:
        for service in tuple(stopped):
            restore(service)
        if target:
            docker('rm', '--force', target)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
