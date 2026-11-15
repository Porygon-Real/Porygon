"""Disposable, owned-only syscall observations. Never runs public exploit code."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
from experiments.attacks.catalog import catalog, digest
from experiments.runtime_binding import resolve_runtime_binding, assert_binding_matches

LABEL = 'io.porygon.attack-control.run'
PEER = "import socket; s=socket.socket(); s.bind(('0.0.0.0',8080)); s.listen(8); [(lambda c: (c.recv(16),c.close()))(s.accept()[0]) for _ in range(8)]"
TARGET = "import time; time.sleep(300)"
# Payloads only use an installed binary and a private owned peer. No host mounts,
# public endpoints, arbitrary user commands, or externally supplied images.
WORK = r'''
import json, os, shutil, socket, subprocess, sys
case, peer = json.load(sys.stdin)
helper='/tmp/porygon-helper'
shutil.copyfile(sys.executable, helper); os.chmod(helper,0o700)
if case in ('writable-network','approved-network'):
    subprocess.run([helper,'-c',"import socket; s=socket.socket(); s.connect(('"+peer+"',8080)); s.send(b'control'); s.close()"],check=True,timeout=5)
elif case in ('memfd-exec','memfd-create'):
    fd=os.memfd_create('porygon-harmless',0)
    with open('/usr/bin/true','rb') as source: os.write(fd,source.read())
    if case=='memfd-exec': os.execve(fd,['porygon-harmless'],{})
    os.close(fd)
elif case in ('sensitive-write','sensitive-open','sensitive-zero','approved-write'):
    code="import os,json; written=None; fd=os.open('/etc/porygon-owned-fixture',os.O_WRONLY|os.O_CREAT,0o600); "
    if case in ('sensitive-write','approved-write'): code+="written=os.write(fd,b'x'); "
    if case=='sensitive-zero': code+="written=os.write(fd,b''); "
    completed=subprocess.run([helper,'-c',code+'os.close(fd); print(json.dumps({"write_return":written}))'],check=True,timeout=5,capture_output=True,text=True)
    print(json.dumps({'owned_operation':case, **json.loads(completed.stdout)}))
else: raise ValueError('Unknown owned case')
'''
QUERY = r'''
import json,sys
from datetime import datetime,timezone
from sqlalchemy import select
from porygon_api.db import SessionLocal
from porygon_api.models import ProcessExecEvent,KernelRuntimeEvent
from porygon_api.assessment_service import AssessmentScope
from porygon_api.runtime_evidence import query_events,query_context_events,build_bundle
request=json.load(sys.stdin)
scope=AssessmentScope(docker_host_id=request['host'],container_id=request['container'],context_hash='0'*64)
start=datetime.fromisoformat(request['start']); end=datetime.fromisoformat(request['end'])
with SessionLocal() as db:
    events=query_events(db,scope,start,end)
    context=query_context_events(db,scope,start,end,events)
    bundle=build_bundle(events,scope,start,end,request['known'],context=context)
print(json.dumps(bundle))
'''
DISABLED = "from porygon_api.config import get_settings; print('disabled' if get_settings().response_execution_mode=='disabled' else 'unsafe')"
CASES = {
    'writable-network': ['POR-EVD-WRITABLE-NET'], 'approved-network': [],
    'memfd-exec': ['POR-EVD-MEMFD-EXEC'], 'memfd-create': [],
    'sensitive-write': ['POR-EVD-SENSITIVE-WRITE'], 'sensitive-open': [],
    'sensitive-zero': [], 'approved-write': [],
}


def container_create_argv(image_id, network, run_id, code, *, observable):
    """Observable owned targets must not carry Falco's protected exclusion."""
    return ('run', '-d', '--pull=never', '--network', network,
            '--label', LABEL+'='+run_id,
            '--label', 'io.porygon.owned-disposable=true',
            '--label', 'com.porygon.protected='+('false' if observable else 'true'),
            '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
            '--pids-limit=32', '--memory=128m', '--cpus=0.5', '--user=0:0',
            '--entrypoint=python', image_id, '-c', code)


def run_docker(binding, *argv, data=None, timeout=30):
    result = subprocess.run(binding.docker_argv(*argv), input=data, text=True,
                            capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        # Docker stderr can contain environment or application data. Do not emit it.
        raise RuntimeError('Owned-target Docker operation failed')
    return result.stdout.strip()


def inspect_owned(binding, container_id, run_id):
    value = json.loads(run_docker(binding, 'inspect', container_id))[0]
    host = value.get('HostConfig') or {}
    labels = value.get('Config', {}).get('Labels') or {}
    if (labels.get(LABEL) != run_id or value.get('Mounts') or host.get('Privileged')
            or host.get('NetworkMode') != 'porygon-attack-control-'+run_id
            or 'ALL' not in (host.get('CapDrop') or [])
            or host.get('PidMode') == 'host' or host.get('IpcMode') == 'host'):
        raise RuntimeError('Disposable target ownership or isolation mismatch')
    return value


def run(args):
    if args.compose_project != 'porygon-service-trust':
        raise ValueError('This harness only targets the isolated service-trust stack')
    binding = resolve_runtime_binding(args.compose_project, args.docker_context, args.api_origin)
    backend = binding.services['backend']['container_id']
    image_id = binding.services['backend']['image_id']
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise ValueError('An inspected immutable cached image ID is required')
    if run_docker(binding,'exec',backend,'python','-c',DISABLED) != 'disabled':
        raise ValueError('Containment must remain disabled')
    run_id = uuid.uuid4().hex
    network = 'porygon-attack-control-'+run_id
    created = []
    network_created = False
    receipt = dict(contract='porygon.owned-attack-control', run_id=run_id,
                   catalog_sha256=digest(catalog()), binding=binding.to_dict(),
                   image_id=image_id, cases=[], capture_scope='owned disposable containers only',
                   async_completion='unsupported',
                   source_hashes={name: hashlib.sha256((Path(__file__).resolve().parents[2]/name).read_bytes()).hexdigest()
                                  for name in ('experiments/attacks/live.py', 'experiments/attacks/catalog.py',
                                               'backend/src/porygon_api/runtime_evidence.py', 'falco/porygon_rules.yaml')})
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Reserve a new private receipt before creating any disposable resource.
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)
    owned_inode = args.output.stat().st_ino

    def persist():
        nonlocal owned_inode
        if args.output.is_symlink() or args.output.stat().st_ino != owned_inode:
            raise RuntimeError('Receipt ownership changed; refusing overwrite')
        temporary = args.output.with_name('.'+args.output.name+'.'+uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, 'w') as stream:
                stream.write(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, args.output)
            owned_inode = args.output.stat().st_ino
        finally:
            temporary.unlink(missing_ok=True)

    def create(code, *, observable):
        cid = run_docker(binding, *container_create_argv(
            image_id, network, run_id, code, observable=observable))
        if not re.fullmatch(r'[0-9a-f]{64}',cid):
            raise RuntimeError('Unexpected owned container identity')
        created.append(cid)
        inspect_owned(binding,cid,run_id)
        return cid

    try:
        run_docker(binding,'network','create','--internal','--label',LABEL+'='+run_id,network)
        network_created = True
        peer = create(PEER, observable=False)
        peer_ip = inspect_owned(binding,peer,run_id)['NetworkSettings']['Networks'][network]['IPAddress']
        # Readiness is checked on the owned peer itself; the actual observation
        # uses blocking connect, bounded externally by subprocess/Docker deadlines.
        run_docker(binding,'exec',peer,'python','-c',
                   "import socket; s=socket.socket(); s.connect(('127.0.0.1',8080)); s.send(b'ready'); s.close()",timeout=5)
        for case, expected in CASES.items():
            assert_binding_matches(binding, resolve_runtime_binding(args.compose_project,args.docker_context,args.api_origin))
            if run_docker(binding,'exec',backend,'python','-c',DISABLED) != 'disabled':
                raise RuntimeError('Containment mode changed during observation')
            cid = create(TARGET, observable=True)
            start = datetime.now(timezone.utc).isoformat()
            operation_output = run_docker(binding,'exec','-i',cid,'python','-c',WORK,
                       data=json.dumps([case,peer_ip]),timeout=15)
            operation_ack = json.loads(operation_output) if case in ('sensitive-write','sensitive-open','sensitive-zero','approved-write') else None
            # One bounded drain interval; no broad log capture or indefinite polling.
            time.sleep(args.drain_seconds)
            end = datetime.now(timezone.utc).isoformat()
            known = ['/tmp/porygon-helper'] if case.startswith('approved-') else []
            bundle = json.loads(run_docker(binding,'exec','-i',backend,'python','-c',QUERY,
                data=json.dumps(dict(host=binding.daemon_id,container=cid,start=start,end=end,known=known)),timeout=30))
            actual = sorted({x['rule_id'] for x in bundle['findings']})
            events = bundle['events']
            execs = [x for x in events if x['channel']=='process' and x['exec_return_value']==0 and x['event_direction']=='<']
            kernels = [x for x in events if x['channel']=='kernel']
            relevant = bool(execs) and (bool(kernels) or case=='memfd-exec')
            identities = bundle['coverage']['unavailable_identity_events']==0
            if case in ('approved-network','approved-write'):
                identities = identities and any(x.get('executable')=='/tmp/porygon-helper' and x.get('exe_writable') is True for x in execs)
            if case.startswith('memfd'):
                relevant = relevant and (any(x.get('exe_from_memfd') is True for x in execs) if case=='memfd-exec'
                                         else any(x.get('runtime_action')=='memfd_create' for x in kernels))
            elif 'network' in case:
                relevant = relevant and any(x.get('runtime_action')=='net_outbound' and x.get('return_value',-1)>=0 for x in kernels)
            else:
                action = 'file_write_open' if case in ('sensitive-open','sensitive-zero') else 'file_write'
                relevant = relevant and any(x.get('runtime_action')==action and x.get('file_path')=='/etc/porygon-owned-fixture' for x in kernels)
            if case=='sensitive-zero':
                relevant = relevant and operation_ack == {'owned_operation':case, 'write_return':0}
            status = ('passed' if set(expected)<=set(actual) and (expected or not actual) else 'failed') if relevant and identities else 'unknown'
            receipt['cases'].append(dict(case_id=case,status=status,expected_rules=expected,actual_rules=actual,
                missingness=[] if relevant and identities else ['required successful syscall or exact process identity unavailable'],
                selected_event_ids=[x['event_id'] for x in events], context_event_ids=[x['event_id'] for x in bundle['context_events']],
                owned_operation_ack=operation_ack,
                zero_write_observation='controller return only; sensor emits positive writes only' if case=='sensitive-zero' else None,
                container_id=cid,window_start=start,window_end=end,bundle=bundle))
            persist()
    finally:
        cleanup_errors = []
        try:
            receipt['containment_disabled_at_cleanup'] = run_docker(binding,'exec',backend,'python','-c',DISABLED) == 'disabled'
            assert_binding_matches(binding, resolve_runtime_binding(args.compose_project,args.docker_context,args.api_origin))
            receipt['stack_healthy_at_exit'] = True
        except (RuntimeError, ValueError, subprocess.SubprocessError):
            receipt['stack_healthy_at_exit'] = False
            receipt['containment_disabled_at_cleanup'] = False
        for cid in reversed(created):
            try:
                inspect_owned(binding,cid,run_id)
                run_docker(binding,'rm','-f',cid)
            except (RuntimeError, ValueError, subprocess.SubprocessError):
                cleanup_errors.append({'container_id':cid, 'status':'owned cleanup failed; manual inspection required'})
        if network_created:
            try:
                info=json.loads(run_docker(binding,'network','inspect',network))[0]
                if info.get('Labels',{}).get(LABEL)!=run_id or not info.get('Internal'):
                    raise RuntimeError('Network ownership changed; refusing cleanup')
                run_docker(binding,'network','rm',network)
            except (RuntimeError, ValueError, subprocess.SubprocessError):
                cleanup_errors.append({'network':network, 'status':'owned cleanup failed; manual inspection required'})
        receipt['cleanup']='owned resources removed' if not cleanup_errors else 'incomplete'
        receipt['cleanup_errors']=cleanup_errors
        persist()
    return 0 if not receipt['cleanup_errors'] and receipt.get('stack_healthy_at_exit') and receipt.get('containment_disabled_at_cleanup') and len(receipt['cases'])==len(CASES) and all(x['status']=='passed' for x in receipt['cases']) else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose-project',required=True)
    parser.add_argument('--docker-context',required=True)
    parser.add_argument('--api-origin',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--drain-seconds',type=int,choices=range(1,16),default=5)
    return run(parser.parse_args())


if __name__=='__main__':
    raise SystemExit(main())
