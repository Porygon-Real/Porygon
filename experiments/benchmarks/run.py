"""Collect a bounded workload trace or validate independently measured node samples.

The driver executes only in a pre-created disposable, labeled, digest-pinned
container. It does not stop shared services or manufacture kernel denominators.
Failure experiments are supplied as measured trace files from an isolated lab.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import re
import subprocess
import time
from experiments.artifacts import atomic_write_json

SCENARIOS=('exec','network','memfd','file-write','control-plane-outage','adapter-outage',
    'disk-backpressure','database-restart','slow-notification','sustained','burst','soak')
BOUNDARIES=('controller_operations','falco_selected','adapter_accepted','backend_persisted','assessment_completed')


def finite(value):return type(value) in (int,float) and math.isfinite(value) and value>=0


def validate_samples(document):
    if document.get('contract')!='porygon.capacity-measurement':raise ValueError('Unknown measurement contract')
    hardware=document.get('hardware',{})
    for key in ('cpu','logical_cpus','memory_bytes','kernel','disk','docker','falco_rules_sha256'):
        if not hardware.get(key):raise ValueError('Declared hardware/configuration required')
    if not re.fullmatch(r'[a-f0-9]{64}',hardware['falco_rules_sha256']):raise ValueError('Rules digest required')
    samples=document.get('samples')
    if not isinstance(samples,list) or not samples:raise ValueError('Measured samples required')
    seen=set()
    for sample in samples:
        identifier=(sample.get('host_id'),sample.get('counter_epoch'),sample.get('sequence'))
        if any(value is None for value in identifier) or identifier in seen:raise ValueError('Unique independent host/epoch/sequence required')
        seen.add(identifier)
        counters=sample.get('boundaries',{})
        if set(counters)!=set(BOUNDARIES):raise ValueError('Every observed boundary must be known or explicitly unknown')
        for boundary,value in counters.items():
            if value is not None and not finite(value):raise ValueError('Invalid measured boundary')
        if sample.get('source_kind') not in ('independent-measured','synthetic-fixture'):raise ValueError('Measurement source required')
        for metric in ('sensor_cpu_seconds','sensor_rss_bytes','spool_bytes','oldest_age_seconds','dead_letters','rejected_records'):
            if sample.get(metric) is not None and not finite(sample[metric]):raise ValueError('Invalid resource metric')
        if not isinstance(sample.get('failure_accounting'),list):raise ValueError('Failures must remain explicit')
    return document


def summarize(document):
    validate_samples(document)
    samples=document['samples'];real=all(row['source_kind']=='independent-measured' for row in samples)
    nodes={row['host_id'] for row in samples}
    losses=[]
    for row in samples:
        values=row['boundaries']
        # Only compare matching boundary units. Controller operations are not syscalls.
        if values['falco_selected'] is not None and values['backend_persisted'] is not None:
            losses.append(values['falco_selected']-values['backend_persisted'])
    return {'contract':'porygon.capacity-report','source_sha256':hashlib.sha256(json.dumps(document,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'nodes':len(nodes),'source_kind':'independent-measured' if real else 'synthetic-fixture',
        'selected_to_persisted_deltas':losses,'kernel_completeness':'unknown',
        'targets':{'three_node_envelope':'unknown','p95_assessment_latency':'unknown','outage_recovery':'unknown','seven_day_soak':'unknown'},
        'failure_count':sum(len(row['failure_accounting']) for row in samples)}


def driver(container,scenario,rate,duration,seed,*,context=None,peer=None):
    if scenario not in ('exec','memfd','file-write','network'):raise ValueError('This local driver supports exec/memfd/file-write; other scenarios need independently recorded lab traces')
    if not re.fullmatch(r'[a-f0-9]{64}',container):raise ValueError('Exact full disposable container ID required')
    prefix=['docker']+(['--context',context] if context else [])
    info=json.loads(subprocess.run([*prefix,'inspect',container],capture_output=True,check=True).stdout)[0]
    if info['Id']!=container or info['Config'].get('Labels',{}).get('com.porygon.benchmark')!='disposable':raise ValueError('Container is not an explicitly disposable benchmark target')
    if info.get('HostConfig',{}).get('Privileged') or any(mount.get('Type')=='bind' for mount in info.get('Mounts',[])):
        raise ValueError('Benchmark target cannot be privileged or bind-mounted')
    if not info.get('Image','').startswith('sha256:'):raise ValueError('Immutable container image required')
    program='''import json,os,subprocess,time
scenario,rate,duration,seed,peer=json.loads(__import__('sys').argv[1]);start=time.monotonic();start_ns=time.time_ns();attempted=completed=0;failures=[]
while time.monotonic()-start<duration:
    attempted+=1
    try:
        if scenario=='exec':subprocess.run(['/bin/true'],check=True,timeout=1)
        elif scenario=='memfd':
            fd=os.memfd_create('porygon-benchmark',0);os.write(fd,b'harmless measurement');os.close(fd)
        elif scenario=='network':
            import socket
            with socket.create_connection((peer['address'],peer['port']),timeout=1):pass
        else:
            with open('/etc/porygon-benchmark-write','wb') as handle:handle.write(b'harmless measurement')
        completed+=1
    except Exception as error:
        if len(failures)<100:failures.append(type(error).__name__)
    delay=start+attempted/rate-time.monotonic()
    if delay>0:time.sleep(delay)
print(json.dumps({'attempted_operations':attempted,'completed_operations':completed,'elapsed_seconds':time.monotonic()-start,'started_ns':start_ns,'finished_ns':time.time_ns(),'failures':failures}))
'''
    result=subprocess.run([*prefix,'exec',container,'python','-c',program,json.dumps([scenario,rate,duration,seed,peer])],capture_output=True,check=True,timeout=duration+30)
    return {'contract':'porygon.benchmark-controller','scenario':scenario,'seed':seed,'requested_rate':rate,'requested_duration_seconds':duration,
        'host':platform.node(),'container_id':container,'image_id':info['Image'],'started_at':datetime.now(timezone.utc).isoformat(),
        'controller':json.loads(result.stdout),'source_loss':'unknown','operation_units':'controller actions, not kernel syscall count'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario',choices=SCENARIOS,required=True);parser.add_argument('--seed',type=int,default=1729)
    parser.add_argument('--rate',type=float,default=100);parser.add_argument('--duration',type=float,default=60)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--measurements',type=Path);parser.add_argument('--container-id')
    args=parser.parse_args()
    if not finite(args.rate) or not 0<args.rate<=100000 or not finite(args.duration) or not 0<args.duration<=604800:
        parser.error('Positive bounded rate and duration required')
    if args.measurements:
        if args.measurements.stat().st_size>64*1024*1024:raise ValueError('Trace exceeds bounded size')
        report=summarize(json.loads(args.measurements.read_text()))
    elif args.container_id:report=driver(args.container_id,args.scenario,args.rate,args.duration,args.seed)
    else:parser.error('Provide a measured trace or an exact disposable container ID')
    atomic_write_json(args.output,report)
    print(json.dumps({'output':str(args.output),'contract':report['contract']}))


if __name__=='__main__':main()
