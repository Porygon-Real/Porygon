"""Bounded lab collector and isolated failure drivers for explicit Docker contexts.

Never selects services by broad names: every target is an exact container ID
whose Compose project is an explicitly disposable lab. Captured output contains
counts/resource coordinates only, never commands, environment values or payloads.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import re
import subprocess
import time
from experiments.artifacts import atomic_write_json

BACKEND_QUERY=r'''
import json,sys
from datetime import datetime,timezone
from sqlalchemy import select,func
from porygon_api.db import SessionLocal
from porygon_api.models import ProcessExecEvent,KernelRuntimeEvent,AssessmentJob,AssessmentTarget,SensorHealthSample
host,cid,start,end=json.loads(sys.argv[1]);counts={};latencies=[]
with SessionLocal() as db:
 for name,model in [('process',ProcessExecEvent),('kernel',KernelRuntimeEvent)]:
  counts[name]=db.scalar(select(func.count()).select_from(model).where(model.docker_host_id==host,model.container_id==cid,model.time_nano>=start,model.time_nano<end)) or 0
 jobs=list(db.scalars(select(AssessmentJob).join(AssessmentTarget,AssessmentJob.target_id==AssessmentTarget.target_id).where(AssessmentTarget.docker_host_id==host,AssessmentTarget.container_id==cid).order_by(AssessmentJob.created_at).limit(5001)))
 for row in jobs[:5000]:
  if row.completed_at:
   a=row.completed_at.replace(tzinfo=timezone.utc) if row.completed_at.tzinfo is None else row.completed_at
   b=row.window_end.replace(tzinfo=timezone.utc) if row.window_end.tzinfo is None else row.window_end
   latencies.append(max(0,(a-b).total_seconds()))
 health=db.scalar(select(SensorHealthSample).where(SensorHealthSample.docker_host_id==host,SensorHealthSample.service_name=='telemetry').order_by(SensorHealthSample.observed_at.desc()).limit(1))
 result={'persisted':counts['process']+counts['kernel'],'by_channel':counts,'assessment_completed':sum(row.state=='completed' for row in jobs[:5000]),'assessment_latency_seconds':latencies,'assessment_latency_complete':len(jobs)<=5000,
  'health':{'epoch':health.counter_epoch,'source_epoch':health.metrics.get('source_epoch'),'metrics':health.metrics['metrics'],'observed_at':health.observed_at.isoformat()} if health else None}
print(json.dumps(result))
'''
RESOURCE_QUERY=r'''
import json,os,platform
values={}
for line in open('/proc/1/status'):
 key,_,value=line.partition(':')
 if key in ('VmRSS','VmHWM'):values[key]=int(value.split()[0])*1024
raw=open('/proc/1/stat').read();rest=raw[raw.rfind(')')+2:].split();ticks=os.sysconf('SC_CLK_TCK')
print(json.dumps({'main_cpu_seconds':(int(rest[11])+int(rest[12]))/ticks,'main_rss_bytes':values.get('VmRSS'),'main_peak_rss_bytes':values.get('VmHWM'),'kernel':platform.release(),'clock':'procfs-main-process','observer_cost':'docker-exec sampling, excluded from PID1 CPU; may affect workload'}))
'''
SPOOL_QUERY=r'''
import json,os,sqlite3,time,urllib.request
from porygon_telemetry.config import get_settings
settings=get_settings();path=settings.spool_path
with sqlite3.connect('file:'+path+'?mode=ro',uri=True) as db:
 row=db.execute('SELECT COUNT(*),COALESCE(SUM(length(CAST(payload AS BLOB))),0),MIN(enqueued_at) FROM outbox').fetchone()
 dead=db.execute('SELECT COUNT(*) FROM dead_letters').fetchone()[0]
with urllib.request.urlopen('http://127.0.0.1:8002/status',timeout=3) as response:state=json.load(response)
print(json.dumps({'queue_depth':row[0],'queue_bytes':row[1],'oldest_age_seconds':max(0,time.time()-row[2]) if row[2] else 0,'dead_letters':dead,
 'adapter_accepted':state['events_enqueued'],'adapter_delivered':state['events_delivered'],'counter_epoch':str(state.get('source_inode'))+':'+str(state.get('source_offset')),'backpressure_events':state['spool_overflow_count']}))
'''
SOURCE_CAPTURE=r'''
import json,os,sys,time
from pathlib import Path
from porygon_telemetry.config import get_settings
from porygon_telemetry.normalizer import normalize_falco_event
cid,duration=json.loads(sys.argv[1]);settings=get_settings();path=Path(settings.falco_log_path);deadline=time.monotonic()+duration
positions={};seen=set();count=0;errors=0;resets=0;initial=True
while time.monotonic()<deadline:
 for source in (path,Path(str(path)+'.draining')):
  try:
   info=source.stat();key=(info.st_dev,info.st_ino);previous=positions.get(key,info.st_size if initial else 0)
   if info.st_size<previous:resets+=1;previous=0
   with source.open('rb') as handle:
    handle.seek(previous)
    for _ in range(10000):
     line=handle.readline(settings.falco_max_line_bytes+1)
     if not line or not line.endswith(b'\n'):break
     positions[key]=handle.tell()
     if len(line)>settings.falco_max_line_bytes:errors+=1;continue
     try:
      raw=json.loads(line);fields=raw.get('output_fields',{});reported=fields.get('container.id')
      if not isinstance(reported,str) or len(reported)<12 or not cid.startswith(reported):continue
      row=normalize_falco_event(raw,sensor_instance_id=settings.telemetry_instance_id,expected_rule=settings.falco_expected_rule,reported_docker_host_id=settings.reported_docker_host_id)
      if row and row['event_id'] not in seen:
       if len(seen)>=2000000:raise RuntimeError('Capture unique-event bound exceeded')
       seen.add(row['event_id']);count+=1
     except (ValueError,TypeError,KeyError):errors+=1
  except FileNotFoundError:pass
 initial=False;time.sleep(.1)
print(json.dumps({'selected_source_records':count,'parse_errors':errors,'counter_resets':resets,'source_boundary':'Falco files observed during collector lifetime, reported container prefix','completeness':'unknown','unique_bound':2000000}))
'''


def docker(node,*args,timeout=30,input=None):
    prefix=['docker']
    if node.get('context'):prefix+=['--context',node['context']]
    return subprocess.run([*prefix,*args],check=True,capture_output=True,text=True,timeout=timeout,input=input).stdout


def inspect_owned(node,identifier,*,workload=False):
    if not re.fullmatch(r'[a-f0-9]{64}',identifier):raise ValueError('Exact full container ID required')
    info=json.loads(docker(node,'inspect',identifier))[0]
    labels=info.get('Config',{}).get('Labels',{}) or {};project=labels.get('com.docker.compose.project','')
    if not project.startswith(('porygon-benchmark-','porygon-lab-')):raise ValueError('Failure drivers require an explicitly disposable lab project')
    if workload and labels.get('com.porygon.benchmark')!='disposable':raise ValueError('Workload target requires disposable benchmark label')
    return info


def validate_spec(spec):
    if spec.get('contract')!='porygon.benchmark-lab' or not 1<=len(spec.get('nodes',[]))<=16:raise ValueError('Bounded declared node matrix required')
    hosts=set()
    for node in spec['nodes']:
        if node['host_id'] in hosts:raise ValueError('Independent assigned host IDs required')
        hosts.add(node['host_id'])
        if node.get('context') and not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',node['context']):raise ValueError('Invalid configured Docker context')
        for key in ('target','telemetry','falco','backend'):
            inspect_owned(node,node[key],workload=key=='target')
        daemon=json.loads(docker(node,'info','--format','{{json .}}'))
        node['_daemon_id']=daemon['ID'];node['_docker_version']=daemon['ServerVersion']
    if len({row['_daemon_id'] for row in spec['nodes']})!=len(spec['nodes']):raise ValueError('Multiple contexts of one daemon are not independent nodes')
    return spec


def capture(node,start_ns,end_ns):
    result={'host_id':node['host_id'],'observed_at':datetime.now(timezone.utc).isoformat(),'failures':[]}
    for key,script in (('backend',BACKEND_QUERY),('telemetry',SPOOL_QUERY)):
        try:
            args=['exec',node[key],'python','-c',script]
            if key=='backend':args.append(json.dumps([node['host_id'],node['target'],start_ns,end_ns]))
            result[key]=json.loads(docker(node,*args))
        except (subprocess.SubprocessError,OSError,ValueError):result[key]=None;result['failures'].append(key+'_unavailable')
    result['resources']={}
    for service in ('telemetry','falco','backend'):
        try:
            # Falco image may not include Python: explicitly unknown, never fabricated.
            result['resources'][service]=json.loads(docker(node,'exec',node[service],'python','-c',RESOURCE_QUERY))
        except (subprocess.SubprocessError,OSError,ValueError):result['resources'][service]={'status':'unknown'}
    return result


def outage(node,scenario,seconds):
    key={'control-plane-outage':'backend','adapter-outage':'telemetry','database-restart':'postgres'}[scenario]
    identifier=node.get(key)
    if not identifier:raise ValueError('Exact owned failure target is not configured')
    inspect_owned(node,identifier)
    try:
        docker(node,'stop','--time','5',identifier,timeout=15)
        time.sleep(seconds)
    finally:docker(node,'start',identifier,timeout=30)
    return {'scenario':scenario,'outage_seconds':seconds,'target_kind':key,'restored':True}


def disk_pressure(node):
    image=json.loads(docker(node,'inspect',node['telemetry']))[0]['Image']
    program="""import json,sqlite3
from porygon_telemetry.spool import TelemetryStore,SpoolFullError
store=TelemetryStore('/pressure/spool.db',100000,max_bytes=16777216);accepted=0;failure=None
try:
 for index in range(10000):
  store.enqueue({'event_id':format(index,'064x'),'fixture':'x'*4096});accepted+=1
except (SpoolFullError,sqlite3.OperationalError) as error:failure=type(error).__name__
print(json.dumps({'accepted':accepted,'failure':failure,'boundary':'isolated tmpfs SQLite durability; no production spool touched'}))
"""
    name='porygon-benchmark-pressure-'+os.urandom(6).hex()
    try:
        raw=docker(node,'run','--rm','--name',name,'--label','com.porygon.benchmark=disposable','--network','none','--read-only',
            '--cap-drop','ALL','--security-opt','no-new-privileges','--tmpfs','/pressure:rw,size=4m,mode=1777',
            '--entrypoint','python',image,'-c',program,timeout=60)
        return json.loads(raw)
    finally:
        subprocess.run(['docker',*(['--context',node['context']] if node.get('context') else []),'rm','-f',name],capture_output=True,timeout=15)
