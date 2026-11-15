"""Bounded lab collector and isolated failure drivers for explicit Docker contexts.

Never selects services by broad names: every target is an exact container ID
whose Compose project is an explicitly disposable lab. Captured output contains
counts/resource coordinates only, never commands, environment values or payloads.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import time
from experiments.artifacts import atomic_write_json

BACKEND_QUERY = r"""
import json,sys,hashlib,signal,time
signal.signal(signal.SIGALRM,lambda *args: (_ for _ in ()).throw(TimeoutError("Bounded database snapshot deadline")));signal.alarm(25)
from datetime import datetime,timezone,timedelta
from sqlalchemy import select,func,text
from porygon_api.db import SessionLocal
from porygon_api.models import ProcessExecEvent,KernelRuntimeEvent,AssessmentJob,AssessmentTarget,SensorHealthSample
host,cid,start,end,mode=json.loads(sys.argv[1])
if mode not in ('periodic','exact'):raise ValueError('Unknown bounded snapshot mode')
snapshot_started=time.perf_counter();identity_query_count=0;identity_ids_materialized=0;assessment_query_count=0;percentile_query_count=0;identity_seconds=0.0;assessment_seconds=0.0
counts={};selected_ids=[]
epoch=datetime(1970,1,1,tzinfo=timezone.utc);start_at=epoch+timedelta(microseconds=(start+999)//1000);end_at=epoch+timedelta(microseconds=end//1000)
with SessionLocal() as db:
 db.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'))
 db.execute(text("SET LOCAL statement_timeout='20000ms'"))
 for name,model in [('process',ProcessExecEvent),('kernel',KernelRuntimeEvent)]:
  filters=(model.docker_host_id==host,model.container_id==cid,model.time_nano>=start,model.time_nano<end)
  counts[name]=db.scalar(select(func.count()).select_from(model).where(*filters)) or 0
  if sum(counts.values())>2000000:raise ValueError('Persisted identity bound exceeded')
  if mode=='exact':
   query_started=time.perf_counter()
   identifiers=list(db.scalars(select(model.event_id).where(*filters).order_by(model.event_id)))
   identity_seconds+=time.perf_counter()-query_started;identity_query_count+=1;identity_ids_materialized+=len(identifiers);selected_ids.extend(identifiers)
 filters=(AssessmentTarget.docker_host_id==host,AssessmentTarget.container_id==cid,AssessmentJob.window_end>=start_at,AssessmentJob.window_end<=end_at)
 coverage_state=AssessmentJob.coverage['state'].as_string().label('coverage_state')
 joined=select(AssessmentJob.state,coverage_state,AssessmentJob.assessment_key,AssessmentJob.completed_at,AssessmentJob.window_end).join(AssessmentTarget,AssessmentJob.target_id==AssessmentTarget.target_id).where(*filters).subquery()
 query_started=time.perf_counter()
 if mode=='exact':
  total,unique=db.execute(select(func.count(),func.count(func.distinct(joined.c.assessment_key)))).one();assessment_query_count+=1
  state_counts=dict(db.execute(select(joined.c.state,func.count()).group_by(joined.c.state)).all());assessment_query_count+=1
  coverage_counts=dict(db.execute(select(joined.c.coverage_state,func.count()).group_by(joined.c.coverage_state)).all());assessment_query_count+=1
  successful=(joined.c.state=='completed',joined.c.coverage_state.in_(['available','degraded']),joined.c.completed_at.is_not(None))
  success=db.scalar(select(func.count()).select_from(joined).where(*successful)) or 0;assessment_query_count+=1
  lag=func.extract('epoch',joined.c.completed_at-joined.c.window_end)
  negative_lag=db.scalar(select(func.count()).select_from(joined).where(*successful,lag<0)) or 0;assessment_query_count+=1
  percentile_query_count=int(bool(success))
  p95=db.scalar(select(func.percentile_cont(0.95).within_group(lag)).select_from(joined).where(*successful)) if success else None
  assessment_query_count+=percentile_query_count
  duplicates=total-unique;latency_complete=total>0 and success==total and negative_lag==0
 else:
  total=db.scalar(select(func.count()).select_from(joined)) or 0;assessment_query_count+=1
  state_counts=dict(db.execute(select(joined.c.state,func.count()).group_by(joined.c.state)).all());assessment_query_count+=1
  coverage_counts=dict(db.execute(select(joined.c.coverage_state,func.count()).group_by(joined.c.coverage_state)).all());assessment_query_count+=1
  success=state_counts.get('completed',0);negative_lag=None;p95=None;duplicates=None;latency_complete=False
 assessment_seconds=time.perf_counter()-query_started
 health=db.scalar(select(SensorHealthSample).where(SensorHealthSample.docker_host_id==host,SensorHealthSample.service_name=='telemetry').order_by(SensorHealthSample.observed_at.desc()).limit(1))
 identity_hash=hashlib.sha256()
 for identifier in sorted(selected_ids):identity_hash.update(identifier.encode()+b'\n')
 result={'snapshot_mode':mode,'persisted_id_set_sha256':identity_hash.hexdigest() if mode=='exact' else None,'duplicate_logical_jobs':duplicates,'persisted':counts['process']+counts['kernel'],'by_channel':counts,
  'assessment_completed':success,'assessment_jobs':total,'assessment_state_counts':state_counts,'assessment_coverage_counts':coverage_counts,
  'assessment_pending':sum(value for key,value in state_counts.items() if key in ('pending','claimed')),'assessment_latency_p95_seconds':float(p95) if p95 is not None else None,
  'negative_assessment_lag_count':negative_lag,'assessment_latency_complete':latency_complete,'assessment_latency_method':'PostgreSQL exact percentile_cont over all successful selected jobs; no row truncation' if mode=='exact' else None,
  'observer_query_metrics':{'identity_query_count':identity_query_count,'identity_ids_materialized':identity_ids_materialized,'assessment_query_count':assessment_query_count,'percentile_query_count':percentile_query_count,'identity_query_elapsed_seconds':identity_seconds,'assessment_query_elapsed_seconds':assessment_seconds,'snapshot_query_elapsed_seconds':time.perf_counter()-snapshot_started},
  'health':{'epoch':health.counter_epoch,'source_epoch':health.metrics.get('source_epoch'),'metrics':health.metrics['metrics'],'observed_at':health.observed_at.isoformat()} if health else None}
print(json.dumps(result))
"""

RESOURCE_QUERY = r"""
import json,os,platform
values={}
for line in open('/proc/1/status'):
 key,_,value=line.partition(':')
 if key in ('VmRSS','VmHWM'):values[key]=int(value.split()[0])*1024
raw=open('/proc/1/stat').read();rest=raw[raw.rfind(')')+2:].split();ticks=os.sysconf('SC_CLK_TCK')
print(json.dumps({'main_cpu_seconds':(int(rest[11])+int(rest[12]))/ticks,'main_rss_bytes':values.get('VmRSS'),'main_peak_rss_bytes':values.get('VmHWM'),'kernel':platform.release(),'clock':'procfs-main-process','observer_cost':'docker-exec sampling, excluded from PID1 CPU; may affect workload'}))
"""
SPOOL_QUERY = r"""
import json,os,sqlite3,time,urllib.request,signal
signal.signal(signal.SIGALRM,lambda *args: (_ for _ in ()).throw(TimeoutError("Bounded spool snapshot deadline")));signal.alarm(25)
from porygon_telemetry.config import get_settings
settings=get_settings();path=settings.spool_path
raw=open('/proc/1/stat').read();process_start=raw[raw.rfind(')')+2:].split()[19]
boot=open('/proc/sys/kernel/random/boot_id').read().strip()
with sqlite3.connect('file:'+path+'?mode=ro',uri=True) as db:
 row=db.execute('SELECT COUNT(*),COALESCE(SUM(length(CAST(payload AS BLOB))),0),MIN(enqueued_at) FROM outbox').fetchone()
 dead=db.execute('SELECT COUNT(*) FROM dead_letters').fetchone()[0]
with urllib.request.urlopen('http://127.0.0.1:8002/status',timeout=3) as response:state=json.load(response)
print(json.dumps({'queue_depth':row[0],'queue_bytes':row[1],'oldest_age_seconds':max(0,time.time()-row[2]) if row[2] else 0,'dead_letters':dead,
 'adapter_accepted':state['events_enqueued'],'adapter_delivered':state['events_delivered'],'counter_epoch':boot+':'+process_start,'file_generation':state.get('source_inode'),'backpressure_events':state['spool_overflow_count']}))
"""
SOURCE_CAPTURE = r"""
import json,os,sys,time,hashlib,re
from array import array
from pathlib import Path
from types import SimpleNamespace
from porygon_telemetry.normalizer import normalize_falco_event
from porygon_telemetry.observer import SourceCursor
cid,duration,start_ns,canary_mode,expected_seed,configuration=json.loads(sys.argv[1]);settings=SimpleNamespace(**configuration);path=Path(settings.falco_log_path);deadline=time.monotonic()+duration
cursor=SourceCursor(settings.falco_max_line_bytes);seen=set();times=array('q');canaries={};count=0;errors=0;initial=True
while time.monotonic()<deadline:
 for source in (path,Path(str(path)+'.draining')):
  try:
   for line in cursor.read_lines(source,tail_if_new=initial):
    if len(line)>settings.falco_max_line_bytes:errors+=1;continue
    try:
     raw=json.loads(line);fields=raw.get('output_fields',{});reported=fields.get('container.id')
     if not isinstance(reported,str) or len(reported)<12 or not cid.startswith(reported):continue
     row=normalize_falco_event(raw,sensor_instance_id=settings.telemetry_instance_id,expected_rule=settings.falco_expected_rule,reported_docker_host_id=settings.reported_docker_host_id)
     if row and row['time_nano']>=start_ns and row['event_id'] not in seen:
      if len(seen)>=2000000:raise RuntimeError('Capture unique-event bound exceeded')
      seen.add(row['event_id']);times.append(row['time_nano']);count+=1
      if canary_mode:
       marker=re.fullmatch(r'(?:/bin/true|/usr/bin/true|true) porygon-benchmark-canary-'+str(expected_seed)+r'-([0-9]+)',(row.get('command_line') or '').strip())
       if marker and row.get('exec_return_value')==0 and row.get('event_direction')=='<':
        sequence=int(marker.group(1));canaries.setdefault(sequence,row['time_nano'])
    except (ValueError,TypeError,KeyError):errors+=1
  except FileNotFoundError:pass
 if initial:print(json.dumps({'state':'ready'}),flush=True)
 initial=False;time.sleep(.1)
identity_hash=hashlib.sha256()
for identifier in sorted(seen):identity_hash.update(identifier.encode()+b'\n')
print(json.dumps({'id_set_sha256':identity_hash.hexdigest(),'started_ns':start_ns,'canary_sequences':sorted(canaries),'canary_observations':[{'sequence':key,'at_ns':value} for key,value in sorted(canaries.items())],'event_timestamps_ns':list(times),'selected_source_records':count,'parse_errors':errors,'counter_resets':cursor.resets,'source_boundary':'Falco files observed during collector lifetime, reported container prefix','completeness':'unknown','unique_bound':2000000,'finished_ns':time.time_ns()}))
"""


def docker(node, *args, timeout=30, input=None):
    prefix = ["docker"]
    if node.get("context"):
        prefix += ["--context", node["context"]]
    return subprocess.run(
        [*prefix, *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input,
    ).stdout


def inspect_owned(node, identifier, *, workload=False):
    if not re.fullmatch(r"[a-f0-9]{64}", identifier):
        raise ValueError("Exact full container ID required")
    info = json.loads(docker(node, "inspect", identifier))[0]
    labels = info.get("Config", {}).get("Labels", {}) or {}
    project = labels.get("com.docker.compose.project", "")
    if not project.startswith(("porygon-benchmark-", "porygon-lab-")):
        raise ValueError("Failure drivers require an explicitly disposable lab project")
    if labels.get("com.porygon.benchmark-opt-in") != "true":
        raise ValueError("Target lacks explicit benchmark opt-in label")
    if workload and labels.get("com.porygon.benchmark") != "disposable":
        raise ValueError("Workload target requires disposable benchmark label")
    return info


def validate_spec(spec):
    if (
        spec.get("contract") != "porygon.benchmark-lab"
        or not 1 <= len(spec.get("nodes", [])) <= 16
    ):
        raise ValueError("Bounded declared node matrix required")
    control = spec.get("control_plane", {})
    if not control.get("backend"):
        raise ValueError("One shared control-plane backend is required")
    inspect_owned(control, control["backend"])
    if control.get("postgres"):
        inspect_owned(control, control["postgres"])
    if control.get("context") and not re.fullmatch(
        r"[A-Za-z0-9_.-]{1,128}", control["context"]
    ):
        raise ValueError("Invalid control-plane Docker context")
    hosts = set()
    for node in spec["nodes"]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", node["host_id"]):
            raise ValueError("Bounded host identity required")
        if node["host_id"] in hosts:
            raise ValueError("Independent assigned host IDs required")
        hosts.add(node["host_id"])
        if node.get("context") and not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,128}", node["context"]
        ):
            raise ValueError("Invalid configured Docker context")
        inspections = {
            key: inspect_owned(node, node[key], workload=key == "target")
            for key in ("target", "telemetry", "falco", "observer")
        }
        observer = inspections["observer"]
        sensor = inspections["telemetry"]
        if len({node[key] for key in inspections}) != len(inspections):
            raise ValueError(
                "Observer and fault/workload targets must be distinct containers"
            )
        if observer["Image"] != sensor["Image"] or not observer.get(
            "HostConfig", {}
        ).get("ReadonlyRootfs"):
            raise ValueError(
                "Independent observer requires the same telemetry image with a read-only root filesystem"
            )
        allowed = {
            "PORYGON_TELEMETRY_INSTANCE_ID",
            "PORYGON_FALCO_LOG_PATH",
            "PORYGON_FALCO_EXPECTED_RULE",
            "PORYGON_DOCKER_HOST_ID",
        }
        settings = {
            key: value
            for item in sensor.get("Config", {}).get("Env", [])
            if "=" in item
            for key, value in [item.split("=", 1)]
            if key in allowed
        }
        log_path = settings.get(
            "PORYGON_FALCO_LOG_PATH", "/var/log/porygon/falco-events.jsonl"
        )
        mounts = [
            mount
            for mount in sensor.get("Mounts", [])
            if mount.get("Type") == "volume"
            and Path(log_path).is_relative_to(mount["Destination"])
        ]
        if len(mounts) != 1:
            raise ValueError("Sensor log must have one declared shared volume")
        matching = [
            mount
            for mount in observer.get("Mounts", [])
            if mount.get("Type") == "volume"
            and mount.get("Name") == mounts[0].get("Name")
            and mount.get("Destination") == mounts[0].get("Destination")
            and mount.get("RW") is False
        ]
        if len(matching) != 1 or any(
            mount.get("RW") for mount in observer.get("Mounts", [])
        ):
            raise ValueError(
                "Independent observer mounts must be read-only, including the exact Falco log volume"
            )
        reported = settings.get("PORYGON_DOCKER_HOST_ID")
        node["_capture_settings"] = {
            "falco_log_path": log_path,
            "falco_max_line_bytes": 1048576,
            "telemetry_instance_id": settings.get(
                "PORYGON_TELEMETRY_INSTANCE_ID", "local-falco-adapter-01"
            ),
            "falco_expected_rule": settings.get(
                "PORYGON_FALCO_EXPECTED_RULE", "Porygon Container Process Execution"
            ),
            "reported_docker_host_id": None if reported in (None, "auto") else reported,
        }
        daemon = json.loads(docker(node, "info", "--format", "{{json .}}"))
        boot = docker(
            node,
            "exec",
            node["target"],
            "python",
            "-c",
            "print(open('/proc/sys/kernel/random/boot_id').read().strip())",
        ).strip()
        if not re.fullmatch(r"[a-f0-9-]{36}", boot):
            raise ValueError("Observed kernel boot identity required")
        node["_kernel_boot_id"] = boot
        node["_daemon_id"] = daemon["ID"]
        node["_docker_version"] = daemon["ServerVersion"]
        raw_rules = docker(
            node, "exec", node["falco"], "cat", "/etc/falco/porygon_rules.yaml"
        )
        import hashlib

        declaration = node.get("hardware_declaration", {})
        if any(
            not isinstance(declaration.get(key), str)
            or not 1 <= len(declaration[key]) <= 255
            for key in ("cpu_model", "disk_model_or_media", "filesystem")
        ):
            raise ValueError(
                "Declare CPU model, disk model/media and filesystem for each measured host"
            )
        node["_hardware"] = {
            "cpu_model": declaration["cpu_model"],
            "disk_model_or_media": declaration["disk_model_or_media"],
            "filesystem": declaration["filesystem"],
            "architecture": daemon.get("Architecture"),
            "logical_cpus": daemon.get("NCPU"),
            "memory_bytes": daemon.get("MemTotal"),
            "kernel": daemon.get("KernelVersion"),
            "storage_driver": daemon.get("Driver"),
            "docker": daemon["ServerVersion"],
            "falco_rules_sha256": hashlib.sha256(raw_rules.encode()).hexdigest(),
        }
    if len({row["_daemon_id"] for row in spec["nodes"]}) != len(spec["nodes"]) or len(
        {row["_kernel_boot_id"] for row in spec["nodes"]}
    ) != len(spec["nodes"]):
        raise ValueError(
            "Independent Linux kernels and Docker daemons are required for distinct nodes"
        )
    return spec


def capture(node, start_ns, end_ns, control, *, mode="periodic"):
    if mode not in ("periodic", "exact"):
        raise ValueError("Snapshot mode must be periodic or exact")
    sample_started = time.perf_counter()
    result = {
        "host_id": node["host_id"],
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "observer_mode": mode,
        "failures": [],
    }
    for key, script in (("backend", BACKEND_QUERY), ("telemetry", SPOOL_QUERY)):
        try:
            location = control if key == "backend" else node
            args = ["exec", location[key], "python", "-c", script]
            if key == "backend":
                args.append(
                    json.dumps([node["host_id"], node["target"], start_ns, end_ns, mode])
                )
            result[key] = json.loads(docker(location, *args))
        except (subprocess.SubprocessError, OSError, ValueError):
            result[key] = None
            result["failures"].append(key + "_unavailable")
    result["resources"] = {}
    for service in ("telemetry", "falco", "backend"):
        try:
            # Falco image may not include Python: explicitly unknown, never fabricated.
            location = control if service == "backend" else node
            result["resources"][service] = json.loads(
                docker(
                    location, "exec", location[service], "python", "-c", RESOURCE_QUERY
                )
            )
        except (subprocess.SubprocessError, OSError, ValueError):
            result["resources"][service] = {"status": "unknown"}
    result["observer_elapsed_seconds"] = time.perf_counter() - sample_started
    return result


def outage(node, scenario, seconds):
    key = {
        "control-plane-outage": "backend",
        "adapter-outage": "telemetry",
        "database-restart": "postgres",
    }[scenario]
    identifier = node.get(key)
    if not identifier:
        raise ValueError("Exact owned failure target is not configured")
    inspect_owned(node, identifier)
    try:
        docker(node, "stop", "--time", "5", identifier, timeout=15)
        time.sleep(seconds)
    finally:
        docker(node, "start", identifier, timeout=30)
    return {
        "scenario": scenario,
        "outage_seconds": seconds,
        "target_kind": key,
        "restored": True,
    }


def disk_pressure(node):
    image = json.loads(docker(node, "inspect", node["telemetry"]))[0]["Image"]
    program = """import json,sqlite3
from porygon_telemetry.spool import TelemetryStore,SpoolFullError
store=TelemetryStore('/pressure/spool.db',100000,max_bytes=16777216);accepted=0;failure=None
try:
 for index in range(10000):
  store.enqueue({'event_id':format(index,'064x'),'fixture':'x'*4096});accepted+=1
except (SpoolFullError,sqlite3.OperationalError) as error:failure=type(error).__name__
print(json.dumps({'accepted':accepted,'failure':failure,'boundary':'isolated tmpfs SQLite durability; no production spool touched'}))
"""
    name = "porygon-benchmark-pressure-" + os.urandom(6).hex()
    try:
        raw = docker(
            node,
            "run",
            "--rm",
            "--name",
            name,
            "--label",
            "com.porygon.benchmark=disposable",
            "--label",
            "com.porygon.benchmark-run=" + name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--tmpfs",
            "/pressure:rw,size=4m,mode=1777",
            "--entrypoint",
            "python",
            image,
            "-c",
            program,
            timeout=60,
        )
        return json.loads(raw)
    finally:
        try:
            info = json.loads(docker(node, "inspect", name))[0]
        except (ValueError, subprocess.SubprocessError):
            info = None
        if (
            info
            and (info.get("Config", {}).get("Labels", {}) or {}).get(
                "com.porygon.benchmark-run"
            )
            == name
        ):
            docker(node, "rm", "-f", info["Id"], timeout=15)


def source_window(
    node, seconds, start_ns, ready, canary_mode=False, expected_seed=1729
):
    prefix = ["docker"] + (
        ["--context", node["context"]] if node.get("context") else []
    )
    process = subprocess.Popen(
        [
            *prefix,
            "exec",
            node["observer"],
            "python",
            "-u",
            "-c",
            SOURCE_CAPTURE,
            json.dumps(
                [
                    node["target"],
                    seconds,
                    start_ns,
                    canary_mode,
                    expected_seed,
                    node["_capture_settings"],
                ]
            ),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    import threading

    timer = threading.Timer(15, process.kill)
    timer.daemon = True
    timer.start()
    try:
        first = bytearray()
        while not first.endswith(b"\n") and len(first) < 65537:
            part = os.read(process.stdout.fileno(), 1)
            if not part:
                break
            first.extend(part)
        if json.loads(first).get("state") != "ready":
            raise RuntimeError("Bounded source observer did not become ready")
        timer.cancel()
        timer = threading.Timer(seconds + 30, process.kill)
        timer.daemon = True
        timer.start()
        ready.set()
        output, _error = process.communicate(timeout=seconds + 30)
        if process.returncode != 0:
            raise RuntimeError("Bounded source observer failed")
        return json.loads(output)
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def network_peer(node):
    from ipaddress import ip_address

    peer = node.get("peer")
    if not isinstance(peer, dict):
        raise ValueError("Network scenario needs an owned local peer")
    info = inspect_owned(node, peer["container_id"], workload=True)
    target = json.loads(docker(node, "inspect", node["target"]))[0]
    shared = set(info["NetworkSettings"]["Networks"]) & set(
        target["NetworkSettings"]["Networks"]
    )
    addresses = {
        info["NetworkSettings"]["Networks"][name]["IPAddress"] for name in shared
    }
    if peer.get("address") not in addresses:
        raise ValueError("Peer address is not on the disposable target network")
    address = ip_address(peer["address"])
    if (
        not address.is_private
        or address.is_loopback
        or type(peer.get("port")) is not int
        or not 1 <= peer["port"] <= 65535
    ):
        raise ValueError("Private non-loopback owned peer and valid port required")
    return {"address": str(address), "port": peer["port"]}


def slow_notification(control):
    program = r"""
import json,secrets,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from threading import Thread
from porygon_api.notifications import Destination
from porygon_api.notification_worker import send_webhook
class Handler(BaseHTTPRequestHandler):
 def do_POST(self):
  self.rfile.read(int(self.headers['Content-Length']));time.sleep(2);self.send_response(204);self.end_headers()
 def log_message(self,*args):pass
server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=Thread(target=server.serve_forever,daemon=True);thread.start()
start=time.monotonic();failed=False
try:
 destination=Destination(destination_id='slow-local-sink',url=f'http://127.0.0.1:{server.server_port}/events',hmac_secret=secrets.token_urlsafe(48),allow_loopback=True)
 try:send_webhook(destination,'bounded-local-fixture',b'{}',timeout=1)
 except (ValueError,OSError):failed=True
 print(json.dumps({'timeout_observed':failed,'elapsed_seconds':time.monotonic()-start,'destination':'literal-loopback','external_messages':0,'boundary':'webhook transport; outbox semantics covered separately'}))
finally:server.shutdown();server.server_close();thread.join(timeout=3)
"""
    return json.loads(
        docker(control, "exec", control["backend"], "python", "-c", program, timeout=15)
    )


def summarize_observer_metrics(samples):
    periodic = [row for row in samples if row.get("observer_mode") == "periodic"]
    exact = [row for row in samples if row.get("observer_mode") == "exact"]

    def total(rows, key):
        values = [
            ((row.get("backend") or {}).get("observer_query_metrics") or {}).get(key)
            for row in rows
        ]
        if not rows or any(type(value) not in (int, float) for value in values):
            return None
        return sum(values)

    elapsed = [row.get("observer_elapsed_seconds") for row in samples]
    return {
        "periodic_snapshot_count": len(periodic),
        "periodic_identity_query_count": total(periodic, "identity_query_count"),
        "periodic_event_ids_materialized": total(
            periodic, "identity_ids_materialized"
        ),
        "periodic_assessment_query_count": total(
            periodic, "assessment_query_count"
        ),
        "periodic_percentile_query_count": total(periodic, "percentile_query_count"),
        "exact_final_query_count": len(exact),
        "exact_identity_query_count": total(exact, "identity_query_count"),
        "exact_event_ids_materialized": total(
            exact, "identity_ids_materialized"
        ),
        "exact_assessment_query_count": total(exact, "assessment_query_count"),
        "exact_percentile_query_count": total(exact, "percentile_query_count"),
        "observer_elapsed_seconds_total": sum(
            value for value in elapsed if type(value) in (int, float)
        )
        if elapsed and all(type(value) in (int, float) for value in elapsed)
        else None,
        "observer_elapsed_seconds_max": max(
            (value for value in elapsed if type(value) in (int, float)),
            default=None,
        ),
        "backend_snapshot_elapsed_seconds_total": total(
            samples, "snapshot_query_elapsed_seconds"
        ),
        "identity_query_elapsed_seconds_total": total(
            samples, "identity_query_elapsed_seconds"
        ),
        "assessment_query_elapsed_seconds_total": total(
            samples, "assessment_query_elapsed_seconds"
        ),
        "measurement_note": "query counts and materialized identities are software observer metrics, not measured production speedup",
    }


def health_observed_through(backend, boundary_ns):
    health = (backend or {}).get("health")
    if not health or not health.get("observed_at"):
        return False
    try:
        observed = datetime.fromisoformat(health["observed_at"])
    except (TypeError, ValueError):
        return False
    if observed.tzinfo is None:
        return False
    return observed.timestamp() * 1e9 >= boundary_ns


def run_node(
    node,
    control,
    scenario,
    rate,
    duration,
    seed,
    outage_seconds,
    drain_seconds,
    output,
    *,
    inject_shared_fault=True,
):
    from threading import Event
    from experiments.benchmarks.run import driver

    output = Path(output)
    output.mkdir(mode=0o700, parents=True)
    start_ns = int(
        docker(
            node,
            "exec",
            node["target"],
            "python",
            "-c",
            "import time; print(time.time_ns())",
        ).strip()
    )
    before = capture(node, start_ns, start_ns, control, mode="periodic")
    samples = [before]
    source = None
    workload = None
    fault = None
    failures = []
    with ThreadPoolExecutor(max_workers=3) as pool:
        ready = Event()
        observer = pool.submit(
            source_window,
            node,
            duration + drain_seconds + 10,
            start_ns,
            ready,
            scenario == "soak",
            seed,
        )
        sampling_origin = time.monotonic()
        try:
            if not ready.wait(timeout=15):
                raise RuntimeError("Source observer readiness deadline exceeded")
            workload_kind = (
                "network"
                if scenario == "network"
                else "memfd"
                if scenario == "memfd"
                else "file-write"
                if scenario == "file-write"
                else "exec"
            )
            peer = network_peer(node) if workload_kind == "network" else None
            requested_rate = (
                1 / 86400
                if scenario == "soak"
                else rate * 5
                if scenario == "burst"
                else rate
            )
            workload_future = pool.submit(
                driver,
                node["target"],
                workload_kind,
                requested_rate,
                duration,
                seed,
                context=node.get("context"),
                peer=peer,
            )
            fault_future = None
            if scenario == "adapter-outage" or (
                inject_shared_fault
                and scenario in ("control-plane-outage", "database-restart")
            ):
                if scenario in ("control-plane-outage", "database-restart"):
                    fault_node = dict(control)
                else:
                    fault_node = node
                fault_future = pool.submit(
                    outage, fault_node, scenario, min(outage_seconds, duration)
                )
            elif scenario == "disk-backpressure":
                fault_future = pool.submit(disk_pressure, node)
            elif scenario == "slow-notification":
                fault_future = pool.submit(slow_notification, control)
            deadline = time.monotonic() + duration + drain_seconds + 15
            while time.monotonic() < deadline and not observer.done():
                observed_ns = start_ns + int((time.monotonic() - sampling_origin) * 1e9)
                samples.append(
                    capture(node, start_ns, observed_ns, control, mode="periodic")
                )
                time.sleep(min(5, max(0, deadline - time.monotonic())))
            workload = workload_future.result(timeout=5)
            if fault_future:
                fault = fault_future.result(timeout=10)
            source = observer.result(timeout=15)
            # Poll cheap counts and freshness until ready; exact identity and latency
            # reconciliation runs once after this bounded recovery loop.
            recovery_deadline = time.monotonic() + drain_seconds
            recovery_ready = False
            while True:
                poll = capture(
                    node, start_ns, source["finished_ns"], control, mode="periodic"
                )
                samples.append(poll)
                backend = poll.get("backend") or {}
                health_fresh = health_observed_through(
                    backend, source["finished_ns"]
                )
                job_count = backend.get("assessment_jobs")
                assessment_observed = source["selected_source_records"] == 0 or (
                    type(job_count) is int and job_count > 0
                )
                if (
                    backend.get("persisted") == source["selected_source_records"]
                    and backend.get("assessment_pending") == 0
                    and assessment_observed
                    and health_fresh
                ):
                    recovery_ready = True
                    break
                if time.monotonic() >= recovery_deadline:
                    break
                time.sleep(min(5, max(0, recovery_deadline - time.monotonic())))
            exact = capture(
                node, start_ns, source["finished_ns"], control, mode="exact"
            )
            samples.append(exact)
            if (exact.get("backend") or {}).get("snapshot_mode") != "exact":
                failures.append("exact_final_backend_snapshot_unavailable")
            if not recovery_ready:
                failures.append("bounded_recovery_readiness_deadline_exceeded")
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
            failures.append(type(error).__name__)
    result = {
        "contract": "porygon.lab-node-trace",
        "host_id": node["host_id"],
        "daemon_id": node["_daemon_id"],
        "kernel_boot_id": node["_kernel_boot_id"],
        "hardware": node["_hardware"],
        "scenario": scenario,
        "seed": seed,
        "requested_duration_seconds": duration,
        "requested_operation_rate": rate,
        "source": source,
        "controller": workload,
        "fault": fault,
        "samples": samples,
        "observer_metrics": summarize_observer_metrics(samples),
        "failures": failures,
        "capture_global_completeness": "unknown",
        "resource_boundary": "main process CPU/RSS; sampling overhead is present and declared",
    }
    atomic_write_json(output / "trace.json", result)
    return result


def percentile(values, fraction):
    import math

    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, min(len(values) - 1, math.ceil(fraction * len(values)) - 1))]


def summarize_lab(traces, scenario, shared_fault=None):
    nodes = []
    latencies = []
    latency_complete = True
    for trace in traces:
        unknown = []
        failed = []
        samples = trace.get("samples", [])
        first = samples[0] if samples else {}
        last = samples[-1] if samples else {}
        source = trace.get("source")
        backend = last.get("backend")
        controller = trace.get("controller")
        delta = None
        rate = None
        duration = 0
        if source and backend:
            delta = source["selected_source_records"] - backend["persisted"]
            if source["counter_resets"] or source["parse_errors"]:
                unknown.append("source_observer_reset_or_parse_error")
            if source["selected_source_records"] == 0:
                unknown.append("no_selected_records_observed")
            if source["id_set_sha256"] != backend.get("persisted_id_set_sha256"):
                failed.append("observed_file_to_database_identity_set_mismatch")
            if controller:
                generation = controller["controller"]
                a = generation["started_ns"]
                b = generation["finished_ns"]
                duration = generation["elapsed_seconds"]
                count = sum(a <= stamp < b for stamp in source["event_timestamps_ns"])
                rate = count / ((b - a) / 1e9) if b > a else None
            if backend.get("duplicate_logical_jobs") is None:
                unknown.append("logical_assessment_identity_interval_incomplete")
            elif backend["duplicate_logical_jobs"]:
                failed.append("duplicate_logical_assessment_jobs")
        else:
            unknown.append("observed_file_or_database_boundary_unavailable")
        old = first.get("telemetry")
        new = last.get("telemetry")
        if old and new:
            if old["counter_epoch"] != new["counter_epoch"]:
                unknown.append("adapter_counter_reset")
            elif any(
                new[key] < old[key]
                for key in (
                    "adapter_accepted",
                    "adapter_delivered",
                    "backpressure_events",
                )
            ):
                unknown.append("adapter_counter_regression")
            if new["dead_letters"] > old["dead_letters"]:
                failed.append("dead_letters_increased")
            if new["backpressure_events"] > old["backpressure_events"]:
                failed.append("backpressure_observed")
        else:
            unknown.append("adapter_boundary_unavailable")
        first_health = (first.get("backend") or {}).get("health")
        last_health = (backend or {}).get("health")
        if (
            not first_health
            or not last_health
            or first_health["source_epoch"] is None
            or first_health["source_epoch"] != last_health["source_epoch"]
        ):
            unknown.append("kernel_counter_interval_unknown_or_reset")
        else:
            if source:
                first_stamp = (
                    datetime.fromisoformat(first_health["observed_at"]).timestamp()
                    * 1e9
                )
                last_stamp = (
                    datetime.fromisoformat(last_health["observed_at"]).timestamp() * 1e9
                )
                if not 0 <= source["started_ns"] - first_stamp <= 120 * 1e9:
                    unknown.append("starting_health_boundary_unobserved_or_stale")
                if not 0 <= last_stamp - source["finished_ns"] <= 120 * 1e9:
                    unknown.append("ending_health_boundary_unobserved_or_stale")
            for name in ("falco_drops", "falco_output_drops"):
                a = first_health["metrics"].get(name)
                b = last_health["metrics"].get(name)
                if a is None or b is None:
                    unknown.append(name + "_unknown")
                elif b < a:
                    unknown.append(name + "_regressed")
                elif b > a:
                    failed.append(name + "_observed")
        if (
            backend
            and backend["assessment_latency_complete"]
            and backend["assessment_completed"]
            and not backend["assessment_pending"]
        ):
            latencies.append(backend["assessment_latency_p95_seconds"])
        else:
            latency_complete = False
            unknown.append("assessment_latency_unavailable_or_incomplete")
            if backend and backend.get("assessment_state_counts", {}).get("failed", 0):
                failed.append("assessment_jobs_failed")
            if backend and backend.get("negative_assessment_lag_count", 0):
                unknown.append("cross_host_clock_anomaly")
        trace_failures = set(trace.get("failures") or [])
        unavailable_exact_snapshot = (
            "exact_final_backend_snapshot_unavailable" in trace_failures
        )
        if unavailable_exact_snapshot:
            unknown.append("exact_final_backend_snapshot_unavailable")
            trace_failures.remove("exact_final_backend_snapshot_unavailable")
        if trace_failures or (
            controller and controller["controller"]["failure_count"]
        ):
            failed.append("controller_or_collection_failure")
        if not controller:
            unknown.append("controller_measurement_missing")
        state = "fail" if failed else "unknown" if unknown else "pass"
        nodes.append(
            {
                "host_id": trace["host_id"],
                "measured_selected_events_per_second": rate,
                "observed_file_to_database_delta": delta,
                "unknown_reasons": unknown,
                "failure_reasons": failed,
                "matching_measured_boundaries": state,
                "duration_seconds": duration,
                "observer_metrics": trace.get("observer_metrics"),
            }
        )
    duration = min((row["duration_seconds"] for row in nodes), default=0)
    p95 = max(latencies) if latencies else None

    def target(required_rate, required_duration):
        if (
            len(nodes) < 3
            or duration < required_duration
            or any(row["measured_selected_events_per_second"] is None for row in nodes)
        ):
            return "unknown"
        if any(
            row["matching_measured_boundaries"] == "fail"
            or row["measured_selected_events_per_second"] < required_rate
            for row in nodes
        ):
            return "fail"
        if any(row["matching_measured_boundaries"] == "unknown" for row in nodes):
            return "unknown"
        return "pass"

    targets = {
        "three_node_envelope": target(100, 3600)
        if scenario == "sustained"
        else "unknown",
        "five_times_burst": target(500, 60) if scenario == "burst" else "unknown",
        "p95_assessment_latency": "unknown",
        "outage_recovery": "unknown",
        "seven_day_soak": "unknown",
    }
    if p95 is not None:
        targets["p95_assessment_latency"] = (
            "fail" if p95 >= 10 else "pass" if latency_complete else "unknown"
        )
    fault = shared_fault or (traces[0].get("fault") if traces else None)
    if (
        scenario == "control-plane-outage"
        and fault
        and fault.get("outage_seconds", 0) >= 1800
    ):
        targets["outage_recovery"] = (
            "fail"
            if any(row["matching_measured_boundaries"] == "fail" for row in nodes)
            else "unknown"
            if any(row["matching_measured_boundaries"] == "unknown" for row in nodes)
            else "pass"
        )
    canary_accounting = []
    if scenario == "soak" and duration >= 604800:
        for trace in traces:
            controller = (trace.get("controller") or {}).get("controller", {})
            values = controller.get("completion_times_ns", [])
            start = controller.get("started_ns")
            end = controller.get("finished_ns")
            source = trace.get("source") or {}
            bins = (
                [
                    sum(
                        start + day * 86400 * 10**9
                        <= stamp
                        < start + (day + 1) * 86400 * 10**9
                        for stamp in values
                    )
                    for day in range(7)
                ]
                if start
                else []
            )
            observed = {
                row["sequence"]: row["at_ns"]
                for row in source.get("canary_observations", [])
            }
            correlated = bool(controller.get("completion_records")) and all(
                row["sequence"] in observed
                and 0 <= row["at_ns"] - observed[row["sequence"]] <= 5 * 10**9
                for row in controller.get("completion_records", [])
            )
            covered = bool(
                correlated
                and start
                and end
                and values
                and len(bins) == 7
                and all(bins)
                and values[0] - start <= 60 * 10**9
                and end - values[-1] <= 86460 * 10**9
                and len(source.get("canary_sequences", [])) >= 7
            )
            canary_accounting.append(
                {
                    "host_id": trace["host_id"],
                    "daily_controller_counts": bins,
                    "endpoints_and_selected_canaries_observed": covered,
                    "controller_source_sequence_correlation": correlated,
                }
            )
        targets["seven_day_soak"] = (
            "fail"
            if any(
                not row["endpoints_and_selected_canaries_observed"]
                for row in canary_accounting
            )
            or any(row["matching_measured_boundaries"] == "fail" for row in nodes)
            else "unknown"
            if any(row["matching_measured_boundaries"] == "unknown" for row in nodes)
            else "pass"
        )
    return {
        "contract": "porygon.lab-capacity-report",
        "scenario": scenario,
        "nodes": nodes,
        "maximum_node_p95_window_close_to_assessment_seconds": p95,
        "assessment_quantile_method": "maximum exact per-node percentile_cont; all selected jobs must be successful for a pass",
        "targets": targets,
        "daily_canary_accounting": canary_accounting,
        "shared_control_plane_fault": shared_fault,
        "global_kernel_completeness": "unknown",
        "units": "selected normalized Falco records within exact controller event-time generation interval; downstream drain excluded from throughput",
        "independent_linux_nodes": len({row["kernel_boot_id"] for row in traces}),
        "control_planes": 1,
    }


def run_lab(
    spec, scenario, duration, rate, seed, outage_seconds, drain_seconds, output
):
    import math
    from experiments.benchmarks.run import SCENARIOS

    if (
        scenario not in SCENARIOS
        or type(seed) is not int
        or not 0 <= seed <= 2147483647
    ):
        raise ValueError("Declared scenario and bounded seed required")
    if (
        any(
            type(value) not in (int, float) or not math.isfinite(value) or value <= 0
            for value in (duration, rate, outage_seconds, drain_seconds)
        )
        or duration > 604800
        or rate > 100000
        or drain_seconds > 3600
    ):
        raise ValueError("Positive bounded measurement options required")
    output = Path(output)
    if output.exists():
        raise ValueError("Use a fresh output directory")
    spec = validate_spec(spec)
    output.mkdir(mode=0o700, parents=True)
    atomic_write_json(
        output / "lab-plan.json",
        {
            "contract": "porygon.benchmark-lab-plan",
            "spec": spec,
            "scenario": scenario,
            "rate": rate,
            "duration_seconds": duration,
            "seed": seed,
        },
    )
    with ThreadPoolExecutor(max_workers=len(spec["nodes"])) as pool:
        futures = [
            pool.submit(
                run_node,
                node,
                spec["control_plane"],
                scenario,
                rate,
                duration,
                seed,
                outage_seconds,
                drain_seconds,
                output / node["host_id"],
                inject_shared_fault=index == 0,
            )
            for index, node in enumerate(spec["nodes"])
        ]
        traces = [future.result() for future in futures]
    shared = (
        traces[0].get("fault")
        if scenario in ("control-plane-outage", "database-restart")
        else None
    )
    atomic_write_json(output / "report.json", summarize_lab(traces, scenario, shared))
    return {"output": str(output), "nodes": len(traces), "measured": True}


def main():
    from experiments.benchmarks.run import SCENARIOS

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--rate", type=float, default=100)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--outage-seconds", type=float, default=1800)
    parser.add_argument("--drain-seconds", type=float, default=120)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    import math

    if not 0 <= args.seed <= 2147483647:
        parser.error("Bounded nonnegative seed required")
    if (
        any(
            not math.isfinite(value) or value <= 0
            for value in (
                args.duration,
                args.rate,
                args.outage_seconds,
                args.drain_seconds,
            )
        )
        or args.duration > 604800
        or args.rate > 100000
        or args.drain_seconds > 3600
    ):
        parser.error("Positive bounded duration/rate/deadlines required")
    if args.spec.stat().st_size > 65536:
        parser.error("Lab specification exceeds bounded size")
    if args.output.exists():
        parser.error("Use a fresh output directory")
    print(
        json.dumps(
            run_lab(
                json.loads(args.spec.read_text()),
                args.scenario,
                args.duration,
                args.rate,
                args.seed,
                args.outage_seconds,
                args.drain_seconds,
                args.output,
            )
        )
    )


if __name__ == "__main__":
    main()
