"""Back up a selected Compose database and prove restore into a new private volume.

No backend/responder is started. Restored credentials and unresolved response
intents remain offline; promotion to a running installation requires operator review.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import tempfile
import time
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[1]


def command(args,**kwargs):
    return subprocess.run(args,check=True,capture_output=True,**kwargs).stdout


def sql(container,statement,snapshot_id=None):
    # PostgreSQL password stays inside the container environment, never argv/output.
    if snapshot_id:
        if not re.fullmatch(r"[A-Fa-f0-9-]+",snapshot_id):raise ValueError("Invalid exported snapshot")
        statement="BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET TRANSACTION SNAPSHOT '"+snapshot_id+"'; "+statement+" COMMIT;"
    return command(['docker','exec',container,'sh','-c',
        'exec psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -qAt',],input=statement.encode()).decode()


def snapshot(container,snapshot_id=None):
    tables=sql(container,"SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;",snapshot_id).splitlines()
    result={}
    for table in tables:
        if not re.fullmatch(r'[a-z_][a-z0-9_]*',table):raise ValueError('Unexpected database identifier')
        # Hash each full row server-side, then hash the sorted digests. No values leave PostgreSQL.
        rows=sql(container,f'SELECT md5(row_to_json(t)::text) FROM "{table}" t ORDER BY 1;',snapshot_id).splitlines()
        result[table]={'rows':len(rows),'row_digest_sha256':hashlib.sha256('\n'.join(rows).encode()).hexdigest()}
    return result


def verify(output,destination_project=None,*,rpo_target_seconds=3600,rto_target_seconds=600):
    output=Path(output).resolve()
    if output.exists():raise ValueError('Use a new private output directory')
    output.mkdir(mode=0o700,parents=True)
    source=command(['docker','compose','ps','-q','postgres'],cwd=ROOT).decode().strip()
    if not re.fullmatch(r'[a-f0-9]{12,64}',source):raise ValueError('Exactly one active source database is required')
    source_info=json.loads(command(['docker','inspect',source]))[0]
    active_project=source_info.get('Config',{}).get('Labels',{}).get('com.docker.compose.project')
    project=destination_project or 'porygon-restore-'+uuid4().hex[:12]
    if not re.fullmatch(r'porygon-restore-[a-z0-9-]{6,40}',project) or project==active_project:
        raise ValueError('Restore requires a fresh porygon-restore-* project')
    volume=project+'-database';container=project+'-postgres'
    active_volumes={item.get('Name') for item in source_info.get('Mounts',[]) if item.get('Type')=='volume'}
    if volume in active_volumes:raise ValueError('Active volume cannot be a restore destination')
    # Refuse every pre-existing destination, including a previous failed drill.
    for kind,name in (('volume',volume),('container',container)):
        exists=subprocess.run(['docker',kind,'inspect',name],capture_output=True).returncode==0
        if exists:raise ValueError('Restore destination already exists')
    started=time.monotonic();created_at=datetime.now(timezone.utc).isoformat()
    snapshot_time=datetime.now(timezone.utc)
    holder=subprocess.Popen(['docker','exec','-i',source,'sh','-c',
        'exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    try:
        holder.stdin.write('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT pg_export_snapshot();\n');holder.stdin.flush()
        snapshot_id=holder.stdout.readline().strip()
        if not re.fullmatch(r'[A-Fa-f0-9-]+',snapshot_id):raise RuntimeError('Could not export read-only database snapshot')
        before=snapshot(source,snapshot_id)
        dump=output/'database.dump'
        descriptor=os.open(dump,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(descriptor,'wb') as handle:
            subprocess.run(['docker','exec',source,'sh','-c',
                'exec pg_dump -Fc --snapshot "$1" -U "$POSTGRES_USER" -d "$POSTGRES_DB"','restore-snapshot',snapshot_id],
                stdout=handle,stderr=subprocess.PIPE,check=True)
    finally:
        if holder.stdin:
            try:holder.stdin.write('ROLLBACK;\n');holder.stdin.flush()
            except BrokenPipeError:pass
            holder.stdin.close()
        try:holder.wait(timeout=10)
        except subprocess.TimeoutExpired:holder.kill();holder.wait()
    responder=command(['docker','compose','ps','-q','responder'],cwd=ROOT).decode().strip()
    if not re.fullmatch(r'[a-f0-9]{12,64}',responder):raise ValueError('Active responder receipt store is required')
    receipt_backup=output/'response-receipts.sqlite'
    descriptor=os.open(receipt_backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'wb') as handle:
        subprocess.run(['docker','exec',responder,'python','-c',
            'import os,sqlite3,tempfile,sys; source=sqlite3.connect("file:"+os.environ.get("PORYGON_COMPLETION_STORE_PATH","/var/lib/porygon/completions.sqlite")+"?mode=ro",uri=True); '
            'fd,path=tempfile.mkstemp(); os.close(fd); target=sqlite3.connect(path); source.backup(target); target.close(); source.close(); '
            'sys.stdout.buffer.write(open(path,"rb").read()); os.unlink(path)'],stdout=handle,stderr=subprocess.PIPE,check=True)
    with sqlite3.connect('file:'+str(receipt_backup)+'?mode=ro',uri=True) as receipts:
        if receipts.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('Response receipt backup integrity failed')
    receipt_hash=hashlib.sha256(receipt_backup.read_bytes()).hexdigest()
    label='com.porygon.restore-drill='+project
    created_volume=False;created_container=False
    try:
        command(['docker','volume','create','--label',label,volume])
        volume_info=json.loads(command(['docker','volume','inspect',volume]))[0]
        if volume_info.get('Labels',{}).get('com.porygon.restore-drill')!=project:raise ValueError('Destination volume ownership changed')
        created_volume=True
        with tempfile.NamedTemporaryFile('w',dir=output,prefix='.restore-env-',delete=False) as handle:
            private_env=Path(handle.name);os.chmod(private_env,0o600)
            handle.write('POSTGRES_USER=porygon_restore\nPOSTGRES_DB=porygon_restore\nPOSTGRES_PASSWORD='+secrets.token_urlsafe(48)+'\n')
        try:
            command(['docker','run','-d','--name',container,'--label',label,'--network','none',
                '--env-file',str(private_env),'--mount',f'type=volume,src={volume},dst=/var/lib/postgresql/data',source_info['Image']])
            created_container=True
        finally:private_env.unlink(missing_ok=True)
        deadline=time.monotonic()+90
        while True:
            ready=subprocess.run(['docker','exec',container,'pg_isready','-U','porygon_restore','-d','porygon_restore'],capture_output=True).returncode==0
            if ready:break
            if time.monotonic()>=deadline:raise RuntimeError('Disposable database readiness deadline exceeded')
            time.sleep(1)
        with dump.open('rb') as handle:
            subprocess.run(['docker','exec','-i',container,'pg_restore','--exit-on-error','--no-owner','--no-privileges',
                '-U','porygon_restore','-d','porygon_restore'],stdin=handle,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,check=True)
        restored=snapshot(container)
        source_after=json.loads(command(['docker','inspect',source]))[0]
        preserved=source_after['Id']==source_info['Id'] and source_after.get('Mounts')==source_info.get('Mounts')
        snapshot_age=(datetime.now(timezone.utc)-snapshot_time).total_seconds()
        report={'contract':'porygon.restore-drill','started_at':created_at,'source_project':active_project,
            'destination_project':project,'destination_network':'none','source_image_id':source_info['Image'],
            'dump_sha256':hashlib.sha256(dump.read_bytes()).hexdigest(),'source_before':before,'restored':restored,
            'restore_matches_snapshot':before==restored,'source_objects_preserved':preserved,'source_access':'read-only-exported-snapshot','snapshot_at':snapshot_time.isoformat(),
            'snapshot_age_seconds':snapshot_age,
            'rpo_target_seconds':rpo_target_seconds,'rto_target_seconds':rto_target_seconds,
            'elapsed_seconds':time.monotonic()-started,'response_intents':'offline-operator-review-required',
            'receipt_recovery':{'sha256':receipt_hash,'integrity':'ok','state':'offline-operator-review-required'},
            'passed':before==restored and preserved and snapshot_age<=rpo_target_seconds and time.monotonic()-started<=rto_target_seconds}
        descriptor=os.open(output/'report.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(descriptor,'w') as handle:json.dump(report,handle,sort_keys=True,indent=2)
        return report
    finally:
        # Only remove exact objects created in this invocation and carrying its label.
        if created_container:
            info=json.loads(command(['docker','inspect',container]))[0]
            if info['Config']['Labels'].get('com.porygon.restore-drill')==project:command(['docker','rm','-f',container])
        if created_volume:
            info=json.loads(command(['docker','volume','inspect',volume]))[0]
            if info['Labels'].get('com.porygon.restore-drill')==project:command(['docker','volume','rm',volume])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--disposable',action='store_true',required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--destination-project')
    parser.add_argument('--rpo-target-seconds',type=int,default=3600);parser.add_argument('--rto-target-seconds',type=int,default=600)
    args=parser.parse_args()
    if args.rpo_target_seconds<=0 or args.rto_target_seconds<=0:parser.error('Recovery targets must be positive')
    try:report=verify(args.output,args.destination_project,rpo_target_seconds=args.rpo_target_seconds,rto_target_seconds=args.rto_target_seconds)
    except (ValueError,OSError,subprocess.SubprocessError,RuntimeError) as exc:
        failure={'passed':False,'error_category':type(exc).__name__}
        if args.output.is_dir():
            descriptor=os.open(args.output/'failure.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(descriptor,'w') as handle:json.dump(failure,handle)
        print(json.dumps(failure));return 1
    print(json.dumps({key:report[key] for key in ('passed','elapsed_seconds','restore_matches_snapshot','source_objects_preserved')}))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
