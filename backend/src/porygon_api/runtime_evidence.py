"""Bounded process-lifetime evidence; proximity is never promoted to causality."""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime,timezone
from ipaddress import ip_address
from sqlalchemy import select
from fastapi import HTTPException
from porygon_api.models import ProcessExecEvent,KernelRuntimeEvent
from porygon_api.vulnerability import sha256_document

CONTRACT='porygon.runtime-evidence'
RULES={
    'POR-EVD-CHILD-NET':{'requires':['observed_parent','unexpected_exec','attributed_nonloopback_connection'],'severity':0.82},
    'POR-EVD-MEMFD-EXEC':{'requires':['process_lifetime','observed_exe_from_memfd'],'severity':0.90},
    'POR-EVD-SENSITIVE-WRITE':{'requires':['unexpected_exec','observed_parent','attributed_positive_sensitive_write'],'severity':0.86},
    'POR-EVD-WRITABLE-NET':{'requires':['unexpected_exec','observed_exe_writable','attributed_nonloopback_connection'],'severity':0.80},
}
CONFIG={'contract':CONTRACT,'max_rows':10000,'max_link_seconds':120,'max_depth':4,'rules':RULES}
RULES_HASH=sha256_document(CONFIG)
FIELDS=('event_id','docker_host_id','container_id','sensor_instance_id','sensor_epoch','process_pid',
    'process_start_ns','parent_start_ns','pid_namespace_start_ns','process_ppid','time_nano','event_type',
    'runtime_action','return_value','exe_from_memfd','exe_writable','executable','parent_executable',
    'remote_address','remote_port','file_path','exec_return_value','event_direction')


def epoch_ns(value):
    value=value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    delta=value-datetime(1970,1,1,tzinfo=timezone.utc)
    return (delta.days*86400+delta.seconds)*1000000000+delta.microseconds*1000


def identity(event):
    """Require observed namespace/lifetime fields; adapter epoch is conservative."""
    values=[event.get(key) for key in ('docker_host_id','container_id','sensor_instance_id','sensor_epoch',
        'pid_namespace_start_ns','process_pid','process_start_ns')]
    if (not all(value is not None for value in values) or
        any(not isinstance(event.get(key),str) or not event[key] or len(event[key])>128 for key in ('docker_host_id','sensor_instance_id','sensor_epoch')) or
        any(
        not isinstance(event.get(key),int) or isinstance(event.get(key),bool) or event[key]<=0
        for key in ('pid_namespace_start_ns','process_pid','process_start_ns'))):
        return None
    if event['process_start_ns']>event['time_nano']:
        return None
    return tuple(values)


def query_events(db,scope,start,end,*,process_ids=None,kernel_ids=None):
    records=[]
    for model,ids in ((ProcessExecEvent,process_ids),(KernelRuntimeEvent,kernel_ids)):
        query=select(model).where(model.docker_host_id==scope.docker_host_id,model.container_id==scope.container_id,
            model.correlation_status=='resolved',model.time_nano>=epoch_ns(start),model.time_nano<epoch_ns(end))
        if ids is not None:
            query=query.where(model.event_id.in_(ids))
        rows=db.scalars(query.order_by(model.time_nano,model.event_id).limit(CONFIG['max_rows']+1)).all()
        if len(rows)>CONFIG['max_rows']:
            raise HTTPException(413,'Runtime evidence selection exceeds its bounded contract')
        if ids is not None and len(rows)!=len(set(ids)):
            raise HTTPException(409,'Frozen runtime evidence is unavailable')
        for row in rows:
            record={field:getattr(row,field,None) for field in FIELDS}
            record['channel']='process' if model is ProcessExecEvent else 'kernel'
            records.append(record)
    if len(records)>CONFIG['max_rows']:
        raise HTTPException(413,'Runtime evidence selection exceeds its bounded contract')
    return sorted(records,key=lambda event:(event['time_nano'],event['event_id']))


def build_bundle(events,scope,window_start,window_end,known_executables):
    """Pure deterministic replay over a deliberately argument-free evidence subset."""
    if len(events)>CONFIG['max_rows']:
        raise ValueError('Evidence row bound exceeded')
    start_ns=epoch_ns(window_start);end_ns=epoch_ns(window_end)
    selected=[]
    for source in events:
        event={field:source.get(field) for field in (*FIELDS,'channel')}
        if (event['docker_host_id']!=scope.docker_host_id or event['container_id']!=scope.container_id
                or not isinstance(event['time_nano'],int) or isinstance(event['time_nano'],bool) or not start_ns<=event['time_nano']<end_ns):
            raise ValueError('Evidence outside declared exact target/window')
        selected.append(event)
    selected.sort(key=lambda item:(item['time_nano'],item['event_id']))
    if len({item['event_id'] for item in selected})!=len(selected):
        raise ValueError('Duplicate evidence IDs')
    executions=defaultdict(list)
    for event in selected:
        key=identity(event)
        if event['channel']=='process' and key and event.get('exec_return_value')==0 and event.get('event_direction')=='<':
            executions[key].append(event)
    edges=[];parents={};attributions={}
    for event in selected:
        key=identity(event)
        if not key:
            edges.append({'source':event['event_id'],'target':None,'relation':'process_identity','certainty':'unavailable'})
            continue
        if event['channel']=='process':
            if event.get('exec_return_value')!=0 or event.get('event_direction')!='<':
                edges.append({'source':event['event_id'],'target':None,'relation':'successful_exec','certainty':'unavailable'})
                continue
            parent_key=(*key[:5],event.get('process_ppid'),event.get('parent_start_ns'))
            candidates=[item for item in executions.get(parent_key,[]) if item['time_nano']<=event['time_nano']]
            if candidates:
                parent=max(candidates,key=lambda item:(item['time_nano'],item['event_id']))
                parents[event['event_id']]=parent
                edges.append({'source':parent['event_id'],'target':event['event_id'],'relation':'parent_process','certainty':'observed'})
            elif event.get('process_ppid') is not None:
                edges.append({'source':None,'target':event['event_id'],'relation':'parent_process','certainty':'unavailable'})
        else:
            candidates=[item for item in executions.get(key,[]) if 0<=event['time_nano']-item['time_nano']<=CONFIG['max_link_seconds']*1e9]
            if candidates:
                process=max(candidates,key=lambda item:(item['time_nano'],item['event_id']))
                attributions[event['event_id']]=process
                edges.append({'source':process['event_id'],'target':event['event_id'],'relation':'same_observed_process_lifetime','certainty':'observed'})
            else:
                # PID/time proximity alone remains an inferred association and
                # is excluded from every rule's supporting causal path.
                candidates=[item for item in selected if item['channel']=='process' and item['process_pid']==event['process_pid']]
                edges.append({'source':candidates[-1]['event_id'] if candidates else None,
                    'target':event['event_id'],'relation':'proximity_only','certainty':'inferred' if candidates else 'unavailable'})
    findings=[]
    def emit(rule,event,support):
        ids=sorted(set(support));spec=RULES[rule]
        document={'rule_id':rule,'supporting_ids':ids,'rules_hash':RULES_HASH}
        if any(item['finding_hash']==sha256_document(document) for item in findings):
            return
        findings.append(dict(document,finding_hash=sha256_document(document),severity=spec['severity'],
            certainty='observed',time_nano=event['time_nano'],explanation=spec['requires']))
    for event in selected:
        if event['channel']=='process':
            if identity(event) and event['exe_from_memfd'] is True and event.get('exec_return_value')==0 and event.get('event_direction')=='<':
                emit('POR-EVD-MEMFD-EXEC',event,[event['event_id']])
            continue
        process=attributions.get(event['event_id'])
        if not process or not process.get('executable') or process['executable'] in known_executables:
            continue
        parent=parents.get(process['event_id'])
        outbound=False
        if event['runtime_action']=='net_outbound' and event['return_value'] is not None and event['return_value']>=0:
            try:
                if not isinstance(event['remote_port'],int) or isinstance(event['remote_port'],bool) or not 1<=event['remote_port']<=65535:
                    raise ValueError('Unavailable peer port')
                address=ip_address(event['remote_address'])
                outbound=not (address.is_loopback or address.is_unspecified or
                    (getattr(address,'ipv4_mapped',None) and address.ipv4_mapped.is_loopback))
            except (ValueError,TypeError):
                pass
        if outbound and parent:
            emit('POR-EVD-CHILD-NET',event,[parent['event_id'],process['event_id'],event['event_id']])
        if outbound and process['exe_writable'] is True:
            emit('POR-EVD-WRITABLE-NET',event,[process['event_id'],event['event_id']])
        if (parent and event['runtime_action']=='file_write' and (event.get('return_value') or 0)>0
                and isinstance(event['file_path'],str) and event['file_path'].startswith(('/etc/','/root/.ssh/','/usr/bin/','/bin/'))):
            emit('POR-EVD-SENSITIVE-WRITE',event,[parent['event_id'],process['event_id'],event['event_id']])
    document={'contract':CONTRACT,'rules_hash':RULES_HASH,'scope':scope.manifest(),
        'window_start':window_start.isoformat(),'window_end':window_end.isoformat(),
        'known_executables':sorted(known_executables),'events':selected,'edges':edges,
        'findings':sorted(findings,key=lambda item:item['finding_hash']),
        'coverage':{'complete':False,'source_drop_coverage':'unknown',
                    'unavailable_identity_events':sum(identity(item) is None for item in selected)}}
    return dict(document,bundle_hash=sha256_document(document))


def detection_matches(bundle):
    return [{'rule_id':item['rule_id'],'name':item['rule_id'],'category':'runtime_evidence',
        'description':'Observed process-lifetime evidence hypothesis','severity_weight':item['severity'],
        'confidence_weight':0.9,'incident_eligible':True,'suppressed':False,
        'source_type':'runtime_evidence','source_id':item['finding_hash'],'container_id':bundle['scope']['container_id'],
        'occurred_at':datetime.fromtimestamp(item['time_nano']/1e9,tz=timezone.utc).isoformat(),
        'summary':'Observed attributable runtime evidence; review the supporting records.',
        'details':{'supporting_ids':item['supporting_ids'],'bundle_hash':bundle['bundle_hash'],
                   'rules_hash':bundle['rules_hash'],'certainty':item['certainty']}}
        for item in bundle['findings']]
