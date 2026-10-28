"""Separate bounded health samples with explicit counter epochs and unknown loss."""
from datetime import datetime,timezone,timedelta
from typing import Annotated,Literal
from fastapi import APIRouter,Depends,HTTPException,Query,Request
from pydantic import BaseModel,ConfigDict,Field,model_validator,ValidationError
from sqlalchemy import select,func,delete
from sqlalchemy.orm import Session
from porygon_api.auth import utc
from porygon_api.db import get_db
from porygon_api.models import SensorHealthSample,NotificationDelivery,AssessmentJob
from porygon_api.vulnerability import sha256_document

router=APIRouter(tags=['health-metrics'])
METRICS=frozenset({'source_read_attempts','spooled_events','delivered_events','queue_depth','queue_payload_bytes',
    'spool_disk_bytes','oldest_age_seconds','backpressure_events','dead_letters','falco_events','falco_drops',
    'falco_output_drops','falco_start_ns','falco_reload_ns','host_boot_ns','backend_failures'})


class HealthIn(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,allow_inf_nan=False)
    counter_epoch: str=Field(min_length=1,max_length=128)
    sequence: int=Field(ge=0,le=9223372036854775807)
    metrics: dict[str,Annotated[float,Field(ge=0,le=1e19)]]=Field(max_length=32)
    source_loss: Literal['unknown','known-loss','no-observed-drops']='unknown'
    source_epoch: str | None=Field(default=None,min_length=1,max_length=128)

    @model_validator(mode='after')
    def bounded_names(self):
        if not set(self.metrics)<=METRICS:
            raise ValueError('Unknown or sensitive metric name')
        if self.source_loss!='unknown' and (self.source_epoch is None or 'falco_drops' not in self.metrics):
            raise ValueError('Source loss status needs source counter epoch and observed drop counter')
        return self


def prune_health(db,host,service,now=None):
    """Bound heartbeat history independently of optional raw-retention scheduling.

    Assessment coverage is copied into immutable job evidence before completion.
    Windows older than raw retention already abstain; retain an extra two-minute
    boundary on both event and receipt clocks so eligible windows keep context.
    """
    from porygon_api.config import get_settings
    now=now or datetime.now(timezone.utc)
    cutoff=now-timedelta(days=get_settings().raw_event_retention_days,minutes=2)
    ids=list(db.scalars(select(SensorHealthSample.sample_id).where(
        SensorHealthSample.docker_host_id==host,SensorHealthSample.service_name==service,
        SensorHealthSample.observed_at<cutoff,SensorHealthSample.received_at<cutoff)
        .order_by(SensorHealthSample.received_at,SensorHealthSample.sample_id).limit(64)))
    if ids:db.execute(delete(SensorHealthSample).where(SensorHealthSample.sample_id.in_(ids)))
    return len(ids)


def record_health(db,payload):
    raw=payload.metadata.get('health')
    if raw is None:return None
    try:sample=HealthIn.model_validate(raw)
    except ValidationError as exc:raise HTTPException(422,'Invalid bounded sensor health contract') from exc
    host=payload.metadata.get('docker_host_id')
    if not isinstance(host,str) or not host or host=='auto':
        return None # Compatibility sensors without assigned hosts remain explicitly unknown.
    prune_health(db,host,payload.service_name)
    key={'host':host,'service':payload.service_name,'instance':payload.instance_id,'epoch':sample.counter_epoch,'sequence':sample.sequence}
    identifier=sha256_document(key)
    existing=db.get(SensorHealthSample,identifier)
    if existing is None:
        # Pre-host-identity migrations used another hash; preserve their immutable row ID.
        existing=db.scalar(select(SensorHealthSample).where(SensorHealthSample.docker_host_id==host,
            SensorHealthSample.service_name==payload.service_name,SensorHealthSample.instance_id==payload.instance_id,
            SensorHealthSample.counter_epoch==sample.counter_epoch,SensorHealthSample.sequence==sample.sequence))
    metrics=sample.model_dump()
    if existing:
        if existing.metrics!=metrics:raise HTTPException(409,'Health sequence cannot change contents')
        return existing
    row=SensorHealthSample(sample_id=identifier,docker_host_id=host,service_name=payload.service_name,
        instance_id=payload.instance_id,counter_epoch=sample.counter_epoch,sequence=sample.sequence,
        observed_at=payload.observed_at,received_at=datetime.now(timezone.utc),metrics=metrics)
    db.add(row);return row


def health_coverage(db,host,start,end):
    """Only compare samples bounding the window; current counters cannot prove history."""
    output={'source_loss':'unknown','reasons':[],'boundaries':{}}
    for service in ('collector','telemetry'):
        before=db.scalar(select(SensorHealthSample).where(SensorHealthSample.docker_host_id==host,
            SensorHealthSample.service_name==service,SensorHealthSample.observed_at<=start,
            SensorHealthSample.observed_at>=start-timedelta(minutes=2))
            .order_by(SensorHealthSample.observed_at.desc()).limit(1))
        after=db.scalar(select(SensorHealthSample).where(SensorHealthSample.docker_host_id==host,
            SensorHealthSample.service_name==service,SensorHealthSample.observed_at>=end,
            SensorHealthSample.observed_at<=end+timedelta(minutes=2))
            .order_by(SensorHealthSample.observed_at).limit(1))
        if not before or not after:
            output['reasons'].append(service+'_health_interval_unknown');continue
        old,new=before.metrics,after.metrics
        if before.instance_id != after.instance_id:
            output['reasons'].append(service+'_instance_changed');continue
        if before.counter_epoch!=after.counter_epoch:
            output['reasons'].append(service+'_counter_reset');continue
        previous,current=old['metrics'],new['metrics']
        if any(current[key]<previous[key] for key in ('spooled_events','delivered_events','backpressure_events') if key in previous and key in current):
            output['reasons'].append(service+'_counter_regression');continue
        if current.get('dead_letters',0)>previous.get('dead_letters',0):
            output['reasons'].append(service+'_rejected_records_observed')
        if current.get('backpressure_events',0)>previous.get('backpressure_events',0):
            output['reasons'].append(service+'_backpressure_observed')
        source_epoch=old.get('source_epoch')
        if source_epoch != new.get('source_epoch'):
            output['reasons'].append(service+'_source_epoch_changed')
            continue
        if source_epoch:
            for metric, boundary, reason in (
                ('falco_drops','falco_kernel_drop_delta','falco_kernel_drops_observed'),
                ('falco_output_drops','falco_output_drop_delta','falco_output_drops_observed'),
            ):
                if metric not in previous or metric not in current:
                    output['reasons'].append(metric+'_interval_unknown');continue
                delta=current[metric]-previous[metric]
                if delta<0:
                    output['reasons'].append(metric+'_counter_regression');continue
                output['boundaries'][boundary]=delta
                if delta>0:
                    output['source_loss']='known-loss';output['reasons'].append(reason)
        # Even zero observed drops does not establish global completeness.
    return output


@router.get('/api/v1/health-metrics')
def health_status(request: Request,limit: int=Query(100,ge=1,le=1000),db: Session=Depends(get_db)):
    rows=db.scalars(select(SensorHealthSample).order_by(SensorHealthSample.observed_at.desc()).limit(limit)).all()
    latest={}
    for row in rows:
        key=(row.docker_host_id,row.service_name,row.instance_id)
        if key not in latest:
            latest[key]={'docker_host_id':row.docker_host_id,'service':row.service_name,'instance_id':row.instance_id,'counter_epoch':row.counter_epoch,
                'observed_at':row.observed_at,'received_at':row.received_at,'health':row.metrics}
    notification=dict(db.execute(select(NotificationDelivery.state,func.count()).group_by(NotificationDelivery.state)).all())
    oldest=db.scalar(select(func.min(AssessmentJob.window_end)).where(AssessmentJob.state.in_(['pending','claimed'])))
    worker=getattr(request.app.state,'notification_worker',None)
    return {'notification_worker':worker.snapshot() if worker else {'running':False},'schema':'porygon.health-metrics','samples':list(latest.values()),'notification_states':notification,
        'assessment_oldest_pending_end':oldest,'source_completeness':'unknown',
        'metric_labels':['service'],'clock_skew_seconds_max':max([abs((utc(row.received_at)-utc(row.observed_at)).total_seconds()) for row in rows] or [0])}
