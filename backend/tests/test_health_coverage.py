"""Host identities and separately observed loss boundaries cannot collapse."""
from datetime import datetime,timedelta,timezone
from types import SimpleNamespace
from sqlalchemy.orm import Session
from test_assessment_service import engine as engine,assessment_engine as assessment_engine
from porygon_api.health_metrics import record_health,health_coverage
from porygon_api.models import SensorHealthSample


def heartbeat(host,sequence,when,*,source_epoch='falco:a',drops=0,output_drops=0):
    return SimpleNamespace(service_name='telemetry',instance_id='same-instance',observed_at=when,
        metadata={'docker_host_id':host,'health':{'counter_epoch':'adapter:a','sequence':sequence,'source_epoch':source_epoch,
            'source_loss':'unknown','metrics':{'falco_drops':float(drops),'falco_output_drops':float(output_drops)}}})


def test_same_instance_sequences_are_independent_on_two_hosts(assessment_engine):
    now=datetime.now(timezone.utc)
    with Session(assessment_engine) as db:
        left=record_health(db,heartbeat('left',1,now));right=record_health(db,heartbeat('right',1,now));db.commit()
        assert left.sample_id!=right.sample_id
        assert len(db.query(SensorHealthSample).all())==2


def test_output_loss_has_its_own_boundary(assessment_engine):
    start=datetime.now(timezone.utc);end=start+timedelta(seconds=60)
    with Session(assessment_engine) as db:
        record_health(db,heartbeat('left',1,start,output_drops=1))
        record_health(db,heartbeat('left',2,end,output_drops=3));db.commit()
        result=health_coverage(db,'left',start,end)
        assert result['source_loss']=='known-loss'
        assert result['boundaries']['falco_output_drop_delta']==2
        assert result['boundaries']['falco_kernel_drop_delta']==0


def test_source_epoch_change_is_explicit_and_not_zero_loss(assessment_engine):
    start=datetime.now(timezone.utc);end=start+timedelta(seconds=60)
    with Session(assessment_engine) as db:
        record_health(db,heartbeat('left',1,start));record_health(db,heartbeat('left',2,end,source_epoch='falco:b'));db.commit()
        result=health_coverage(db,'left',start,end)
        assert 'telemetry_source_epoch_changed' in result['reasons']
        assert result['source_loss']=='unknown'


def test_legacy_sample_identifier_replays_by_full_natural_host_identity(assessment_engine):
    now=datetime.now(timezone.utc)
    with Session(assessment_engine) as db:
        original=record_health(db,heartbeat('left',1,now));db.flush()
        original.sample_id='f'*64;db.commit()
        replayed=record_health(db,heartbeat('left',1,now));db.commit()
        assert replayed.sample_id=='f'*64 and len(db.query(SensorHealthSample).all())==1
