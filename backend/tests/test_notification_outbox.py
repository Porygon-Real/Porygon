from datetime import datetime,timedelta,timezone
from types import SimpleNamespace
import pytest
from sqlalchemy import select,func
from sqlalchemy.orm import Session,sessionmaker
from test_incident_grouping import engine as engine,window
from porygon_api.models import Incident,NotificationDelivery
from porygon_api.notifications import Destination,enqueue_transition,load_destinations
from porygon_api.notification_worker import NotificationWorker


def settings():
    return SimpleNamespace(notification_max_attempts=3,notification_lease_seconds=60,notification_batch_size=1,notification_timeout_seconds=1,notification_config_file=None)


def destination():return Destination(destination_id='local',url='http://127.0.0.1:8888/events',allow_loopback=True,hmac_secret='x'*32)


def queued(engine,monkeypatch):
    monkeypatch.setattr('porygon_api.notifications.load_destinations',lambda *args:{'local':destination()})
    monkeypatch.setattr('porygon_api.notification_worker.load_destinations',lambda *args:{'local':destination()})
    with Session(engine) as db:
        identifier,_,_=window(db,1)
        row=db.scalar(select(NotificationDelivery))
        assert row is not None
        return identifier,row.delivery_id


def test_severity_transaction_rollback_does_not_emit_a_transition(engine,monkeypatch):
    identifier,delivery_id=queued(engine,monkeypatch)
    with Session(engine) as db:
        incident=db.get(Incident,identifier);incident.severity_level='critical';enqueue_transition(db,incident,'high');db.flush();db.rollback()
        assert db.scalar(select(func.count()).select_from(NotificationDelivery))==1
        assert db.get(Incident,identifier).severity_level=='high'


def test_crash_after_send_redelivers_same_id_and_fences_old_claim(engine,monkeypatch):
    _,identifier=queued(engine,monkeypatch);factory=sessionmaker(engine,expire_on_commit=False)
    worker=NotificationWorker(settings(),factory)
    first=worker.claim();assert first[0]==identifier
    with factory() as db:
        row=db.get(NotificationDelivery,identifier);row.lease_expires_at=datetime.now(timezone.utc)-timedelta(seconds=1);db.commit()
    second=worker.claim();assert second[0]==identifier and second[1]>first[1]
    assert not worker.finish(first[0],first[1],success=True)
    assert worker.finish(second[0],second[1],success=True)


def test_retry_exhaustion_is_durable_and_payload_has_no_arguments(engine,monkeypatch):
    _,identifier=queued(engine,monkeypatch);configuration=settings();configuration.notification_max_attempts=1
    def fail(*args):raise OSError('local sink unavailable')
    worker=NotificationWorker(configuration,sessionmaker(engine,expire_on_commit=False),sender=fail);worker.run_once()
    with Session(engine) as db:
        row=db.get(NotificationDelivery,identifier)
        assert row.state=='dead_letter' and row.attempts==1
        assert 'command_line' not in row.payload_bytes and 'hmac_secret' not in row.payload_bytes


def test_invalid_configuration_cannot_rollback_incident_creation(engine,monkeypatch):
    monkeypatch.setattr('porygon_api.notifications.load_destinations',lambda *args:(_ for _ in ()).throw(ValueError('invalid')))
    with Session(engine) as db:
        identifier,_,_=window(db,1)
        assert db.get(Incident,identifier) is not None
        assert db.scalar(select(NotificationDelivery)).state=='config_error'


def test_fifo_and_malformed_port_are_refused_without_reading(tmp_path):
    import os
    fifo=tmp_path/'destinations';os.mkfifo(fifo,0o600)
    with pytest.raises(ValueError):load_destinations(SimpleNamespace(notification_config_file=str(fifo)))
    with pytest.raises(ValueError):Destination(destination_id='bad',url='https://example.com:broken/events',connect_ip='1.1.1.1',hmac_secret='x'*32)
