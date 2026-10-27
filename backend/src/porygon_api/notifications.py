"""Transactional stable-ID notifications to operator-configured destinations only."""
from datetime import datetime,timezone
import hashlib
import json
import os
import stat
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4
from pydantic import BaseModel,ConfigDict,Field,SecretStr,model_validator
from sqlalchemy import select
from porygon_api.models import NotificationDelivery
from porygon_api.config import get_settings
from porygon_api.vulnerability import sha256_document

LEVELS={'low':0,'medium':1,'high':2,'critical':3}


class Destination(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    destination_id: str=Field(min_length=1,max_length=64,pattern=r'^[A-Za-z0-9_-]+$')
    url: str=Field(min_length=1,max_length=2048)
    hmac_secret: SecretStr=Field(min_length=32,max_length=512)
    minimum_severity: str=Field(default='high',pattern=r'^(low|medium|high|critical)$')
    allow_loopback: bool=False

    @model_validator(mode='after')
    def validate_url(self):
        value=urlsplit(self.url)
        if (value.scheme not in {'https','http'} or not value.hostname or value.username or value.password or
                value.query or value.fragment or (value.scheme=='http' and not (self.allow_loopback and value.hostname in {'127.0.0.1','::1'}))):
            raise ValueError('Webhook requires HTTPS without URL credentials or an explicit loopback sink')
        return self

    def configuration_hash(self):
        return sha256_document({'destination_id':self.destination_id,'url':self.url,
            'key_fingerprint':hashlib.sha256(self.hmac_secret.get_secret_value().encode()).hexdigest(),
            'minimum_severity':self.minimum_severity,'allow_loopback':self.allow_loopback})


def load_destinations(settings=None):
    settings=settings or get_settings()
    path=getattr(settings,'notification_config_file',None)
    if not path:return {}
    location=Path(path)
    descriptor=os.open(location,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size>65536 or info.st_mode & 0o077:
            raise ValueError('Notification configuration requires a private bounded regular file')
        content=os.read(descriptor,65537)
        if len(content)>65536:raise ValueError('Notification configuration exceeds bounded size')
    finally:os.close(descriptor)
    raw=json.loads(content)
    if not isinstance(raw,list) or len(raw)>16:
        raise ValueError('Notification destinations must be a bounded list')
    values=[Destination.model_validate(item) for item in raw]
    if len({value.destination_id for value in values})!=len(values):
        raise ValueError('Duplicate destination IDs')
    return {value.destination_id:value for value in values}


def enqueue_transition(db,incident,old_severity=None,settings=None):
    if old_severity==incident.severity_level:return []
    configuration_error=False
    try:destinations=load_destinations(settings)
    except (OSError,ValueError):
        destinations={};configuration_error=True
    incident.notification_revision=(incident.notification_revision or 0)+1
    revision=incident.notification_revision
    rows=[]
    if configuration_error:
        identifier=str(uuid4());created=datetime.now(timezone.utc)
        key=sha256_document({'incident':incident.incident_id,'revision':revision,'destination':'configuration-error'})
        row=NotificationDelivery(delivery_id=identifier,delivery_key=key,incident_id=incident.incident_id,
            revision=revision,destination_id='configuration-error',destination_config_hash='0'*64,
            payload_bytes=json.dumps({'delivery_id':identifier,'incident_id':incident.incident_id,'revision':revision,
                'severity_level':incident.severity_level,'previous_severity_level':old_severity,
                'type':'incident_created' if old_severity is None else 'incident_severity_changed',
                'confidence_level':incident.confidence_level,'created_at':created.isoformat()}),
            state='config_error',generation=0,attempts=0,error_category='configuration_invalid',created_at=created)
        db.add(row);return [row]
    for destination in destinations.values():
        if LEVELS[incident.severity_level]<LEVELS[destination.minimum_severity]:continue
        key=sha256_document({'incident':incident.incident_id,'revision':revision,'destination':destination.destination_id})
        existing=db.scalar(select(NotificationDelivery).where(NotificationDelivery.delivery_key==key))
        if existing:
            rows.append(existing);continue
        identifier=str(uuid4());created=datetime.now(timezone.utc)
        payload={'delivery_id':identifier,'incident_id':incident.incident_id,'revision':revision,
            'type':'incident_created' if old_severity is None else 'incident_severity_changed',
            'severity_level':incident.severity_level,'previous_severity_level':old_severity,
            'confidence_level':incident.confidence_level,'evidence_run_id':incident.latest_detection_run_id or incident.detection_run_id,
            'created_at':created.isoformat()}
        row=NotificationDelivery(delivery_id=identifier,delivery_key=key,incident_id=incident.incident_id,
            revision=revision,destination_id=destination.destination_id,destination_config_hash=destination.configuration_hash(),
            payload_bytes=json.dumps(payload,sort_keys=True,separators=(',',':')),state='pending',generation=0,
            attempts=0,created_at=created)
        db.add(row);rows.append(row)
    return rows
