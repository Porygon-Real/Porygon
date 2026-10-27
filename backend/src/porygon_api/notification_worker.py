"""Fenced at-least-once webhook delivery; receiver deduplicates stable IDs."""
from datetime import datetime,timedelta,timezone
import argparse
import hashlib
import hmac
import logging
import json
import http.client
from ipaddress import ip_address
import secrets
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit
from uuid import uuid4
from fastapi import APIRouter,Depends,Query
from sqlalchemy import select,or_,and_
from sqlalchemy.orm import Session
from porygon_api.auth import utc
from porygon_api.config import get_settings
from porygon_api.db import SessionLocal,get_db
from porygon_api.models import NotificationDelivery
from porygon_api.notifications import load_destinations,LEVELS
from porygon_api.security import require_operator_token
from porygon_api.principals import audit_subject
from porygon_api.vulnerability import sha256_document

router=APIRouter(tags=['notifications'])
logger=logging.getLogger('porygon.notifications')


def webhook_headers(delivery_id,payload,secret,timestamp=None):
    timestamp=str(int(time.time()) if timestamp is None else timestamp)
    signature=hmac.new(secret.encode(),timestamp.encode()+b'.'+payload,hashlib.sha256).hexdigest()
    return {'Content-Type':'application/json','X-Porygon-Delivery-ID':delivery_id,
        'X-Porygon-Timestamp':timestamp,'X-Porygon-Signature':'sha256='+signature}


def send_webhook(destination,delivery_id,payload,timeout=10):
    """Resolve once, validate egress, connect that address, verify TLS hostname."""
    parsed=urlsplit(destination.url);host=parsed.hostname;port=parsed.port or (443 if parsed.scheme=='https' else 80)
    addresses=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
    accepted=[]
    for family,_,_,_,address in addresses:
        ip=ip_address(address[0])
        if not ip.is_global and not (destination.allow_loopback and host in {'127.0.0.1','::1'} and ip.is_loopback):
            raise ValueError('Webhook egress address is not allowed')
        accepted.append((family,address))
    if not accepted:raise ValueError('No allowed webhook address')
    family,address=accepted[0]
    sock=socket.socket(family,socket.SOCK_STREAM);sock.settimeout(timeout)
    try:
        sock.connect(address)
        if parsed.scheme=='https':sock=ssl.create_default_context().wrap_socket(sock,server_hostname=host)
        connection=http.client.HTTPConnection(host,port,timeout=timeout);connection.sock=sock
        connection.request('POST',parsed.path or '/',body=payload,headers=webhook_headers(delivery_id,payload,destination.hmac_secret.get_secret_value()))
        response=connection.getresponse();response.read(4096)
        status=response.status;connection.close()
        if not 200<=status<300:
            raise ValueError('Webhook did not acknowledge delivery')
    finally:
        sock.close()


class NotificationWorker:
    def __init__(self,settings,session_factory=SessionLocal,sender=send_webhook):
        self.settings=settings;self.session_factory=session_factory;self.sender=sender
        self.owner='notifications-'+uuid4().hex;self.stop_event=threading.Event();self.thread=None
        self.errors=0;self.last_error_category=None;self.last_failure_at=None

    def claim(self,now=None):
        now=now or datetime.now(timezone.utc)
        with self.session_factory() as db:
            row=db.scalar(select(NotificationDelivery).where(or_(
                and_(NotificationDelivery.state=='pending',or_(NotificationDelivery.next_retry_at.is_(None),NotificationDelivery.next_retry_at<=now)),
                and_(NotificationDelivery.state=='claimed',NotificationDelivery.lease_expires_at<now)))
                .order_by(NotificationDelivery.created_at,NotificationDelivery.delivery_id).with_for_update(skip_locked=True).limit(1))
            if row is None:return None
            if row.attempts>=self.settings.notification_max_attempts:
                row.state='dead_letter';row.error_category='attempts_exhausted';db.commit();return None
            row.state='claimed';row.attempts+=1;row.generation+=1;row.lease_owner=self.owner
            row.lease_expires_at=now+timedelta(seconds=self.settings.notification_lease_seconds)
            snapshot=(row.delivery_id,row.generation,row.destination_id,row.destination_config_hash,row.payload_bytes.encode())
            db.commit();return snapshot

    def finish(self,identifier,generation,*,success,error=None):
        now=datetime.now(timezone.utc)
        with self.session_factory() as db:
            row=db.scalar(select(NotificationDelivery).where(NotificationDelivery.delivery_id==identifier).with_for_update())
            if (row is None or row.state!='claimed' or row.generation!=generation or row.lease_owner!=self.owner
                    or row.lease_expires_at is None or utc(row.lease_expires_at)<=now):return False
            if success:
                row.state='delivered';row.delivered_at=now;row.error_category=None
            else:
                row.state='dead_letter' if row.attempts>=self.settings.notification_max_attempts or error=='destination_changed' else 'pending'
                row.error_category=error or 'delivery_error'
                delay=min(3600,2**row.attempts)+secrets.randbelow(1000)/1000
                row.next_retry_at=now+timedelta(seconds=delay)
            row.lease_expires_at=None;db.commit();return True

    def run_once(self):
        destinations=load_destinations(self.settings)
        for _ in range(self.settings.notification_batch_size):
            claim=self.claim()
            if claim is None:break
            identifier,generation,destination_id,config_hash,payload=claim
            destination=destinations.get(destination_id)
            if destination is None or destination.configuration_hash()!=config_hash:
                self.finish(identifier,generation,success=False,error='destination_changed');continue
            try:
                self.sender(destination,identifier,payload,self.settings.notification_timeout_seconds)
            except Exception:
                self.finish(identifier,generation,success=False,error='delivery_error')
            else:self.finish(identifier,generation,success=True)

    def _run(self):
        while not self.stop_event.is_set():
            try:self.run_once()
            except Exception as error:
                self.errors+=1;self.last_error_category='worker_unavailable';self.last_failure_at=datetime.now(timezone.utc)
                logger.warning('Notification worker unavailable (%s); durable deliveries retained',type(error).__name__)
            self.stop_event.wait(self.settings.notification_poll_seconds)

    def snapshot(self):
        return {'running':bool(self.thread and self.thread.is_alive()),'error_count':self.errors,
            'last_error_category':self.last_error_category,'last_failure_at':self.last_failure_at}

    def start(self):
        self.thread=threading.Thread(target=self._run,name='porygon-notifications',daemon=True);self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:self.thread.join(timeout=15)


@router.get('/api/v1/notification-deliveries')
def list_deliveries(limit: int=Query(100,ge=1,le=500),db: Session=Depends(get_db)):
    rows=db.scalars(select(NotificationDelivery).order_by(NotificationDelivery.created_at.desc()).limit(limit)).all()
    return [{key:getattr(row,key) for key in ('delivery_id','incident_id','revision','destination_id','state','attempts','generation','error_category','created_at','delivered_at')}
        for row in rows]


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--once',action='store_true')
    args=parser.parse_args();worker=NotificationWorker(get_settings())
    if args.once:worker.run_once()
    else:
        try:worker._run()
        except KeyboardInterrupt:worker.stop()


if __name__=='__main__':main()


@router.post('/operator/v1/notification-deliveries/{delivery_id}/repair-config',dependencies=[Depends(require_operator_token)])
def repair_configuration(delivery_id: str,db: Session=Depends(get_db)):
    from fastapi import HTTPException
    row=db.scalar(select(NotificationDelivery).where(NotificationDelivery.delivery_id==delivery_id).with_for_update())
    if row is None:raise HTTPException(404,'Delivery not found')
    if row.state=='migrated':return {'delivery_id':delivery_id,'state':'migrated'}
    if row.state!='config_error':raise HTTPException(409,'Only configuration-error records use explicit repair')
    try:destinations=load_destinations()
    except (ValueError,OSError) as exc:raise HTTPException(409,'Notification configuration remains invalid') from exc
    if not destinations:raise HTTPException(409,'Configure an approved destination before repair')
    original=json.loads(row.payload_bytes)
    for destination in destinations.values():
        if LEVELS[original['severity_level']]<LEVELS[destination.minimum_severity]:continue
        key=sha256_document({'incident':row.incident_id,'revision':row.revision,'destination':destination.destination_id})
        if db.scalar(select(NotificationDelivery).where(NotificationDelivery.delivery_key==key)):continue
        identifier=str(uuid4());payload=dict(original,delivery_id=identifier,configuration_repaired_by=audit_subject('trusted-local'))
        db.add(NotificationDelivery(delivery_id=identifier,delivery_key=key,incident_id=row.incident_id,revision=row.revision,
            destination_id=destination.destination_id,destination_config_hash=destination.configuration_hash(),
            payload_bytes=json.dumps(payload,sort_keys=True,separators=(',',':')),state='pending',generation=0,attempts=0,
            created_at=datetime.now(timezone.utc)))
    row.state='migrated';row.error_category='configuration_repaired';db.commit()
    return {'delivery_id':delivery_id,'state':'migrated'}
