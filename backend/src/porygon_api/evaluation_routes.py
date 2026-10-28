"""Bounded argument-free exact-target snapshots for offline frozen-study replay."""
from datetime import datetime,timezone
from pathlib import PurePosixPath
from fastapi import APIRouter,Depends,HTTPException
from pydantic import BaseModel,ConfigDict,Field,model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session
from porygon_api.db import get_db
from porygon_api.models import ProcessExecEvent,RuntimeEvent
from porygon_api.runtime_evidence import epoch_ns
from porygon_api.vulnerability import sha256_document
from porygon_api.security import require_operator_token

router=APIRouter(tags=['evaluation'])
PROCESS_FIELDS=('event_id','docker_host_id','container_id','time_nano','occurred_at','process_name','executable','parent_name','parent_executable','user_uid','parent_event_id')
RUNTIME_FIELDS=('event_id','docker_host_id','container_id','time_nano','occurred_at','event_type','action')


class SnapshotIn(BaseModel):
    model_config=ConfigDict(extra='forbid')
    docker_host_id: str=Field(min_length=1,max_length=128)
    container_id: str=Field(pattern=r'^[a-f0-9]{64}$')
    image_digest: str=Field(max_length=512,pattern=r'^[^\s@]+@sha256:[a-f0-9]{64}$')
    start: datetime
    end: datetime
    max_events: int=Field(default=100000,ge=1,le=100000)

    @model_validator(mode='after')
    def interval(self):
        if self.start.tzinfo is None or self.end.tzinfo is None or not 0<(self.end-self.start).total_seconds()<=86400:
            raise ValueError('Aware ordered interval within one day required')
        return self


@router.post('/operator/v1/evaluation-snapshots',dependencies=[Depends(require_operator_token)])
def export_snapshot(payload: SnapshotIn,db: Session=Depends(get_db)):
    output={}
    for name,model,fields in (('process',ProcessExecEvent,PROCESS_FIELDS),('runtime',RuntimeEvent,RUNTIME_FIELDS)):
        rows=list(db.scalars(select(model).where(model.docker_host_id==payload.docker_host_id,
            model.container_id==payload.container_id,model.image_digest==payload.image_digest,
            model.time_nano>=epoch_ns(payload.start),model.time_nano<epoch_ns(payload.end))
            .order_by(model.time_nano,model.event_id).limit(payload.max_events+1)))
        if len(rows)>payload.max_events:raise HTTPException(413,'Snapshot bound exceeded; no truncated evidence is exported')
        output[name]=[{key:(getattr(row,key).isoformat() if isinstance(getattr(row,key),datetime) else getattr(row,key)) for key in fields} for row in rows]
        if name=='process':
            from porygon_api.detection import _multicall_applet_from_cmdline
            allowed={'sh','ash','bash','dash','zsh','ksh','fish','id','cat','base64','sleep','printf','echo','uname','ps','head','ls','stat','find','awk','sed','grep','wc','true','false'}
            for row,item in zip(rows,output[name]):
                available=True
                for path_field,argument_field in (('executable','command_line'),('parent_executable','parent_command_line')):
                    base=PurePosixPath(getattr(row,path_field) or '').name
                    item[argument_field]=None
                    if base in {'busybox','toybox'}:
                        applet=_multicall_applet_from_cmdline(getattr(row,argument_field))
                        if applet in allowed:item[argument_field]=base+' '+applet
                        elif applet is not None:available=False
                item['rules_projection_available']=available
        else:
            for row,item in zip(rows,output[name]):
                item['command']=None
                item['image_digest']=row.image_digest
                privileged=(row.container_snapshot or {}).get('host_config',{}).get('privileged')
                item['container_snapshot']={'host_config':{'privileged':privileged if type(privileged) is bool else None}}

    document={'contract':'porygon.frozen-study-snapshot','scope':payload.model_dump(mode='json'),'events':output,
        'transformation':'whitelist only frozen behavioural fields; command arguments and raw payloads omitted',
        'capture_completeness':'unknown','captured_at':datetime.now(timezone.utc).isoformat(),
        'selected_id_set_sha256':sha256_document(sorted(row['event_id'] for rows in output.values() for row in rows)),
        'read_consistency':'two bounded channel queries; late arrivals after selection are excluded; no global completeness claim'}
    return dict(document,sha256=sha256_document(document))
