"""Read-only evidence replay and explicit advisory model administration."""
from datetime import datetime,timezone
from fastapi import APIRouter,Depends,HTTPException,Query
from pydantic import BaseModel,ConfigDict,Field
from sqlalchemy import select,update,func
from sqlalchemy.orm import Session
from porygon_api.db import get_db
from porygon_api.models import RuntimeEvidenceBundle,AdvisoryModel,ModelQualityLock
from porygon_api.auth import utc
from porygon_api.model_registry import ModelArtifact
from porygon_api.principals import audit_subject
from porygon_api.security import require_operator_token
from porygon_api.vulnerability import sha256_document

router=APIRouter(tags=['runtime-evidence'])


class RegisterModelIn(BaseModel):
    model_config=ConfigDict(extra='forbid')
    artifact: ModelArtifact
    evaluation_reference: str=Field(min_length=1,max_length=255)


class QualityCriteria(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,allow_inf_nan=False)
    minimum_recall: float=Field(ge=0,le=1)
    maximum_false_alerts_per_container_hour: float=Field(ge=0,le=1000000)
    comparator: str=Field(min_length=1,max_length=128)
    decision_reference: str=Field(min_length=1,max_length=255)


class HeldoutMetrics(BaseModel):
    model_config=ConfigDict(extra='allow',strict=True,allow_inf_nan=False)
    recall: float=Field(ge=0,le=1)
    false_alerts_per_container_hour: float=Field(ge=0,le=1000000)


class HeldoutReport(BaseModel):
    model_config=ConfigDict(extra='allow',strict=True,allow_inf_nan=False)
    contract: str=Field(pattern=r'^porygon.model-evaluation$')
    artifact_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    test_dataset_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    data_kind: str=Field(pattern=r'^independent-measured$')
    test_run_ids: list[str]=Field(min_length=1,max_length=10000)
    split_manifest_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    first_test_collection_at: str=Field(min_length=20,max_length=40)
    metrics: HeldoutMetrics
    passed_validation: bool


class PromoteModelIn(BaseModel):
    model_config=ConfigDict(extra='forbid')
    heldout_report: HeldoutReport
    report_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    quality_lock_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    comparison_report_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    review_reference: str=Field(min_length=1,max_length=255)


@router.get('/api/v1/runtime-evidence')
def list_evidence(limit: int=Query(100,ge=1,le=500),score_id: str | None=None,db: Session=Depends(get_db)):
    query=select(RuntimeEvidenceBundle)
    if score_id:
        query=query.where(RuntimeEvidenceBundle.score_id==score_id)
    rows=db.scalars(query.order_by(RuntimeEvidenceBundle.created_at.desc()).limit(limit)).all()
    return [{'bundle_hash':row.bundle_hash,'score_id':row.score_id,'contract':row.contract,
        'rules_hash':row.rules_hash,'created_at':row.created_at,'findings':len(row.document['findings']),
        'coverage':row.document['coverage'],'model_status':row.model_prediction['status']} for row in rows]


@router.get('/api/v1/runtime-evidence/{bundle_hash}')
def get_evidence(bundle_hash: str,db: Session=Depends(get_db)):
    row=db.get(RuntimeEvidenceBundle,bundle_hash)
    if row is None:
        raise HTTPException(404,'Runtime evidence bundle not found')
    return {'bundle':row.document,'features':row.feature_document,'model':row.model_prediction}


@router.post('/operator/v1/advisory-models',dependencies=[Depends(require_operator_token)])
def register_model(payload: RegisterModelIn,db: Session=Depends(get_db)):
    artifact=payload.artifact.model_dump()
    row=db.get(AdvisoryModel,payload.artifact.artifact_sha256)
    if row is None:
        row=AdvisoryModel(artifact_hash=payload.artifact.artifact_sha256,artifact=artifact,
            approved_by=audit_subject('trusted-local'),evaluation_reference=payload.evaluation_reference,
            active=False,created_at=datetime.now(timezone.utc))
        db.add(row);db.commit();db.refresh(row)
    return {'artifact_hash':row.artifact_hash,'active':row.active,'evaluation_reference':row.evaluation_reference}


@router.post('/operator/v1/advisory-models/{artifact_hash}/activate',dependencies=[Depends(require_operator_token)])
def activate_model(artifact_hash: str,payload: PromoteModelIn,db: Session=Depends(get_db)):
    if db.get_bind().dialect.name=='postgresql':
        db.execute(select(func.pg_advisory_xact_lock(728164115)))
    row=db.scalar(select(AdvisoryModel).where(AdvisoryModel.artifact_hash==artifact_hash).with_for_update())
    if row is None:
        raise HTTPException(404,'Advisory model not found')
    report=payload.heldout_report.model_dump()
    lock=db.get(ModelQualityLock,artifact_hash)
    try:
        first_test=datetime.fromisoformat(report['first_test_collection_at'])
        if first_test.tzinfo is None:raise ValueError('Timezone required')
    except ValueError as exc:
        raise HTTPException(422,'Heldout collection timestamp requires a timezone') from exc
    if (lock is None or lock.criteria_hash!=payload.quality_lock_sha256 or utc(lock.locked_at)>=first_test or
            report['metrics']['recall']<lock.criteria['minimum_recall'] or
            report['metrics']['false_alerts_per_container_hour']>lock.criteria['maximum_false_alerts_per_container_hour']):
        raise HTTPException(409,'Model promotion requires server-recorded pre-test criteria and comparator review')
    if (sha256_document(report)!=payload.report_sha256 or report['artifact_sha256']!=artifact_hash or
            report['passed_validation'] is not True or len(set(report['test_run_ids']))!=len(report['test_run_ids']) or
            sorted(report['test_run_ids'])!=sorted(row.artifact['provenance']['heldout_run_ids']) or
            report['split_manifest_sha256']!=row.artifact['provenance']['split_manifest_sha256']):
        raise HTTPException(409,'Promotion requires matching independently measured heldout evidence')
    db.execute(update(AdvisoryModel).values(active=False))
    row.active=True;row.approved_by=audit_subject('trusted-local')
    row.evaluation_reference=payload.review_reference+' report:'+payload.report_sha256
    db.commit()
    return {'artifact_hash':artifact_hash,'active':True,'advisory_only':True}


@router.post('/operator/v1/advisory-models/{artifact_hash}/quality-lock',dependencies=[Depends(require_operator_token)])
def lock_model_quality(artifact_hash: str,payload: QualityCriteria,db: Session=Depends(get_db)):
    if db.get(AdvisoryModel,artifact_hash) is None:raise HTTPException(404,'Model not found')
    document=payload.model_dump();digest=sha256_document(document)
    existing=db.get(ModelQualityLock,artifact_hash)
    if existing:
        if existing.criteria_hash!=digest:raise HTTPException(409,'Quality lock is immutable')
        return {'artifact_hash':artifact_hash,'criteria_hash':digest,'locked_at':existing.locked_at,'locked_by':existing.locked_by}
    row=ModelQualityLock(artifact_hash=artifact_hash,criteria_hash=digest,criteria=document,
        locked_by=audit_subject('trusted-local'),locked_at=datetime.now(timezone.utc))
    db.add(row);db.commit();db.refresh(row)
    return {'artifact_hash':artifact_hash,'criteria_hash':digest,'locked_at':row.locked_at,'locked_by':row.locked_by}
