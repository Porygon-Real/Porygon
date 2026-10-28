"""Read-only evidence replay and explicit advisory model administration."""
from datetime import datetime,timezone
from fastapi import APIRouter,Depends,HTTPException,Query
from pydantic import BaseModel,ConfigDict,Field,model_validator
from typing import Literal
from sqlalchemy import select,update,func
from sqlalchemy.orm import Session
from porygon_api.db import get_db
from porygon_api.models import RuntimeEvidenceBundle,AdvisoryModel,ModelQualityLock
from porygon_api.auth import utc
from porygon_api.model_registry import ModelArtifact,RunId
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


class SummaryMetrics(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,allow_inf_nan=False)
    recall: float | None=Field(default=None,ge=0,le=1)
    false_alerts_per_container_hour: float | None=Field(default=None,ge=0,le=1000000)
    precision: float | None=Field(default=None,ge=0,le=1)
    brier: float | None=Field(default=None,ge=0,le=1)
    log_loss: float | None=Field(default=None,ge=0,le=1000)
    independent_runs: int=Field(default=0,ge=0,le=10000)
    abstention: int=Field(default=0,ge=0,le=10000)
    coverage: float=Field(default=0,ge=0,le=1)


class HeldoutMetrics(SummaryMetrics):
    recall: float=Field(ge=0,le=1)
    false_alerts_per_container_hour: float=Field(ge=0,le=1000000)


class EvaluationRecord(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,allow_inf_nan=False)
    run_id: RunId
    family: RunId | None=None
    probability: float | None=Field(default=None,ge=0,le=1)
    label: Literal['benign','attack']
    ground_truth_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    positive: bool
    container_hours: float=Field(gt=0,le=8784)


def measured_metrics(records):
    attacks=sum(row.label=='attack' for row in records)
    hours=sum(row.container_hours for row in records if row.label=='benign')
    if not attacks or not hours:raise ValueError('Evaluation needs attack and benign exposure')
    return {
        'recall':sum(row.positive and row.label=='attack' for row in records)/attacks,
        'false_alerts_per_container_hour':sum(row.positive and row.label=='benign' for row in records)/hours,
    }


class HeldoutReport(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,allow_inf_nan=False)
    contract: str=Field(pattern=r'^porygon.model-evaluation$')
    artifact_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    test_dataset_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    data_kind: str=Field(pattern=r'^independent-measured$')
    test_run_ids: list[RunId]=Field(min_length=1,max_length=10000)
    split_manifest_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    first_test_collection_at: str=Field(min_length=20,max_length=40)
    metrics: HeldoutMetrics
    last_test_collection_at: str=Field(min_length=20,max_length=40)
    records: list[EvaluationRecord]=Field(min_length=1,max_length=10000)
    passed_validation: bool
    by_family: dict[RunId,SummaryMetrics]=Field(default_factory=dict,max_length=1000)
    promotion_eligible: bool=False
    promotion_status: str=Field(default='requires-predeclared-quality-comparison-and-human-review',max_length=255)

    @model_validator(mode='after')
    def validate_records(self):
        ids=[row.run_id for row in self.records]
        if len(set(ids))!=len(ids) or set(ids)!=set(self.test_run_ids):raise ValueError('Evaluation run accounting mismatch')
        actual=measured_metrics(self.records)
        if any(abs(actual[key]-getattr(self.metrics,key))>1e-12 for key in actual):raise ValueError('Metrics differ from run evidence')
        first=datetime.fromisoformat(self.first_test_collection_at)
        last=datetime.fromisoformat(self.last_test_collection_at)
        if first.tzinfo is None or last.tzinfo is None or first>last:raise ValueError('Aware ordered collection interval required')
        return self


class ComparatorReport(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,allow_inf_nan=False)
    comparator: str=Field(min_length=1,max_length=128)
    artifact_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    test_dataset_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    split_manifest_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    records: list[EvaluationRecord]=Field(min_length=1,max_length=10000)



class PromoteModelIn(BaseModel):
    model_config=ConfigDict(extra='forbid')
    heldout_report: HeldoutReport
    report_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    quality_lock_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    comparison_report: ComparatorReport
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
    if row.artifact['provenance']['data_kind']!='independent-measured':
        raise HTTPException(409,'Synthetic training artifacts cannot be promoted')
    report=payload.heldout_report.model_dump()
    lock=db.get(ModelQualityLock,artifact_hash)
    try:
        first_test=datetime.fromisoformat(report['first_test_collection_at'])
        if first_test.tzinfo is None or datetime.fromisoformat(report['last_test_collection_at'])>datetime.now(timezone.utc):raise ValueError('Completed aware collection required')
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
    comparison=payload.comparison_report.model_dump()
    if (sha256_document(comparison)!=payload.comparison_report_sha256 or
            comparison['comparator']!=lock.criteria['comparator'] or
            any(comparison[key]!=report[key] for key in ('artifact_sha256','test_dataset_sha256','split_manifest_sha256'))):
        raise HTTPException(409,'Comparator must bind the same model and heldout collection')
    truth=lambda records:{item.run_id:(item.label,item.ground_truth_sha256,item.container_hours) for item in records}
    if (len({item.run_id for item in payload.comparison_report.records})!=len(payload.comparison_report.records) or
            truth(payload.comparison_report.records)!=truth(payload.heldout_report.records)):
        raise HTTPException(409,'Comparator run accounting or independent ground truth differs')
    comparator_metrics=measured_metrics(payload.comparison_report.records)
    # A human authorizes the tradeoff; persist the exact supplied measured evidence.
    from porygon_api.models import ModelPromotionReview
    review_document={'model_report':report,'comparison_report':comparison,
        'quality_lock_sha256':payload.quality_lock_sha256,'review_reference':payload.review_reference,
        'comparator_metrics':comparator_metrics,'reviewed_by':audit_subject('trusted-local')}
    review_hash=sha256_document(review_document)
    if db.get(ModelPromotionReview,review_hash) is None:
        db.add(ModelPromotionReview(review_hash=review_hash,artifact_hash=artifact_hash,
            document=review_document,reviewed_by=audit_subject('trusted-local'),reviewed_at=datetime.now(timezone.utc)))
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
