"""Non-executable advisory models with exact contract, hash and provenance checks."""
from __future__ import annotations
import math
from datetime import date
from typing import Literal,Annotated
from pydantic import BaseModel,ConfigDict,Field,model_validator
from porygon_api.evidence_features import CONTRACT,FEATURE_NAMES,EvidenceFeatureDocument
from porygon_api.vulnerability import sha256_document


RunId=Annotated[str,Field(min_length=1,max_length=128,pattern=r'^[A-Za-z0-9_.:-]+$')]
Digest=Annotated[str,Field(pattern=r'^[a-f0-9]{64}$')]


class CollectionGroup(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    run_id: RunId
    family: RunId
    host_id: RunId
    release: RunId
    day: str=Field(pattern=r'^\d{4}-\d{2}-\d{2}$')
    image_digest: str=Field(max_length=512,pattern=r'^[^\s@]+@sha256:[a-f0-9]{64}$')

    @model_validator(mode='after')
    def valid_day(self):
        date.fromisoformat(self.day)
        return self


class ModelProvenance(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,allow_inf_nan=False)
    fit_run_ids: list[RunId]=Field(min_length=1,max_length=10000)
    calibration_run_ids: list[RunId]=Field(min_length=1,max_length=10000)
    heldout_run_ids: list[RunId]=Field(min_length=1,max_length=10000)
    split_manifest_sha256: Digest
    training_dataset_sha256: Digest
    heldout_plan_sha256: Digest
    heldout_plan: list[CollectionGroup]=Field(min_length=1,max_length=10000)
    training_groups: list[CollectionGroup]=Field(min_length=1,max_length=20000)
    label_source: Literal['independent-controller']
    seed: int=Field(ge=0,le=2147483647)
    dependencies: dict[str,Annotated[str,Field(min_length=1,max_length=128)]]=Field(min_length=1,max_length=32)
    evaluation_status: Literal['not-promoted','independent-heldout-reviewed']
    data_kind: Literal['synthetic-fixture','independent-measured']
    hyperparameters: dict[str,float | int]=Field(max_length=32)
    class_balance: dict[str,dict[str,int]]

    @model_validator(mode='after')
    def unique_runs(self):
        for values in (self.fit_run_ids,self.calibration_run_ids,self.heldout_run_ids):
            if len(set(values))!=len(values):
                raise ValueError('Duplicate model run IDs')
        fit,calibration,test=map(set,(self.fit_run_ids,self.calibration_run_ids,self.heldout_run_ids))
        if fit&calibration or fit&test or calibration&test:raise ValueError('Overlapping model partitions')
        training_ids=[row.run_id for row in self.training_groups]
        heldout_ids=[row.run_id for row in self.heldout_plan]
        if len(set(training_ids))!=len(training_ids) or set(training_ids)!=fit|calibration:
            raise ValueError('Training group identities differ from assigned runs')
        if len(set(heldout_ids))!=len(heldout_ids) or set(heldout_ids)!=test:
            raise ValueError('Heldout plan identities differ from assigned runs')
        if {row.family for row in self.training_groups}&{row.family for row in self.heldout_plan}:
            raise ValueError('Heldout family leakage')
        if max(row.day for row in self.training_groups)>=min(row.day for row in self.heldout_plan):
            raise ValueError('Heldout collection must follow training')
        physical={}
        for row in self.training_groups:
            partition='fit' if row.run_id in fit else 'calibration'
            key=(row.family,row.host_id,row.release,row.day)
            if key in physical and physical[key]!=partition:raise ValueError('Physical group leakage')
            physical[key]=partition
        splits={run:split for split,ids in (('fit',fit),('calibration',calibration),('test',test)) for run in ids}
        if sha256_document(splits)!=self.split_manifest_sha256:raise ValueError('Split manifest digest mismatch')
        if sha256_document([row.model_dump() for row in self.heldout_plan])!=self.heldout_plan_sha256:
            raise ValueError('Heldout plan digest mismatch')
        if set(self.class_balance)!={'fit','calibration'}:raise ValueError('Class counts must exclude test outcomes')
        for split,ids in (('fit',fit),('calibration',calibration)):
            counts=self.class_balance[split]
            if set(counts)!={'benign','attack'} or any(type(n) is not int or n<1 for n in counts.values()) or sum(counts.values())!=len(ids):
                raise ValueError('Invalid training class counts')
        return self


class ModelArtifact(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,allow_inf_nan=False)
    kind: Literal['run-logistic']
    feature_contract: Literal['porygon.evidence-features']
    feature_names: list[str]
    means: list[float]
    scales: list[float]
    weights: list[float]
    intercept: float
    calibration_slope: float
    calibration_intercept: float
    threshold: float=Field(ge=0,le=1)
    provenance: dict
    artifact_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')

    @model_validator(mode='after')
    def validate_contract(self):
        if self.feature_names!=list(FEATURE_NAMES) or any(len(value)!=len(FEATURE_NAMES) for value in (self.means,self.scales,self.weights)):
            raise ValueError('Model feature schema mismatch')
        if any(value<=0 for value in self.scales) or any(abs(value)>1e6 for value in [*self.means,*self.scales,*self.weights,self.intercept,self.calibration_slope,self.calibration_intercept]):
            raise ValueError('Model coefficients outside bounded numeric contract')
        ModelProvenance.model_validate(self.provenance)
        required={'fit_run_ids','calibration_run_ids','heldout_run_ids','split_manifest_sha256','label_source','training_dataset_sha256','heldout_plan_sha256','heldout_plan','training_groups','seed','dependencies','evaluation_status'}
        if not required<=set(self.provenance) or self.provenance.get('label_source')!='independent-controller':
            raise ValueError('Model lacks independent run-label provenance')
        if sha256_document(self.provenance['heldout_plan'])!=self.provenance['heldout_plan_sha256']:
            raise ValueError('Heldout plan digest mismatch')
        groups=[set(self.provenance[key]) for key in ('fit_run_ids','calibration_run_ids','heldout_run_ids')]
        if not all(groups) or any(groups[i]&groups[j] for i,j in ((0,1),(0,2),(1,2))):
            raise ValueError('Model run partitions overlap or are empty')
        document=self.model_dump(exclude={'artifact_sha256'})
        if sha256_document(document)!=self.artifact_sha256:
            raise ValueError('Model artifact digest mismatch')
        return self


def sigmoid(value):
    return 1/(1+math.exp(-max(-700,min(700,value))))


def predict(document,artifact=None):
    if artifact is None:
        return {'status':'model_unavailable','feature_contract':CONTRACT,'kind':None}
    model=ModelArtifact.model_validate(artifact)
    document=EvidenceFeatureDocument.model_validate(document).model_dump()
    if document.get('contract')!=model.feature_contract:
        raise ValueError('Incompatible evidence feature contract')
    if (document.get('identity_coverage',{}).get('unavailable_identity_events',1) or
            any(value=='unavailable' for value in document.get('observations',{}).values())):
        return {'status':'insufficient_data','kind':model.kind,'artifact_sha256':model.artifact_sha256}
    raw=[math.log1p(float(document['values'][key])) for key in FEATURE_NAMES]
    contributions={key:model.weights[i]*(raw[i]-model.means[i])/model.scales[i] for i,key in enumerate(FEATURE_NAMES)}
    raw_logit=model.intercept+sum(contributions.values())
    calibrated_logit=model.calibration_slope*raw_logit+model.calibration_intercept
    probability=sigmoid(calibrated_logit)
    return {'status':'advisory','kind':model.kind,'artifact_sha256':model.artifact_sha256,
        'feature_contract':CONTRACT,'probability':probability,'threshold':model.threshold,
        'positive':probability>=model.threshold,'training_provenance':model.provenance,
        'explanation':{'method':'linear-additive','output_space':'raw-logit',
            'intercept':model.intercept,'contributions':contributions,'raw_logit':raw_logit,
            'display_transform':'sigmoid(calibration_slope * raw_logit + calibration_intercept)'},
        'calibration_status':'fitted-on-calibration-runs; heldout validation required'}
