"""Admin enrollment stores hashes and returns metadata, never bearer secrets."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import secrets

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from porygon_api.auth import token_digest, utc
from porygon_api.config import get_settings
from porygon_api.db import get_db
from porygon_api.models import ApiCredential
from porygon_api.permissions import ROLE_PERMISSIONS, SERVICE_PURPOSES
from porygon_api.principals import Principal
from porygon_api.security import require_operator_token

router = APIRouter(tags=['credentials'], dependencies=[Depends(require_operator_token)])


class CredentialEnrollIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    token: SecretStr = Field(min_length=43, max_length=512)
    subject: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:@/-]*$')
    kind: str = Field(pattern=r'^(operator|service)$')
    roles: list[str] = Field(default_factory=list, max_length=4)
    scopes: list[str] = Field(default_factory=list, max_length=8)
    host_ids: list[str] = Field(default_factory=list, max_length=1)
    service_name: str | None = Field(default=None, max_length=64)
    instance_id: str | None = Field(default=None, max_length=128)
    expires_at: datetime | None = None

    @field_validator('token')
    @classmethod
    def token_format(cls, value):
        raw = value.get_secret_value()
        if not raw.isascii() or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in raw):
            raise ValueError('Credential material must be URL-safe random bytes')
        return value

    @field_validator('expires_at')
    @classmethod
    def expiry(cls, value):
        if value is not None:
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError('Expiry requires a timezone')
            if value <= datetime.now(timezone.utc):
                raise ValueError('Expiry must be in the future')
        return value

    @model_validator(mode='after')
    def binding(self):
        if self.kind == 'operator':
            if not self.roles or not set(self.roles) <= ROLE_PERMISSIONS.keys():
                raise ValueError('Operator requires known human roles')
            if self.scopes or self.host_ids or self.service_name or self.instance_id:
                raise ValueError('Human credentials cannot carry service bindings')
        else:
            if self.roles or self.service_name not in SERVICE_PURPOSES or not self.instance_id:
                raise ValueError('Service requires a known purpose and instance, without human roles')
            if not self.scopes or not set(self.scopes) <= SERVICE_PURPOSES[self.service_name]:
                raise ValueError('Scopes must match the enrolled service purpose')
            if not self.host_ids or any(not isinstance(h,str) or not 1 <= len(h) <= 128 or h == 'auto' for h in self.host_ids):
                raise ValueError('Service requires explicit host assignments')
        return self


class CredentialRotateIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    token: SecretStr = Field(min_length=43, max_length=512)
    overlap_seconds: int = Field(default=0, ge=0, le=3600)

    @field_validator('token')
    @classmethod
    def token_format(cls, value):
        return CredentialEnrollIn.token_format(value)


class CredentialOut(BaseModel):
    credential_id: str
    fingerprint: str
    subject: str
    kind: str
    roles: list[str]
    scopes: list[str]
    host_ids: list[str]
    service_name: str | None
    instance_id: str | None
    created_at: datetime
    created_by: str
    expires_at: datetime | None
    revoked_at: datetime | None
    revoked_by: str | None
    replaces_credential_id: str | None


def describe(row):
    return CredentialOut(**{field:getattr(row,field) for field in CredentialOut.model_fields
                            if field != 'fingerprint'}, fingerprint=row.token_sha256[:16])


def validate_new_material(material):
    settings = get_settings()
    if any(secrets.compare_digest(material, secret.get_secret_value()) for secret in
           (settings.internal_api_token, settings.operator_api_token)):
        raise HTTPException(422, 'Shared compatibility credentials cannot be enrolled')


@router.get('/operator/v1/credentials', response_model=list[CredentialOut])
def list_credentials(limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)):
    return [describe(row) for row in db.scalars(select(ApiCredential).order_by(
        ApiCredential.created_at, ApiCredential.credential_id).limit(limit)).all()]


@router.post('/operator/v1/credentials', response_model=CredentialOut, status_code=201)
def enroll_credential(payload: CredentialEnrollIn, db: Session = Depends(get_db),
                      principal: Principal = Depends(require_operator_token)):
    validate_new_material(payload.token.get_secret_value())
    values = payload.model_dump(exclude={'token'})
    row = ApiCredential(**values, credential_id=str(uuid4()),
                        token_sha256=token_digest(payload.token.get_secret_value()),
                        created_at=datetime.now(timezone.utc), created_by=principal.subject)
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, 'Credential material is already enrolled') from exc
    db.refresh(row)
    return describe(row)


@router.post('/operator/v1/credentials/{credential_id}/revoke', response_model=CredentialOut)
def revoke_credential(credential_id: str, db: Session = Depends(get_db),
                      principal: Principal = Depends(require_operator_token)):
    row = db.scalar(select(ApiCredential).where(ApiCredential.credential_id == credential_id).with_for_update())
    if row is None:
        raise HTTPException(404, 'Credential not found')
    if row.revoked_at is None:
        row.revoked_at = datetime.now(timezone.utc)
        row.revoked_by = principal.subject
        db.commit()
        db.refresh(row)
    return describe(row)


@router.post('/operator/v1/credentials/{credential_id}/rotate', response_model=CredentialOut)
def rotate_credential(credential_id: str, payload: CredentialRotateIn,
                      db: Session = Depends(get_db), principal: Principal = Depends(require_operator_token)):
    validate_new_material(payload.token.get_secret_value())
    old = db.scalar(select(ApiCredential).where(ApiCredential.credential_id == credential_id).with_for_update())
    if old is None:
        raise HTTPException(404, 'Credential not found')
    digest = token_digest(payload.token.get_secret_value())
    if secrets.compare_digest(digest, old.token_sha256):
        raise HTTPException(422, 'Rotation requires new credential material')
    existing = db.scalar(select(ApiCredential).where(ApiCredential.replaces_credential_id == credential_id))
    if existing is not None:
        if secrets.compare_digest(existing.token_sha256, digest):
            return describe(existing)
        raise HTTPException(409, 'Credential already has a replacement')
    now = datetime.now(timezone.utc)
    if old.revoked_at is not None or (old.expires_at is not None and utc(old.expires_at) <= now):
        raise HTTPException(409, 'Inactive credentials cannot be rotated')
    replacement = ApiCredential(
        credential_id=str(uuid4()), token_sha256=digest, subject=old.subject, kind=old.kind,
        roles=list(old.roles), scopes=list(old.scopes), host_ids=list(old.host_ids),
        service_name=old.service_name, instance_id=old.instance_id,
        created_at=now, created_by=principal.subject, expires_at=old.expires_at,
        replaces_credential_id=old.credential_id)
    cutoff = now + timedelta(seconds=payload.overlap_seconds)
    old.expires_at = min(utc(old.expires_at), cutoff) if old.expires_at else cutoff
    db.add(replacement)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, 'Credential material is already enrolled') from exc
    db.refresh(replacement)
    return describe(replacement)
