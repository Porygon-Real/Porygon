"""Opaque credential authentication and reset-safe HTTP authorization context."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import secrets

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.routing import Match

from porygon_api.db import SessionLocal, get_db
from porygon_api.models import ApiCredential
from porygon_api.permissions import authorization_routes, ROUTE_PERMISSIONS, require_permission
from porygon_api.principals import (
    CURRENT_PRINCIPAL, Principal, LOCAL_INTERNAL_PRINCIPAL, LOCAL_OPERATOR_PRINCIPAL,
)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


@contextmanager
def credential_session(app):
    """Resolve test overrides too; close the auth session before running a handler."""
    override = app.dependency_overrides.get(get_db)
    if override is not None:
        generator = override()
        try:
            yield next(generator)
        finally:
            generator.close()
    else:
        with SessionLocal() as db:
            yield db


def resolve_credential(token: str, app, *, allow_legacy: bool) -> Principal:
    # Resolve the configured provider at request time so credential rotation and
    # deterministic dependency fixtures do not depend on module import order.
    from porygon_api import security
    settings = security.get_settings()
    if allow_legacy:
        if secrets.compare_digest(token, settings.internal_api_token.get_secret_value()):
            return LOCAL_INTERNAL_PRINCIPAL
        if secrets.compare_digest(token, settings.operator_api_token.get_secret_value()):
            return LOCAL_OPERATOR_PRINCIPAL
    else:
        # A shared secret must never become an enrolled identity accidentally.
        if any(secrets.compare_digest(token, secret.get_secret_value()) for secret in
               (settings.internal_api_token, settings.operator_api_token)):
            raise HTTPException(401, 'Legacy credentials are disabled')
    try:
        with credential_session(app) as db:
            row = db.scalar(select(ApiCredential).where(ApiCredential.token_sha256 == token_digest(token)))
            now = datetime.now(timezone.utc)
            if row is None or row.revoked_at is not None or (row.expires_at and utc(row.expires_at) <= now):
                raise HTTPException(401, 'Invalid or expired credential')
            return Principal(row.subject, row.kind, tuple(row.roles), tuple(row.scopes), tuple(row.host_ids),
                             row.credential_id, row.service_name, row.instance_id, False)
    except SQLAlchemyError as exc:
        raise HTTPException(503, 'Credential verification unavailable') from exc


def request_token(request) -> str | None:
    candidates = [request.headers.get(name) for name in
                  ('x-porygon-internal-token','x-porygon-operator-token')]
    authorization = request.headers.get('authorization')
    if authorization:
        scheme, _, value = authorization.partition(' ')
        if scheme.lower() != 'bearer' or not value:
            raise HTTPException(401, 'Bearer credential required')
        candidates.append(value)
    candidates = [value for value in candidates if value]
    if len(set(candidates)) > 1:
        raise HTTPException(400, 'Conflicting credentials')
    token = candidates[0] if candidates else None
    if token is not None and (len(token) > 512 or not token.isascii()):
        raise HTTPException(401, 'Invalid credential')
    return token


def enforce_host(principal: Principal, host: str | None) -> str | None:
    if principal.legacy or principal.kind != 'service':
        return host
    if host is None or host == 'auto':
        if len(principal.host_ids) != 1:
            raise HTTPException(403, 'An explicit enrolled host is required')
        return principal.host_ids[0]
    if host not in principal.host_ids:
        raise HTTPException(403, 'Credential is not assigned to this host')
    return host


def enforce_instance(principal: Principal, instance: str | None) -> None:
    if not principal.legacy and principal.kind == 'service' and instance != principal.instance_id:
        raise HTTPException(403, 'Credential is not assigned to this service instance')


def bind_service_payload(principal: Principal, permission: str, body: dict) -> dict:
    if principal.legacy or principal.kind != 'service':
        return body
    if permission in {'ingest_runtime','ingest_process','ingest_kernel'}:
        field = 'docker_host_id' if permission == 'ingest_runtime' else 'reported_docker_host_id'
        events = body.get('events', [])
        if not isinstance(events, list):
            raise HTTPException(422, 'Events must be a list')
        for event in events:
            if not isinstance(event, dict):
                raise HTTPException(422, 'Event must be an object')
            event[field] = enforce_host(principal, event.get(field))
            if permission != 'ingest_runtime':
                enforce_instance(principal, event.get('sensor_instance_id'))
    elif permission == 'heartbeat':
        enforce_instance(principal, body.get('instance_id'))
        if body.get('service_name') != principal.service_name:
            raise HTTPException(403, 'Heartbeat service does not match enrollment')
        metadata = body.get('metadata', {})
        if not isinstance(metadata, dict):
            raise HTTPException(422, 'Heartbeat metadata must be an object')
        metadata['docker_host_id'] = enforce_host(principal, metadata.get('docker_host_id'))
        body['metadata'] = metadata
    elif permission == 'scan_worker':
        enforce_instance(principal, body.get('scanner_instance_id'))
        if 'docker_host_id' in body or 'scanner_name' in body:
            body['docker_host_id'] = enforce_host(principal, body.get('docker_host_id'))
        metadata = body.get('scanner_metadata')
        if isinstance(metadata, dict):
            metadata['docker_host_id'] = enforce_host(principal, metadata.get('docker_host_id'))
    elif permission == 'response_worker':
        enforce_instance(principal, body.get('executor_instance_id'))
    return body


def install_authentication(app):
    # Validation errors on enrollment must not echo rejected secret material.
    from fastapi.exceptions import RequestValidationError
    from fastapi.exception_handlers import request_validation_exception_handler

    @app.exception_handler(RequestValidationError)
    async def safe_credential_validation(request, exc):
        if request.url.path.startswith('/operator/v1/credentials'):
            return JSONResponse({'detail':[{'loc':list(item['loc']), 'type':item['type'],
                                           'msg':item['msg']} for item in exc.errors()]}, status_code=422)
        return await request_validation_exception_handler(request, exc)
    @app.middleware('http')
    async def authorize(request, call_next):
        token_context = None
        try:
            # Resolve the same path template as Starlette. Trailing-slash redirects
            # are authorized against their canonical target before redirecting.
            template = None
            for path in (request.scope['path'], request.scope['path'].rstrip('/') or '/'):
                scope = dict(request.scope, path=path)
                for route in authorization_routes(app):
                    match, _ = route.matches(scope)
                    if match == Match.FULL:
                        template = getattr(route, 'path', None)
                        break
                if template is not None:
                    break
            if template is None:
                return JSONResponse({'detail':'Not found'}, status_code=404)
            method = 'GET' if request.method == 'HEAD' else request.method
            permission = ROUTE_PERMISSIONS.get((method, template))
            if permission is None:
                return JSONResponse({'detail':'Route is not authorized'}, status_code=403)
            if permission == 'public':
                return await call_next(request)
            from porygon_api import security
            local = getattr(security.get_settings(), 'access_mode', 'local') == 'local'
            token = request_token(request)
            if token is None:
                if not local:
                    raise HTTPException(401, 'Authentication required')
                # Explicit laboratory compatibility; endpoint dependencies still
                # guard the historical internal/operator mutation boundaries.
                return await call_next(request)
            principal = await run_in_threadpool(resolve_credential, token, app, allow_legacy=local)
            require_permission(principal, permission, template)
            token_context = CURRENT_PRINCIPAL.set(principal)
            if principal.kind == 'service' and not principal.legacy and request.method in {'POST','PUT','PATCH'}:
                try:
                    raw_body = await request.body()
                    if len(raw_body) > 64 * 1024 * 1024:
                        raise HTTPException(413, 'Request body is too large')
                    body = json.loads(raw_body)
                except (ValueError, UnicodeError, RecursionError) as exc:
                    raise HTTPException(422, 'Invalid JSON') from exc
                if not isinstance(body, dict):
                    raise HTTPException(422, 'Request body must be an object')
                body = bind_service_payload(principal, permission, body)
                request._body = json.dumps(body, separators=(',', ':')).encode()
            return await call_next(request)
        except HTTPException as exc:
            return JSONResponse({'detail':exc.detail}, status_code=exc.status_code)
        finally:
            if token_context is not None:
                CURRENT_PRINCIPAL.reset(token_context)
