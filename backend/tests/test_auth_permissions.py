"""Local authentication subjects are derived from credentials, never request names."""
import asyncio
import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from fastapi import HTTPException
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from porygon_api.models import Incident, IncidentEvidence
from test_incident_grouping import engine as _disposable_engine
from test_incident_transitions import seed

from porygon_api import main, security
from porygon_api.principals import LOCAL_INTERNAL_PRINCIPAL, LOCAL_OPERATOR_PRINCIPAL

engine = _disposable_engine


@pytest.fixture
def settings(monkeypatch):
    value = SimpleNamespace(internal_api_token=SecretStr('i' * 32),
                            operator_api_token=SecretStr('o' * 32))
    monkeypatch.setattr(security, 'get_settings', lambda: value)
    return value


def test_verified_subject_depends_only_on_the_authenticated_credential(settings):
    assert security.require_internal_token('i' * 32) == LOCAL_INTERNAL_PRINCIPAL
    assert security.require_operator_token('o' * 32) == LOCAL_OPERATOR_PRINCIPAL
    assert LOCAL_INTERNAL_PRINCIPAL != LOCAL_OPERATOR_PRINCIPAL


@pytest.mark.parametrize('check,token', [
    (security.require_operator_token, 'i' * 32),
    (security.require_internal_token, 'o' * 32),
    (security.require_internal_token, 'invalid'),
])
def test_wrong_credentials_never_produce_a_principal(settings, check, token):
    with pytest.raises(HTTPException) as failure:
        check(token)
    assert failure.value.status_code == 401


def test_status_routes_bind_the_corresponding_verified_principal_dependency():
    wanted = {
        '/internal/v1/incidents/{incident_id}/status': security.require_internal_token,
        '/operator/v1/incidents/{incident_id}/status': security.require_operator_token,
        '/operator/v1/incidents/clean-all': security.require_operator_token,
    }
    for path, dependency in wanted.items():
        route = next(route for route in main.app.routes if getattr(route, 'path', None) == path)
        named = {item.name: item.call for item in route.dependant.dependencies if item.name}
        assert named['principal'] is dependency


def post(path, payload, headers, method="POST"):
    """Exercise the actual ASGI dependency/router stack without a test-client dependency."""
    parsed = urlsplit(path)
    body = json.dumps(payload).encode()
    response = []
    sent = False
    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}
    async def send(message):
        response.append(message)
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": parsed.path,
        "raw_path": parsed.path.encode(), "query_string": parsed.query.encode(),
        "root_path": "", "server": ("test", 80), "client": ("127.0.0.1", 1234),
        "headers": [(b"content-type", b"application/json")] + [
            (key.lower().encode(), value.encode()) for key, value in headers.items()],
    }
    asyncio.run(main.app(scope, receive, send))
    start = next(message for message in response if message['type'] == 'http.response.start')
    raw = b''.join(message.get('body', b'') for message in response
                   if message['type'] == 'http.response.body')
    return start['status'], json.loads(raw)


@pytest.fixture
def database_override(engine):
    def dependency():
        with Session(engine) as db:
            yield db
    original = dict(main.app.dependency_overrides)
    main.app.dependency_overrides[main.get_db] = dependency
    try:
        yield engine
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(original)


@pytest.mark.parametrize('endpoint,headers,expected', [
    ('single', {}, 422),
    ('single', {'X-Porygon-Operator-Token': 'i' * 32}, 401),
    ('single', {'X-Porygon-Operator-Token': 'invalid'}, 401),
    ('bulk', {}, 422),
    ('bulk', {'X-Porygon-Operator-Token': 'i' * 32}, 401),
])
def test_http_rejected_requests_never_change_incidents_or_evidence(
        settings, database_override, endpoint, headers, expected):
    with Session(database_override) as db:
        identifier = seed(db)[0]
        before = db.scalar(select(func.count()).select_from(IncidentEvidence))
    path = ('/operator/v1/incidents/clean-all' if endpoint == 'bulk'
            else f'/operator/v1/incidents/{identifier}/status')
    status_code, _ = post(path, {'status': 'resolved', 'actor': 'claimed-person'}, headers)
    assert status_code == expected
    with Session(database_override) as db:
        assert db.get(Incident, identifier).status == 'open'
        assert db.scalar(select(func.count()).select_from(IncidentEvidence)) == before


def test_http_actor_override_is_ignored_and_replay_does_not_duplicate_evidence(
        settings, database_override):
    with Session(database_override) as db:
        identifier = seed(db)[0]
    path = f'/operator/v1/incidents/{identifier}/status'
    payload = {'status': 'resolved', 'actor': 'claimed-person', 'note': 'Reviewed evidence'}
    for _ in range(2):
        status_code, result = post(path, payload, {'X-Porygon-Operator-Token': 'o' * 32})
        assert status_code == 200
        assert result['closed_by'] == LOCAL_OPERATOR_PRINCIPAL.subject
    with Session(database_override) as db:
        items = db.scalars(select(IncidentEvidence).where(
            IncidentEvidence.incident_id == identifier,
            IncidentEvidence.evidence_type == 'status_change')).all()
        assert len(items) == 1
        assert items[0].details['actor'] == LOCAL_OPERATOR_PRINCIPAL.subject
        assert items[0].details['note'] == 'Reviewed evidence'


def test_http_bulk_is_bounded_and_invalid_limits_do_not_mutate(settings, database_override):
    with Session(database_override) as db:
        seed(db, 3)
        before = db.scalar(select(func.count()).select_from(IncidentEvidence))
    headers = {'X-Porygon-Operator-Token': 'o' * 32}
    status_code, _ = post('/operator/v1/incidents/clean-all?limit=0', {}, headers)
    assert status_code == 422
    with Session(database_override) as db:
        assert db.scalar(select(func.count()).select_from(IncidentEvidence)) == before
    status_code, result = post('/operator/v1/incidents/clean-all?limit=2', {}, headers)
    assert status_code == 200
    assert result['resolved_count'] == 2 and result['more_pending'] is True
    with Session(database_override) as db:
        resolved = db.scalars(select(Incident).where(Incident.status == 'resolved')).all()
        assert len(resolved) == 2
        assert all(item.closed_by == LOCAL_OPERATOR_PRINCIPAL.subject for item in resolved)


@pytest.mark.parametrize('provider', ['gemini', 'openai'])
@pytest.mark.parametrize('model', [None, ''])
def test_explicit_blank_ai_model_preserves_provider_default(monkeypatch, provider, model):
    from porygon_api import ai_auditor
    calls = []
    def call_provider(_api_key, selected_model, _prompt):
        calls.append(selected_model)
        return {'ai_risk_score': 0.2, 'threat_level': 'low', 'confidence': 0.4,
                'summary': 'Controlled provider fixture',
                'semantic_analysis': 'No operational recommendation from this fixture.',
                'flagged_commands': [], 'containment_suggestions': []}
    monkeypatch.setattr(ai_auditor, '_call_' + provider, call_provider)
    result = ai_auditor.perform_container_audit(
        container_info={'container_id': 'test'}, events=[], porygon_drift_score=None,
        matched_rules=[], cves=[], provider=provider, api_key='test-only', model=model)
    assert calls == [ai_auditor.DEFAULT_MODELS[provider]]
    assert result.model == ai_auditor.DEFAULT_MODELS[provider]
