"""Incident transition consistency, atomicity and PostgreSQL row-lock regressions."""
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from porygon_api import main
from porygon_api.incident_transitions import resolve_incident_batch, transition_incident
from porygon_api.models import Incident, IncidentEvidence
from porygon_api.principals import LOCAL_INTERNAL_PRINCIPAL, LOCAL_OPERATOR_PRINCIPAL
from porygon_api.schemas import IncidentStatusUpdateIn
from test_incident_grouping import engine as _disposable_engine, window

engine = _disposable_engine


def seed(db, count=1):
    identifiers = []
    for index in range(1, count + 1):
        identifier, _, _ = window(db, index)
        incident = db.get(Incident, identifier)
        # Independent active episodes for bounded-batch tests, not a new scope rule.
        incident.grouping_key = None
        db.commit()
        identifiers.append(identifier)
    return identifiers


def status_evidence(db, incident_id):
    return list(db.scalars(select(IncidentEvidence).where(
        IncidentEvidence.incident_id == incident_id,
        IncidentEvidence.evidence_type == 'status_change',
    )).all())


def test_operator_transition_ignores_client_actor_and_retry_is_a_noop(engine):
    with Session(engine) as db:
        identifier = seed(db)[0]
        payload = IncidentStatusUpdateIn(status='resolved', actor='unverified-request-name',
                                         note='Investigation completed')
        main.operator_update_incident_status(identifier, payload, db, LOCAL_OPERATOR_PRINCIPAL)
        first = db.get(Incident, identifier)
        assert first.closed_by == LOCAL_OPERATOR_PRINCIPAL.subject
        assert first.closure_note == payload.note
        closed_at = first.closed_at
        updated_at = first.updated_at
        main.operator_update_incident_status(identifier, payload, db, LOCAL_OPERATOR_PRINCIPAL)
        entries = status_evidence(db, identifier)
        assert len(entries) == 1
        assert entries[0].details['actor'] == LOCAL_OPERATOR_PRINCIPAL.subject
        assert 'unverified-request-name' not in entries[0].summary
        assert first.closed_at == closed_at and first.updated_at == updated_at


def test_trusted_in_process_call_gets_service_identity_not_payload_actor(engine):
    with Session(engine) as db:
        identifier = seed(db)[0]
        main.update_incident_status(identifier,
                                    IncidentStatusUpdateIn(status='acknowledged', actor='claimed'), db)
        assert db.get(Incident, identifier).acknowledged_by == LOCAL_INTERNAL_PRINCIPAL.subject


def test_failed_or_rolled_back_transition_does_not_leave_partial_evidence(engine):
    with Session(engine) as db:
        identifier = seed(db)[0]
        transition_incident(db, identifier, target_status='resolved',
                            principal=LOCAL_OPERATOR_PRINCIPAL, note='Controlled rollback')
        db.rollback()
    with Session(engine) as db:
        assert db.get(Incident, identifier).status == 'open'
        assert status_evidence(db, identifier) == []
        with pytest.raises(HTTPException) as failure:
            transition_incident(db, 'missing', target_status='resolved',
                                principal=LOCAL_OPERATOR_PRINCIPAL)
        assert failure.value.status_code == 404


def test_bulk_resolution_is_bounded_audited_and_updates_modified_time(engine):
    with Session(engine) as db:
        identifiers = seed(db, 3)
        before = {identifier: db.get(Incident, identifier).updated_at for identifier in identifiers}
        result = main.clean_all_incidents(db, limit=2, note='Reviewed batch',
                                         principal=LOCAL_OPERATOR_PRINCIPAL)
        assert result == {'resolved_count': 2, 'status': 'ok', 'more_pending': True,
                          'batch_limit': 2}
        closed = [db.get(Incident, identifier) for identifier in identifiers
                  if db.get(Incident, identifier).status == 'resolved']
        for incident in closed:
            entries = status_evidence(db, incident.incident_id)
            assert len(entries) == 1
            assert entries[0].details['note'] == 'Reviewed batch'
            assert entries[0].details['actor'] == LOCAL_OPERATOR_PRINCIPAL.subject
            assert incident.closed_by == LOCAL_OPERATOR_PRINCIPAL.subject
            assert incident.updated_at >= before[incident.incident_id]
        remaining = main.clean_all_incidents(db, limit=2, note='Reviewed next batch',
                                            principal=LOCAL_OPERATOR_PRINCIPAL)
        assert remaining['resolved_count'] == 1 and not remaining['more_pending']
        assert main.clean_all_incidents(db, limit=2,
                                        principal=LOCAL_OPERATOR_PRINCIPAL)['resolved_count'] == 0
        assert sum(len(status_evidence(db, identifier)) for identifier in identifiers) == 3


@pytest.mark.parametrize('limit', [0, 501])
def test_invalid_batch_size_is_refused_before_mutation(engine, limit):
    with Session(engine) as db:
        identifier = seed(db)[0]
        with pytest.raises(ValueError):
            resolve_incident_batch(db, principal=LOCAL_OPERATOR_PRINCIPAL, limit=limit)
        assert db.get(Incident, identifier).status == 'open'


@pytest.mark.skipif(os.environ.get('PORYGON_TEST_POSTGRES') != '1',
                    reason='PostgreSQL is required for row-lock races')
def test_concurrent_single_and_bulk_resolution_append_one_transition_per_incident(engine):
    with Session(engine) as db:
        identifiers = seed(db, 4)
    barrier = Barrier(2)
    def resolve(single):
        with Session(engine) as db:
            barrier.wait(timeout=10)
            if single:
                transition_incident(db, identifiers[0], target_status='resolved',
                                    principal=LOCAL_OPERATOR_PRINCIPAL, note='Single review')
            else:
                resolve_incident_batch(db, principal=LOCAL_OPERATOR_PRINCIPAL, limit=4,
                                       note='Concurrent batch review')
            db.commit()
    with ThreadPoolExecutor(2) as pool:
        list(pool.map(resolve, [True, False]))
    with Session(engine) as db:
        resolve_incident_batch(db, principal=LOCAL_OPERATOR_PRINCIPAL, limit=4)
        db.commit()
        assert db.scalar(select(func.count()).select_from(Incident).where(
            Incident.status != 'resolved')) == 0
        for identifier in identifiers:
            assert len(status_evidence(db, identifier)) == 1
