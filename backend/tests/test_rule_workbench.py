from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from porygon_api import rule_workbench
from porygon_api.models import (
    CustomDetectionRule,
    CustomDetectionRuleAudit,
    CustomDetectionRuleRevision,
)
from porygon_api.principals import CURRENT_PRINCIPAL, LOCAL_OPERATOR_PRINCIPAL
from porygon_api.rule_workbench import FixtureIn, _fixture_events, _has_fresh_receipt
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session


def _receipt_db(*, kind="preview", result=None, created_at=None, expires_at=None, interpreter_hash=None,
                provenance=None):
    created_at = created_at or datetime.now(UTC)
    expires_at = expires_at or created_at + timedelta(days=7)
    interpreter_hash = interpreter_hash or rule_workbench._sha(rule_workbench.CUSTOM_RULE_INTERPRETER_CONTRACT)
    result = result or {
        "match_count": 1, "nonmatch_count": 1, "unknown_count": 0,
        "labeled_outcomes": {
            "positive": {"count": 1, "match": 1, "nonmatch": 0, "unknown": 0},
            "negative": {"count": 1, "match": 0, "nonmatch": 1, "unknown": 0},
        },
    }
    fields = {
        "receipt_id": "receipt-1", "custom_rule_id": "rule-1", "revision_hash": "a" * 64,
        "kind": kind, "interpreter_hash": interpreter_hash, "created_at": created_at,
        "expires_at": expires_at, "provenance": provenance or {"source": "labeled_local_fixtures"},
        "result": result,
    }
    document = {
        "receipt_id": fields["receipt_id"], "rule_id": fields["custom_rule_id"],
        "revision_hash": fields["revision_hash"], "kind": fields["kind"],
        "interpreter_hash": fields["interpreter_hash"], "created_at": created_at.isoformat(),
        "expires_at": expires_at.isoformat(), "provenance": fields["provenance"], "result": result,
    }
    fields["receipt_hash"] = rule_workbench._sha(document)
    return SimpleNamespace(**fields)


class _ReceiptSession:
    def __init__(self, receipt, audits=True):
        self.receipt = receipt
        self.audits = [SimpleNamespace(details={"receipt_hash": receipt.receipt_hash})] if audits else []

    def scalar(self, _statement):
        return "audit-1" if any(
            item.details.get("receipt_hash") == self.receipt.receipt_hash for item in self.audits
        ) else None

    def scalars(self, _statement):
        return SimpleNamespace(all=lambda: [self.receipt])


def test_activation_receipt_requires_current_integrity_positive_and_negative_labels():
    assert _has_fresh_receipt(_ReceiptSession(_receipt_db()), "rule-1", "a" * 64, "preview")
    for changed in (
        {"match_count": 1, "nonmatch_count": 1, "unknown_count": 0,
         "labeled_outcomes": {"positive": {"count": 1, "match": 0, "nonmatch": 1, "unknown": 0},
                              "negative": {"count": 1, "match": 0, "nonmatch": 1, "unknown": 0}}},
        {"match_count": 2, "nonmatch_count": 0, "unknown_count": 0,
         "labeled_outcomes": {"positive": {"count": 1, "match": 1, "nonmatch": 0, "unknown": 0},
                              "negative": {"count": 1, "match": 1, "nonmatch": 0, "unknown": 0}}},
        {"match_count": 1, "nonmatch_count": 1, "unknown_count": 1,
         "labeled_outcomes": {"positive": {"count": 1, "match": 1, "nonmatch": 0, "unknown": 0},
                              "negative": {"count": 1, "match": 0, "nonmatch": 1, "unknown": 0}}},
    ):
        assert not _has_fresh_receipt(_ReceiptSession(_receipt_db(result=changed)), "rule-1", "a" * 64, "preview")


def test_activation_receipt_rejects_expired_or_old_interpreter_evidence(monkeypatch):
    now = datetime.now(UTC)
    expired = _receipt_db(created_at=now - timedelta(days=8), expires_at=now - timedelta(days=1))
    assert not _has_fresh_receipt(_ReceiptSession(expired), "rule-1", "a" * 64, "preview")

    valid_at_creation = _receipt_db()
    monkeypatch.setattr(rule_workbench, "CUSTOM_RULE_INTERPRETER_CONTRACT", {"changed": True})
    assert not _has_fresh_receipt(_ReceiptSession(valid_at_creation), "rule-1", "a" * 64, "preview")


def test_activation_receipt_requires_audited_labeled_proof_and_post_staging_receipt():
    receipt = _receipt_db()
    db = _ReceiptSession(receipt, audits=False)
    assert not _has_fresh_receipt(db, "rule-1", "a" * 64, "preview")
    db.audits = [SimpleNamespace(details={"receipt_hash": receipt.receipt_hash})]
    assert _has_fresh_receipt(db, "rule-1", "a" * 64, "preview")
    db.audits = [SimpleNamespace(details={"receipt_hash": "f" * 64})]
    assert not _has_fresh_receipt(db, "rule-1", "a" * 64, "preview")
    db.audits = [SimpleNamespace(details={"receipt_hash": receipt.receipt_hash})]
    assert not _has_fresh_receipt(
        db, "rule-1", "a" * 64, "preview", receipt.created_at + timedelta(seconds=1)
    )
    event_receipt = _receipt_db(provenance={"source": "database_events"})
    assert not _has_fresh_receipt(
        _ReceiptSession(event_receipt), "rule-1", "a" * 64, "preview"
    )


def test_process_fixture_ancestry_is_synthetic_bounded_and_identity_checked():
    fixtures = [
        FixtureIn(fixture_id="child", parent_fixture_id="root", label="positive",
                  fields={"executable": "curl"}),
        FixtureIn(fixture_id="root", label="negative", lineage_complete=True,
                  fields={"executable": "sh"}),
    ]
    events, by_id, _labels = _fixture_events(fixtures, target="process")
    child, root = by_id["child"], by_id["root"]
    assert child.parent_event_id == root.event_id
    assert child.process_ppid == root.process_pid
    assert child.parent_start_ns == root.process_start_ns
    assert child.sensor_instance_id == root.sensor_instance_id == "fixture-sensor"
    assert all(event._fixture_lineage_complete for event in events if event is root)
    from porygon_api.detection import evaluate_custom_condition_detailed
    ancestor_condition = {"field": "executable", "op": "equals", "value": "sh", "scope": "ancestor"}
    assert evaluate_custom_condition_detailed(ancestor_condition, child, by_id)[0] is True
    assert evaluate_custom_condition_detailed(
        {"not": ancestor_condition}, root, by_id
    )[0] is True

    mismatched = FixtureIn(
        fixture_id="child", parent_fixture_id="root", label="positive",
        fields={"process_ppid": 1, "executable": "curl"},
    )
    with pytest.raises(HTTPException):
        _fixture_events([fixtures[1], mismatched], target="process")


def test_process_fixture_rejects_missing_parent_and_cycles():
    missing = FixtureIn(fixture_id="child", parent_fixture_id="absent", label="positive", fields={})
    with pytest.raises(HTTPException):
        _fixture_events([missing], target="process")
    first = FixtureIn(fixture_id="first", parent_fixture_id="second", label="positive", fields={})
    second = FixtureIn(fixture_id="second", parent_fixture_id="first", label="negative", fields={})
    with pytest.raises(HTTPException):
        _fixture_events([first, second], target="process")


@pytest.mark.parametrize("recipe_id,parameters", [
    ("writes_under_path", {"path": "/etc"}),
    ("connects_to_ports", {"ports": [22, 4444]}),
    ("memory_backed_execution", {}),
    ("writable_executable_under_path", {"path": "/tmp"}),
    ("exec_under_shell_ancestry", {"shells": ["SH", "BASH"]}),
])
def test_assistant_proposals_compile_and_pair_positive_negative_unknown(recipe_id, parameters):
    result = rule_workbench.assistant_propose(
        rule_workbench.AssistantProposalIn(recipe_id=recipe_id, parameters=parameters)
    )
    assert result["ready"] is True
    assert result["checks"][0]["actual"] == "match"
    assert all(check["actual"] == check["expected"] for check in result["checks"])
    assert result["fixtures"][0]["label"] == "positive"
    assert all(fixture["label"] == "negative" for fixture in result["fixtures"][1:])
    assert [probe["label"] for probe in result["probes"]] == ["unknown"]
    assert result["rule"]["incident_eligible"] is False
    assert result["rule"]["severity_weight"] < 0.5
    assert result["rule"]["expression"]


def test_assistant_rejects_unbounded_parameters_and_retests_edited_expression():
    with pytest.raises(HTTPException) as error:
        rule_workbench.assistant_propose(rule_workbench.AssistantProposalIn(
            recipe_id="connects_to_ports", parameters={"ports": [70000]}
        ))
    assert error.value.status_code == 422

    with pytest.raises(HTTPException) as error:
        rule_workbench.assistant_propose(rule_workbench.AssistantProposalIn(
            recipe_id="writes_under_path", parameters={"path": "/tmp"}
        ))
    assert error.value.status_code == 422
    with pytest.raises(HTTPException) as error:
        rule_workbench.assistant_propose(rule_workbench.AssistantProposalIn(
            recipe_id="writes_under_path", parameters={"path": "/etcetera"}
        ))
    assert error.value.status_code == 422

    result = rule_workbench.assistant_propose(rule_workbench.AssistantProposalIn(
        recipe_id="connects_to_ports", parameters={"ports": [22]},
        expression='remote_port == 80',
    ))
    assert result["ready"] is False
    assert result["checks"][0]["actual"] == "nonmatch"
    assert result["checks"][-1]["actual"] == "unknown"


def test_assistant_triage_is_deterministic_and_requests_clarification():
    assert rule_workbench.assistant_triage(rule_workbench.AssistantTriageIn(
        objective="Alert when a process connects outbound to port 4444"
    ))["selected_recipe_id"] == "connects_to_ports"
    port_triage = rule_workbench.assistant_triage(rule_workbench.AssistantTriageIn(
        objective="Alert when a process connects outbound to port 4444"
    ))
    assert port_triage["suggested_parameters"] == {"ports": [4444]}
    assert rule_workbench.assistant_triage(rule_workbench.AssistantTriageIn(
        objective="Alert for connections to port 22 from 10.1.2.3"
    ))["suggested_parameters"] == {"ports": [22]}
    assert rule_workbench.assistant_triage(rule_workbench.AssistantTriageIn(
        objective="Alert when a process connects outbound to port 123456"
    ))["suggested_parameters"] is None
    path_triage = rule_workbench.assistant_triage(rule_workbench.AssistantTriageIn(
        objective="Alert when files are written under /etc/ssh"
    ))
    assert path_triage["suggested_parameters"] == {"path": "/etc/ssh"}
    unsupported = rule_workbench.assistant_triage(rule_workbench.AssistantTriageIn(
        objective="Detect suspicious behavior"
    ))
    assert unsupported["selected_recipe_id"] is None
    assert unsupported["recommendations"] == []
    assert unsupported["clarification"]


def test_assistant_proposal_uses_objective_triage_without_external_calls():
    result = rule_workbench.assistant_propose(rule_workbench.AssistantProposalIn(
        objective="Detect memory-backed execution", parameters={}
    ))
    assert result["rule"]["target"] == "process"
    assert result["checks"][0]["actual"] == "match"


def test_assistant_rechecks_each_safety_guard_after_expression_edits():
    writable = rule_workbench.assistant_propose(rule_workbench.AssistantProposalIn(
        recipe_id="writable_executable_under_path", parameters={"path": "/tmp"},
        expression='executable_path startswith "/tmp/"',
    ))
    assert writable["ready"] is False
    assert any(check["label"] == "negative control" and check["actual"] == "match"
               for check in writable["checks"])

    connects = rule_workbench.assistant_propose(rule_workbench.AssistantProposalIn(
        recipe_id="connects_to_ports", parameters={"ports": [22, 4444]},
    ))
    assert connects["fixtures"][0]["fields"]["remote_port"] == 4444
    assert any(check["label"] == "near-miss control" and check["actual"] == "nonmatch"
               for check in connects["checks"])


def test_compatibility_create_helper_persists_a_draft_without_live_pointer():
    class _DraftSession:
        def __init__(self):
            self.values = []

        def scalar(self, _statement):
            return None

        def get(self, _model, _key):
            return None

        def add(self, value):
            self.values.append(value)

        def flush(self):
            return None

        def commit(self):
            return None

        def refresh(self, _value):
            return None

    session = _DraftSession()
    rule = rule_workbench.create_rule_draft(session, {
        "slug": "legacy-route-draft", "name": "Draft rule", "description": "Compatibility create.",
        "category": "custom", "target": "process",
        "condition": {"field": "executable", "op": "equals", "value": "nc", "scope": "event"},
        "severity_weight": 0.5, "confidence_weight": 0.5, "incident_eligible": True,
    }, "operator")
    assert rule.enabled is False
    assert rule.lifecycle_state == "draft" and rule.candidate_state == "draft"
    assert rule.active_revision_hash is None
    assert any(isinstance(value, CustomDetectionRuleRevision) for value in session.values)


def test_draft_and_revision_audits_follow_revision_insertion_with_foreign_keys():
    engine = create_engine("sqlite+pysqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    # Create only the tables participating in the revision/audit foreign keys.
    CustomDetectionRule.__table__.create(engine)
    CustomDetectionRuleRevision.__table__.create(engine)
    CustomDetectionRuleAudit.__table__.create(engine)
    db = Session(engine, expire_on_commit=False)
    slug = f"revision-order-{uuid4().hex[:10]}"
    original = {
        "slug": slug, "name": "Original revision", "description": "Initial test revision.",
        "category": "verification", "target": "process",
        "condition": {"field": "executable", "op": "equals", "value": "probe"},
        "severity_weight": 0.1, "confidence_weight": 0.1, "incident_eligible": False,
    }
    principal_token = CURRENT_PRINCIPAL.set(LOCAL_OPERATOR_PRINCIPAL)
    try:
        rule = rule_workbench.create_rule_draft(db, original, "operator")
        original_hash = rule.current_revision_hash
        revised = rule_workbench.RuleRevisionIn(
            **{**original, "description": "Candidate revision."},
            reference="revision-order regression",
            expected_revision_hash=original_hash,
        )
        candidate = rule_workbench.create_revision(rule.custom_rule_id, revised, db)

        audit_rows = db.scalars(
            select(CustomDetectionRuleAudit).order_by(CustomDetectionRuleAudit.created_at)
        ).all()
        assert [row.action for row in audit_rows] == ["draft_created", "revision_created"]
        assert [row.revision_hash for row in audit_rows] == [
            original_hash, candidate["revision_hash"]
        ]
        assert db.get(CustomDetectionRuleRevision, original_hash) is not None
        assert db.get(CustomDetectionRuleRevision, candidate["revision_hash"]) is not None
    finally:
        CURRENT_PRINCIPAL.reset(principal_token)
        db.rollback()
        db.close()
        engine.dispose()


def test_activation_rejects_a_revision_hash_the_operator_did_not_review():
    document = {
        "slug": "safe-rule", "name": "Safe rule", "description": "A bounded test rule.",
        "category": "custom", "target": "process",
        "condition": {"field": "executable", "op": "equals", "value": "nc", "scope": "event"},
        "severity_weight": 0.5, "confidence_weight": 0.5, "incident_eligible": True,
    }
    revision_hash = rule_workbench._revision_hash("rule-1", document)
    revision = CustomDetectionRuleRevision(
        revision_hash=revision_hash, custom_rule_id="rule-1", document=document,
        provenance="authored", created_by="operator", created_at=datetime.now(UTC),
    )
    rule = CustomDetectionRule(
        custom_rule_id="rule-1", slug="safe-rule", name="Safe rule", description="A bounded test rule.",
        category="custom", target="process", condition=document["condition"], severity_weight=0.5,
        confidence_weight=0.5, incident_eligible=True, enabled=False, lifecycle_state="draft",
        current_revision_hash=revision_hash, created_by="operator", created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    class _RuleSession:
        def scalar(self, _statement):
            return rule

        def get(self, model, _key):
            return revision if model is CustomDetectionRuleRevision else None

    token = CURRENT_PRINCIPAL.set(LOCAL_OPERATOR_PRINCIPAL)
    try:
        with pytest.raises(HTTPException) as error:
            rule_workbench.activate_rule(
                "rule-1",
                rule_workbench.RuleTransitionIn(reference="change-1", expected_revision_hash="b" * 64),
                _RuleSession(),
            )
        assert error.value.status_code == 409
    finally:
        CURRENT_PRINCIPAL.reset(token)


def test_active_revision_stays_live_while_candidate_is_edited_and_switches_on_promotion(monkeypatch):
    active_document = {
        "slug": "safe-rule", "name": "Safe rule", "description": "The live revision.",
        "category": "custom", "target": "process",
        "condition": {"field": "executable", "op": "equals", "value": "nc", "scope": "event"},
        "severity_weight": 0.5, "confidence_weight": 0.5, "incident_eligible": True,
    }
    active_hash = rule_workbench._revision_hash("rule-1", active_document)
    active_revision = CustomDetectionRuleRevision(
        revision_hash=active_hash, custom_rule_id="rule-1", document=active_document,
        provenance="authored", created_by="operator", created_at=datetime.now(UTC),
    )
    rule = CustomDetectionRule(
        custom_rule_id="rule-1", slug="safe-rule", name="Safe rule", description="The live revision.",
        category="custom", target="process", condition=active_document["condition"], severity_weight=0.5,
        confidence_weight=0.5, incident_eligible=True, enabled=True, lifecycle_state="active",
        current_revision_hash=active_hash, active_revision_hash=active_hash, candidate_state="none",
        created_by="operator", created_at=datetime.now(UTC), updated_at=datetime.now(UTC),
    )

    class _RuleSession:
        def __init__(self):
            self.values = []
            self.scalar_calls = 0

        def scalar(self, _statement):
            self.scalar_calls += 1
            return rule if self.scalar_calls == 1 else None

        def scalars(self, _statement):
            return SimpleNamespace(all=lambda: [rule])

        def get(self, model, key):
            if model is CustomDetectionRuleRevision and key == active_hash:
                return active_revision
            return None

        def add(self, value):
            self.values.append(value)

        def flush(self):
            return None

        def commit(self):
            return None

        def refresh(self, _value):
            return None

    db = _RuleSession()
    token = CURRENT_PRINCIPAL.set(LOCAL_OPERATOR_PRINCIPAL)
    try:
        revised = rule_workbench.RuleRevisionIn(
            slug="safe-rule", name="Safe rule", description="Candidate revision.", category="custom",
            target="process", condition={"field": "executable", "op": "equals", "value": "curl"},
            severity_weight=0.5, confidence_weight=0.5, incident_eligible=True,
            reference="change-2", expected_revision_hash=active_hash,
        )
        candidate = rule_workbench.create_revision("rule-1", revised, db)
        candidate_hash = candidate["revision_hash"]
        assert rule.lifecycle_state == "active" and rule.enabled is True
        assert rule.active_revision_hash == active_hash and rule.current_revision_hash == candidate_hash

        snapshot = rule_workbench.resolve_active_snapshot(db)
        assert snapshot["rules"][0]["revision_hash"] == active_hash
        assert snapshot["rules"][0]["condition"] == active_document["condition"]
        candidate_revision = next(
            value for value in db.values
            if isinstance(value, CustomDetectionRuleRevision) and value.revision_hash == candidate_hash
        )
        receipt = SimpleNamespace(receipt_hash="c" * 64)
        def get_revision(model, key):
            if model is not CustomDetectionRuleRevision:
                return None
            return {active_hash: active_revision, candidate_hash: candidate_revision}.get(key)

        db.get = get_revision
        scalar_values = iter([rule, None])
        db.scalar = lambda _statement: next(scalar_values)
        rolled_back = rule_workbench.rollback_rule(
            "rule-1", rule_workbench.RollbackIn(
                reference="rollback-1", expected_revision_hash=candidate_hash, revision_hash=active_hash,
            ), db,
        )
        assert rolled_back["revision_hash"] == active_hash
        assert rule.active_revision_hash == active_hash and rule.enabled is True
        assert rule.current_revision_hash == active_hash and rule.candidate_state == "draft"

        scalar_values = iter([rule, None])
        db.scalar = lambda _statement: next(scalar_values)
        staged = rule_workbench.rollback_rule(
            "rule-1", rule_workbench.RollbackIn(
                reference="stage-candidate-1", expected_revision_hash=active_hash,
                revision_hash=candidate_hash,
            ), db,
        )
        assert staged["revision_hash"] == candidate_hash
        assert rule.active_revision_hash == active_hash and rule.enabled is True
        db.scalar = lambda _statement: rule
        with pytest.raises(HTTPException) as stale:
            rule_workbench.activate_rule(
                "rule-1",
                rule_workbench.RuleTransitionIn(reference="stale-review", expected_revision_hash="b" * 64),
                db,
            )
        assert stale.value.status_code == 409
        assert rule.active_revision_hash == active_hash and rule.enabled is True
        rule.candidate_state = "shadow"

        scalar_values = iter([rule, None])
        db.scalar = lambda _statement: next(scalar_values)
        monkeypatch.setattr(rule_workbench, "_check_activation_capacity", lambda *_args: None)
        monkeypatch.setattr(rule_workbench, "_candidate_staging_floor", lambda *_args: datetime.now(UTC))
        monkeypatch.setattr(rule_workbench, "_fresh_receipt", lambda *_args: receipt)
        activated = rule_workbench.activate_rule(
            "rule-1",
            rule_workbench.RuleTransitionIn(reference="change-3", expected_revision_hash=candidate_hash),
            db,
        )
        assert activated["revision_hash"] == candidate_hash
        assert rule.active_revision_hash == candidate_hash and rule.current_revision_hash == candidate_hash
        assert rule.candidate_state == "none" and rule.enabled is True
    finally:
        CURRENT_PRINCIPAL.reset(token)
