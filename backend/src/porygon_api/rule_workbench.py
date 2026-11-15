from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import delete, desc, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from porygon_api.db import get_db
from porygon_api.detection import (
    CUSTOM_RULE_INTERPRETER_CONTRACT,
    MAX_ACTIVE_CUSTOM_RULES,
    MAX_CUSTOM_RULE_SNAPSHOT_BYTES,
    MAX_PREVIEW_EVALUATION_OPERATIONS,
    EvaluationBudget,
    RuleEvaluationBudgetExceeded,
    RuleSetCapacityExceeded,
    custom_ruleset_hash,
    evaluate_custom_condition_detailed,
    validate_custom_condition,
)
from porygon_api.models import (
    CustomDetectionRule,
    CustomDetectionRuleAudit,
    CustomDetectionRuleReceipt,
    CustomDetectionRuleRevision,
    DetectionRun,
    KernelRuntimeEvent,
    ProcessExecEvent,
    RuntimeEvent,
)
from porygon_api.principals import current_principal
from porygon_api.rule_expression import (
    MAX_EXPRESSION_LENGTH,
    ExpressionError,
    parse_expression,
    render_expression,
)
from porygon_api.security import require_operator_token

router = APIRouter(tags=["custom-rule-workbench"])
MAX_PREVIEW_EVENTS = 250
MAX_PREVIEW_SECONDS = 3600
MAX_FIXTURE_TEXT = 512


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _actor() -> str:
    principal = current_principal()
    if principal is None or principal.kind != "operator":
        raise HTTPException(401, "Verified operator identity required")
    return principal.subject


def _rule_content(data: Any) -> dict[str, Any]:
    return {
        "slug": data.slug,
        "name": data.name,
        "description": data.description,
        "category": data.category,
        "target": data.target,
        "condition": data.condition,
        "severity_weight": float(data.severity_weight),
        "confidence_weight": float(data.confidence_weight),
        "incident_eligible": bool(data.incident_eligible),
    }


def _revision_hash(rule_id: str, document: dict[str, Any]) -> str:
    return _sha({"rule_id": rule_id, "document": document})


def _validate_revision_document_bounds(document: Any) -> None:
    if not isinstance(document, dict):
        raise HTTPException(409, "Stored immutable rule revision is not an object")
    limits = {"slug": 40, "name": 255, "description": 4000, "category": 64, "target": 16}
    for field, maximum in limits.items():
        value = document.get(field)
        if not isinstance(value, str) or len(value) > maximum:
            raise HTTPException(409, "Stored immutable rule revision exceeds a field bound")
    try:
        validate_custom_condition(document.get("condition"), target=document.get("target"))
    except (ValueError, AttributeError) as exc:
        raise HTTPException(409, "Stored immutable rule revision no longer passes the interpreter contract") from exc


def _revision_content(row: CustomDetectionRuleRevision) -> dict[str, Any]:
    _validate_revision_document_bounds(row.document)
    if _revision_hash(row.custom_rule_id, row.document) != row.revision_hash:
        raise HTTPException(409, "Stored immutable rule revision hash does not match its content")
    return row.document


def _insert_audit(
    db: Session,
    rule_id: str,
    action: str,
    actor: str,
    revision_hash: str | None,
    reference: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(CustomDetectionRuleAudit(
        audit_id=str(uuid4()), custom_rule_id=rule_id, revision_hash=revision_hash,
        action=action, actor=actor, reference=reference,
        details=details or {}, created_at=datetime.now(UTC),
    ))


class RuleDocumentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    slug: str = Field(min_length=1, max_length=40, pattern=r"^[a-z0-9-]{1,40}$")
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=4000)
    category: str = Field(min_length=1, max_length=64)
    target: Literal["process", "runtime", "kernel"]
    condition: dict[str, Any] | None = None
    expression: str | None = Field(default=None, max_length=MAX_EXPRESSION_LENGTH)
    severity_weight: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    confidence_weight: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    incident_eligible: bool

    @model_validator(mode="after")
    def compile_and_validate(self) -> RuleDocumentIn:
        if (self.condition is None) == (self.expression is None):
            raise ValueError("provide exactly one of condition or expression")
        if self.expression is not None:
            try:
                self.condition = parse_expression(self.expression)
            except ExpressionError as exc:
                raise ValueError(f"invalid expression: {exc}") from exc
        validate_custom_condition(self.condition, target=self.target)
        return self


class RuleCreateIn(RuleDocumentIn):
    pass


@router.post("/operator/v1/rule-workbench/validate", dependencies=[Depends(require_operator_token)])
def validate_rule(payload: RuleDocumentIn) -> dict[str, Any]:
    document = _rule_content(payload)
    return {"valid": True, "target": payload.target,
            "condition": payload.condition, "expression": render_expression(payload.condition),
            "document_hash": _sha(document),
            "limits": {"max_depth": 6, "max_leaves": 40, "max_value_characters": 512,
                       "max_list_items": 100}}


class RuleRevisionIn(RuleDocumentIn):
    reference: str = Field(min_length=1, max_length=255)
    expected_revision_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def reference_is_meaningful(self) -> RuleRevisionIn:
        self.reference = self.reference.strip()
        if not self.reference:
            raise ValueError("reference must contain non-whitespace text")
        return self


class RuleTransitionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reference: str = Field(min_length=1, max_length=255)
    expected_revision_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def reference_is_meaningful(self) -> RuleTransitionIn:
        self.reference = self.reference.strip()
        if not self.reference:
            raise ValueError("reference must contain non-whitespace text")
        return self


class RollbackIn(RuleTransitionIn):
    revision_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class FixtureIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: Literal["positive", "negative", "unknown"]
    fields: dict[str, Any] = Field(max_length=24)
    fixture_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    parent_fixture_id: str | None = Field(default=None, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    lineage_complete: bool = False

    @model_validator(mode="after")
    def validate_fixture(self) -> FixtureIn:
        allowed = {
            "executable", "executable_path", "process_name", "parent_executable",
            "parent_executable_path", "parent_name", "command_line", "user_uid",
            "container_id", "action", "image_digest", "privileged", "runtime_action",
            "event_type", "return_value", "exe_from_memfd", "exe_writable", "file_path",
            "remote_address", "remote_port", "process_pid", "process_start_ns",
            "process_ppid", "parent_start_ns", "time_nano", "sensor_instance_id",
            "pid_namespace_start_ns", "sensor_epoch", "docker_host_id",
        }
        if set(self.fields) - allowed:
            raise ValueError("fixture contains unsupported fields")
        if ("executable" in self.fields and "executable_path" in self.fields
                or "parent_executable" in self.fields and "parent_executable_path" in self.fields):
            raise ValueError("fixture cannot provide both basename and path aliases for one field")
        for value in self.fields.values():
            if isinstance(value, str) and len(value) > MAX_FIXTURE_TEXT:
                raise ValueError("fixture string exceeds the bounded length")
            if isinstance(value, (dict, list)):
                raise ValueError("fixture fields must be scalar values")  # noqa: TRY004
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("fixture values must be finite")
        return self


class PreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    event_ids: list[str] = Field(default_factory=list, max_length=MAX_PREVIEW_EVENTS)
    fixtures: list[FixtureIn] = Field(default_factory=list, max_length=MAX_PREVIEW_EVENTS)

    @model_validator(mode="after")
    def exactly_one_source(self) -> PreviewIn:
        if bool(self.event_ids) == bool(self.fixtures):
            raise ValueError("provide event_ids or fixtures, but not both")
        if len(set(self.event_ids)) != len(self.event_ids):
            raise ValueError("event_ids must be unique")
        if any(len(event_id) > 128 or re.fullmatch(r"[A-Za-z0-9_.:-]+", event_id) is None
               for event_id in self.event_ids):
            raise ValueError("event IDs must be bounded opaque identifiers")
        if len({item.fixture_id for item in self.fixtures}) != len(self.fixtures):
            raise ValueError("fixture IDs must be unique")
        return self


def _make_revision(
    db: Session, rule: CustomDetectionRule, content: dict[str, Any], actor: str,
    *, provenance: str = "authored",
) -> str:
    revision_hash = _revision_hash(rule.custom_rule_id, content)
    existing = db.get(CustomDetectionRuleRevision, revision_hash)
    if existing is None:
        db.add(CustomDetectionRuleRevision(
            revision_hash=revision_hash, custom_rule_id=rule.custom_rule_id,
            document=content, provenance=provenance, created_by=actor,
            created_at=datetime.now(UTC),
        ))
    rule.slug = content["slug"]
    rule.name = content["name"]
    rule.description = content["description"]
    rule.category = content["category"]
    rule.target = content["target"]
    rule.condition = content["condition"]
    rule.severity_weight = content["severity_weight"]
    rule.confidence_weight = content["confidence_weight"]
    rule.incident_eligible = content["incident_eligible"]
    rule.current_revision_hash = revision_hash
    rule.updated_at = datetime.now(UTC)
    return revision_hash


def _rule_output(rule: CustomDetectionRule, revision: CustomDetectionRuleRevision | None = None) -> dict[str, Any]:
    document = _revision_content(revision) if revision is not None else {
        "slug": rule.slug, "name": rule.name, "description": rule.description,
        "category": rule.category, "target": rule.target, "condition": rule.condition,
        "severity_weight": rule.severity_weight, "confidence_weight": rule.confidence_weight,
        "incident_eligible": rule.incident_eligible,
    }
    try:
        expression = render_expression(document["condition"])
    except ExpressionError:
        expression = None
    return {
        "custom_rule_id": rule.custom_rule_id, **document,
        "revision_hash": rule.current_revision_hash, "lifecycle_state": rule.lifecycle_state,
        "active_revision_hash": rule.active_revision_hash,
        "candidate_state": rule.candidate_state,
        "enabled": rule.enabled, "expression": expression,
        "created_by": rule.created_by, "created_at": rule.created_at,
        "updated_at": rule.updated_at, "disabled_at": rule.disabled_at,
        "disabled_by": rule.disabled_by,
    }


def create_rule_draft(db: Session, content: dict[str, Any], actor: str) -> CustomDetectionRule:
    """Compatibility service for the old POST route; creation is always draft-only."""
    conflict = db.scalar(select(CustomDetectionRule).where(
        CustomDetectionRule.slug == content["slug"],
        CustomDetectionRule.lifecycle_state != "disabled",
    ))
    if conflict:
        raise HTTPException(409, "A non-disabled rule already uses this slug")
    now = datetime.now(UTC)
    rule = CustomDetectionRule(
        custom_rule_id=str(uuid4()), slug=content["slug"], name=content["name"],
        description=content["description"], category=content["category"],
        target=content["target"], condition=content["condition"],
        severity_weight=content["severity_weight"], confidence_weight=content["confidence_weight"],
        incident_eligible=content["incident_eligible"], enabled=False,
        lifecycle_state="draft", candidate_state="draft", active_revision_hash=None,
        created_by=actor, created_at=now, updated_at=now,
    )
    db.add(rule)
    try:
        # Insert the parent before its immutable revision because some drivers
        # cannot order these rows without mapped ORM relationships.
        db.flush()
        revision_hash = _make_revision(db, rule, content, actor)
        # The audit row has a foreign key to the revision row.
        db.flush()
        _insert_audit(db, rule.custom_rule_id, "draft_created", actor, revision_hash)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "A rule with this slug or revision already exists") from exc
    db.refresh(rule)
    return rule


def _get_rule(db: Session, rule_id: str, *, for_update: bool = False) -> CustomDetectionRule:
    statement = select(CustomDetectionRule).where(CustomDetectionRule.custom_rule_id == rule_id)
    if for_update:
        statement = statement.with_for_update()
    rule = db.scalar(statement)
    if rule is None:
        raise HTTPException(404, "Custom rule not found")
    return rule


@router.get("/api/v1/rule-workbench/rules")
def list_workbench_rules(db: Session = Depends(get_db)) -> list[dict[str, Any]]:  # noqa: B008
    rows = db.scalars(select(CustomDetectionRule).order_by(CustomDetectionRule.created_at.desc())).all()
    return [_rule_output(row) for row in rows]


@router.post("/operator/v1/rule-workbench/rules", status_code=201, dependencies=[Depends(require_operator_token)])
def create_rule(payload: RuleCreateIn, db: Session = Depends(get_db)) -> dict[str, Any]:  # noqa: B008
    actor = _actor()
    rule = create_rule_draft(db, _rule_content(payload), actor)
    revision_hash = rule.current_revision_hash
    return _rule_output(rule, db.get(CustomDetectionRuleRevision, revision_hash))


@router.post("/operator/v1/rule-workbench/rules/{rule_id}/revisions", dependencies=[Depends(require_operator_token)])
def create_revision(rule_id: str, payload: RuleRevisionIn, db: Session = Depends(get_db)) -> dict[str, Any]:  # noqa: B008
    actor = _actor()
    rule = _get_rule(db, rule_id, for_update=True)
    if rule.current_revision_hash != payload.expected_revision_hash:
        raise HTTPException(409, "Rule revision changed since it was opened; refresh before editing")
    if payload.slug != rule.slug:
        raise HTTPException(422, "A rule revision cannot change its stable slug")
    content = _rule_content(payload)
    prior_state = rule.lifecycle_state
    previous_revision_hash = rule.current_revision_hash
    has_active_revision = bool(rule.enabled and rule.active_revision_hash)
    if has_active_revision:
        # Keep the live pointer and enabled state until this candidate is explicitly promoted.
        rule.lifecycle_state = "active"
    elif prior_state != "disabled":
        rule.lifecycle_state = "draft"
    else:
        rule.enabled = False
    rule.candidate_state = "draft"
    try:
        revision_hash = _make_revision(db, rule, content, actor)
        # Audit rows reference immutable revisions and must be inserted afterward.
        db.flush()
        _insert_audit(db, rule_id, "revision_created", actor, revision_hash, payload.reference,
                      {"previous_revision_hash": previous_revision_hash,
                       "active_revision_hash": rule.active_revision_hash,
                       "previous_state": prior_state})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Rule revision conflicts with an existing rule") from exc
    db.refresh(rule)
    return _rule_output(rule, db.get(CustomDetectionRuleRevision, revision_hash))


@router.get("/api/v1/rule-workbench/rules/{rule_id}/revisions")
def list_revisions(rule_id: str, db: Session = Depends(get_db)) -> list[dict[str, Any]]:  # noqa: B008
    _get_rule(db, rule_id)
    rows = db.scalars(select(CustomDetectionRuleRevision).where(
        CustomDetectionRuleRevision.custom_rule_id == rule_id,
    ).order_by(CustomDetectionRuleRevision.created_at.desc()).limit(100)).all()
    return [{"revision_hash": row.revision_hash, "provenance": row.provenance,
             "created_by": row.created_by, "created_at": row.created_at,
             "document": _revision_content(row)} for row in rows]


def _db_events(rule: CustomDetectionRule, event_ids: list[str], db: Session) -> tuple[list[Any], dict[str, Any], dict[str, Any]]:
    model = {"process": ProcessExecEvent, "runtime": RuntimeEvent,
             "kernel": KernelRuntimeEvent}[rule.target]
    rows = db.scalars(select(model).where(model.event_id.in_(event_ids))).all()
    if len(rows) != len(event_ids):
        raise HTTPException(422, "One or more selected events are unavailable")
    by_id = {row.event_id: row for row in rows}
    rows = [by_id[event_id] for event_id in event_ids]
    hosts = {getattr(row, "docker_host_id", None) for row in rows}
    containers = {getattr(row, "container_id", None) for row in rows}
    times = [row.occurred_at for row in rows]
    if len(hosts) != 1 or None in hosts or len(containers) != 1 or None in containers:
        raise HTTPException(422, "Preview events must share a verified host and container scope")
    if (max(times) - min(times)).total_seconds() > MAX_PREVIEW_SECONDS:
        raise HTTPException(422, "Preview event time span exceeds the one-hour bound")
    epochs = {getattr(row, "sensor_epoch", None) for row in rows} if rule.target in {"process", "kernel"} else set()
    if rule.target in {"process", "kernel"} and (len(epochs) != 1 or None in epochs):
        raise HTTPException(422, "Telemetry preview events must share a verified sensor epoch")
    sensors = {getattr(row, "sensor_instance_id", None) for row in rows} if rule.target in {"process", "kernel"} else set()
    if rule.target in {"process", "kernel"} and (len(sensors) != 1 or None in sensors):
        raise HTTPException(422, "Telemetry preview events must share a verified sensor instance")
    if rule.target in {"process", "kernel"} and any(
        getattr(row, "correlation_status", None) != "resolved" for row in rows
    ):
        raise HTTPException(422, "Telemetry preview events require resolved host/container correlation")
    process_identity = None
    if rule.target == "kernel":
        identities = {(row.process_pid, row.process_start_ns, row.pid_namespace_start_ns) for row in rows}
        identity = next(iter(identities)) if len(identities) == 1 else ()
        if (any(row.correlation_status != "resolved" for row in rows)
                or len(identities) != 1 or len(identity) != 3
                or any(value is None for value in identity)):
            raise HTTPException(422, "Kernel preview events must share one resolved process lifetime")
        process_identity = list(identity)
    scope = {"source": "database_events", "target": rule.target,
             "docker_host_id": next(iter(hosts)), "container_id": next(iter(containers)),
             "sensor_epoch": next(iter(epochs)) if epochs else None,
             "sensor_instance_id": next(iter(sensors)) if sensors else None,
             "process_identity": process_identity,
             "event_ids": event_ids, "event_count": len(rows),
             "window_start": min(times).isoformat(), "window_end": max(times).isoformat(),
             "coverage": "selected_events_only_ancestry_outside_selection_is_unknown"}
    return rows, by_id, scope


def _fixture_events(fixtures: list[FixtureIn], *, target: str) -> tuple[list[Any], dict[str, Any], dict[str, str]]:
    fixtures_by_id = {fixture.fixture_id: fixture for fixture in fixtures}
    if any(fixture.parent_fixture_id and fixture.parent_fixture_id not in fixtures_by_id
           for fixture in fixtures):
        raise HTTPException(422, "Fixture ancestry must reference a fixture in this selection")
    state: dict[str, int] = {}
    ordered: list[FixtureIn] = []

    def visit(fixture: FixtureIn) -> None:
        marker = state.get(fixture.fixture_id, 0)
        if marker == 1:
            raise HTTPException(422, "Fixture ancestry cannot contain cycles")
        if marker == 2:
            return
        state[fixture.fixture_id] = 1
        if fixture.parent_fixture_id:
            visit(fixtures_by_id[fixture.parent_fixture_id])
        state[fixture.fixture_id] = 2
        ordered.append(fixture)

    for fixture in fixtures:
        visit(fixture)
    positions = {fixture.fixture_id: index for index, fixture in enumerate(ordered, start=1)}
    fixture_time_base = datetime(2026, 1, 1, tzinfo=UTC)
    by_id: dict[str, Any] = {}
    labels: dict[str, str] = {}
    for fixture in ordered:
        index = positions[fixture.fixture_id]
        item = SimpleNamespace(event_id=fixture.fixture_id, parent_event_id=fixture.parent_fixture_id,
                               occurred_at=fixture_time_base + timedelta(seconds=index), container_id="fixture-container",
                               docker_host_id="fixture-host", sensor_epoch="fixture-epoch",
                               sensor_instance_id="fixture-sensor", pid_namespace_start_ns=1,
                               process_pid=10000 + index, process_ppid=None,
                               process_start_ns=index, parent_start_ns=None,
                               time_nano=index * 1_000_000_000,
                               _fixture_lineage_complete=fixture.lineage_complete)
        for name, value in fixture.fields.items():
            if name in {"executable", "executable_path"}:
                item.executable = value
            elif name in {"parent_executable", "parent_executable_path"}:
                item.parent_executable = value
            elif name == "privileged":
                item.container_snapshot = {"host_config": {"privileged": value}}
            else:
                setattr(item, name, value)
        if target == "process" and fixture.parent_fixture_id:
            parent = by_id[fixture.parent_fixture_id]
            if "process_ppid" not in fixture.fields:
                item.process_ppid = parent.process_pid
            if "parent_start_ns" not in fixture.fields:
                item.parent_start_ns = parent.process_start_ns
            if (item.docker_host_id != parent.docker_host_id
                    or item.sensor_instance_id != parent.sensor_instance_id
                    or item.sensor_epoch != parent.sensor_epoch
                    or item.container_id != parent.container_id
                    or item.pid_namespace_start_ns != parent.pid_namespace_start_ns
                    or item.process_ppid != parent.process_pid
                    or item.parent_start_ns != parent.process_start_ns
                    or item.time_nano < parent.time_nano):
                raise HTTPException(422, "Fixture ancestry identities and process lifetime must agree")
        by_id[fixture.fixture_id] = item
        labels[fixture.fixture_id] = fixture.label
    if target == "process" and any(f.lineage_complete and f.parent_fixture_id for f in fixtures):
        raise HTTPException(422, "Only a fixture root may declare a complete ancestry chain")
    return list(by_id.values()), by_id, labels


def _write_examples(values: dict[str, Any]) -> tuple[list[FixtureIn], FixtureIn]:
    fields = {"file_path": values["path"] + "config.db", "return_value": 4096,
              "event_type": "write", "runtime_action": "file_write"}
    negative_path = "/etc/payload" if not values["path"].startswith("/etc/") else "/usr/bin/payload"
    return ([FixtureIn(fixture_id="assistant-positive", label="positive", fields=fields),
             FixtureIn(fixture_id="assistant-negative", label="negative",
                       fields={**fields, "file_path": negative_path}),
             FixtureIn(fixture_id="assistant-nearmiss", label="negative",
                       fields={**fields, "runtime_action": "file_write_open", "return_value": 5})],
            FixtureIn(fixture_id="assistant-unknown", label="unknown",
                      fields={key: value for key, value in fields.items() if key != "file_path"}))


def _connect_examples(values: dict[str, Any]) -> tuple[list[FixtureIn], FixtureIn]:
    fields = {"remote_port": values["ports"][-1], "event_type": "connect", "return_value": 0,
              "runtime_action": "net_outbound"}
    return ([FixtureIn(fixture_id="assistant-positive", label="positive", fields=fields),
             FixtureIn(fixture_id="assistant-negative", label="negative",
                       fields={**fields, "remote_port": next(port for port in range(1, 65536)
                                                               if port not in values["ports"])}),
             FixtureIn(fixture_id="assistant-nearmiss", label="negative",
                       fields={**fields, "return_value": -115})],
            FixtureIn(fixture_id="assistant-unknown", label="unknown",
                      fields={key: value for key, value in fields.items() if key != "remote_port"}))


def _memory_examples(_values: dict[str, Any]) -> tuple[list[FixtureIn], FixtureIn]:
    fields = {"exe_from_memfd": True, "executable": "memfd:payload"}
    return ([FixtureIn(fixture_id="assistant-positive", label="positive", fields=fields),
             FixtureIn(fixture_id="assistant-negative", label="negative",
                       fields={**fields, "exe_from_memfd": False})],
            FixtureIn(fixture_id="assistant-unknown", label="unknown", fields={"executable": "memfd:payload"}))


def _writable_examples(values: dict[str, Any]) -> tuple[list[FixtureIn], FixtureIn]:
    fields = {"executable_path": values["path"] + "payload", "exe_writable": True}
    return ([FixtureIn(fixture_id="assistant-positive", label="positive", fields=fields),
             FixtureIn(fixture_id="assistant-negative", label="negative",
                       fields={**fields, "exe_writable": False})],
            FixtureIn(fixture_id="assistant-unknown", label="unknown", fields={"exe_writable": True}))


def _shell_examples(values: dict[str, Any]) -> tuple[list[FixtureIn], FixtureIn]:
    return ([FixtureIn(fixture_id="assistant-positive", label="positive", fields={"executable": "curl"},
                       parent_fixture_id="assistant-shell"),
             FixtureIn(fixture_id="assistant-negative", label="negative", fields={"executable": "curl"},
                       lineage_complete=True),
             FixtureIn(fixture_id="assistant-shell", label="negative", fields={"executable": values["shells"][0]},
                       lineage_complete=True)],
            FixtureIn(fixture_id="assistant-unknown", label="unknown", fields={"executable": "curl"}))


def _resolve_recipe_template(value: Any, parameters: dict[str, Any]) -> Any:
    if isinstance(value, dict) and set(value) == {"$parameter"}:
        return parameters[value["$parameter"]]
    if isinstance(value, dict):
        return {key: _resolve_recipe_template(item, parameters) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_recipe_template(item, parameters) for item in value]
    return value


# This catalog is intentionally local and finite. Parameters are inserted only as
# typed DSL literals, then both the expression compiler and production evaluator
# decide what each synthetic example means.
_ASSISTANT_RECIPES: tuple[dict[str, Any], ...] = (
    {"id": "writes_under_path", "title": "Successful writes below a path",
     "description": "Find successful file writes whose destination is inside a selected directory.",
     "target": "kernel",
     "parameters": [{"id": "path", "label": "Directory path", "type": "path", "default": "/etc", "help": "Absolute directory prefix; a trailing slash is added."}],
     "condition_template": {"all": [{"field": "file_path", "op": "startswith", "value": {"$parameter": "path"}}, {"field": "runtime_action", "op": "equals", "value": "file_write"}, {"field": "return_value", "op": "gt", "value": 0}]},
     "example_builder": _write_examples,
     "requirements": ["A kernel file_write event must expose file_path and a positive byte count in return_value.", "Falco currently emits sensitive file activity only beneath /etc, /usr/bin, /usr/sbin, /bin, /sbin, and /root/.ssh."],
     "limitations": ["A path prefix is lexical and does not resolve symlinks or mount aliases.", "Open attempts and zero-byte writes do not match; only observed positive-byte file_write events are covered."]},
    {"id": "connects_to_ports", "title": "Outbound connects to selected ports",
     "description": "Match kernel network-connect events targeting one or more remote ports.",
     "target": "kernel",
     "parameters": [{"id": "ports", "label": "Remote ports", "type": "integer_list", "default": [22, 4444], "help": "One to eight ports from 1 through 65535."}],
     "condition_template": {"all": [{"field": "remote_port", "op": "in", "value": {"$parameter": "ports"}}, {"field": "runtime_action", "op": "equals", "value": "net_outbound"}, {"field": "event_type", "op": "equals", "value": "connect"}, {"field": "return_value", "op": "equals", "value": 0}]},
     "example_builder": _connect_examples,
     "requirements": ["Kernel telemetry must populate remote_port for net_outbound connect events."],
     "limitations": ["Nonblocking connects reported as EINPROGRESS (-115) are not treated as successful connections.", "Encrypted application intent is not visible from this field alone."]},
    {"id": "memory_backed_execution", "title": "Memory-backed execution",
     "description": "Identify process execution reported as originating from a memory-backed executable.",
     "target": "process",
     "condition_template": {"field": "exe_from_memfd", "op": "equals", "value": True}, "example_builder": _memory_examples,
     "parameters": [], "requirements": ["Process telemetry must populate exe_from_memfd."],
     "limitations": ["Coverage depends on the host sensor and kernel exposing the memfd execution signal."]},
    {"id": "writable_executable_under_path", "title": "Writable executable below a path",
     "description": "Match an executable marked writable whose executable path is under a selected directory.",
     "target": "process",
     "parameters": [{"id": "path", "label": "Directory path", "type": "path", "default": "/tmp", "help": "Absolute directory prefix; a trailing slash is added."}],
     "condition_template": {"all": [{"field": "executable_path", "op": "startswith", "value": {"$parameter": "path"}}, {"field": "exe_writable", "op": "equals", "value": True}]},
     "example_builder": _writable_examples,
     "requirements": ["Process exec telemetry must expose executable_path and exe_writable."],
     "limitations": ["A path prefix does not resolve symlinks or mount aliases."]},
    {"id": "exec_under_shell_ancestry", "title": "Exec under verified shell ancestry",
     "description": "Match a process when a verified ancestor executable is one of the selected shells.",
     "target": "process",
     "parameters": [{"id": "shells", "label": "Shell executables", "type": "string_list", "default": ["sh", "bash", "dash", "zsh"], "help": "One to eight executable basenames, each at most 80 characters."}],
     "condition_template": {"field": "executable", "op": "in", "value": {"$parameter": "shells"}, "scope": "ancestor"},
     "example_builder": _shell_examples,
     "requirements": ["Process events need complete, identity-verified ancestry for negative proof."],
     "limitations": ["If ancestry is incomplete or unavailable, evaluation is unknown.", "This checks ancestor executable names, not interactive shell intent."]},
)


class AssistantProposalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recipe_id: str | None = Field(default=None, min_length=1, max_length=80)
    parameters: dict[str, Any] = Field(default_factory=dict, max_length=8)
    objective: str | None = Field(default=None, max_length=500)
    expression: str | None = Field(default=None, max_length=MAX_EXPRESSION_LENGTH)


class AssistantTriageIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    objective: str = Field(min_length=1, max_length=500)


def _triage_objective(objective: str) -> dict[str, Any]:
    text_value = objective.casefold()
    candidates: list[tuple[str, tuple[str, ...], str]] = [
        ("writes_under_path", ("write", "writes", "written", "file path", "directory"), "Mentions file writes or a destination path."),
        ("connects_to_ports", ("connect", "connection", "outbound", "port", "network"), "Mentions outbound network connections or destination ports."),
        ("memory_backed_execution", ("memfd", "memory-backed", "memory backed", "fileless", "in memory"), "Mentions memory-backed or fileless execution."),
        ("writable_executable_under_path", ("writable executable", "writable binary", "writable program"), "Mentions an executable that is writable."),
        ("exec_under_shell_ancestry", ("shell ancestry", "child of a shell", "under a shell", "shell parent"), "Mentions process ancestry under a shell."),
    ]
    matches = [(recipe_id, reason) for recipe_id, terms, reason in candidates if any(term in text_value for term in terms)]
    suggested_parameters: dict[str, Any] | None = None
    if len(matches) == 1 and matches[0][0] == "connects_to_ports":
        tail = re.search(r"\bports?\b\s*(?::|are\b|of\b)?\s*(\d{1,5}(?!\d)(?:\s*(?:,|and)\s*\d{1,5}(?!\d))*)", objective, flags=re.IGNORECASE)
        numbers = [int(value) for value in re.findall(r"\d+", tail.group(1))] if tail else []
        suffix = objective[tail.end(1):] if tail else ""
        incomplete_list = bool(re.match(r"\s*(?:,|and\b)", suffix, flags=re.IGNORECASE))
        if numbers and not incomplete_list and len(numbers) <= 8 and all(1 <= value <= 65535 for value in numbers):
            suggested_parameters = {"ports": sorted(set(numbers))}
    elif len(matches) == 1 and matches[0][0] == "writes_under_path":
        path_matches = set(re.findall(r"(?<![A-Za-z0-9])/(?:[A-Za-z0-9_.-]+/?)+", objective))
        if len(path_matches) == 1:
            path_value = next(iter(path_matches)).rstrip("/") or "/"
            roots = ("/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/root/.ssh")
            if len(path_value) <= 200 and any(path_value == root or path_value.startswith(root + "/") for root in roots):
                suggested_parameters = {"path": path_value}
    if len(matches) == 1:
        return {"selected_recipe_id": matches[0][0], "recommendations": [matches[0][0]],
                "rationale": [matches[0][1]], "clarification": None,
                "suggested_parameters": suggested_parameters}
    if len(matches) > 1:
        return {"selected_recipe_id": None, "recommendations": [item[0] for item in matches],
                "rationale": [item[1] for item in matches],
                "clarification": "The objective maps to multiple supported behaviors. Choose which behavior should trigger the rule, or state whether all should be combined.",
                "suggested_parameters": None}
    return {"selected_recipe_id": None, "recommendations": [], "rationale": [],
            "clarification": "I could not map this objective to a supported recipe. Clarify whether you mean file writes, outbound ports, memory-backed execution, writable executables, or shell ancestry.",
            "suggested_parameters": None}


@router.get("/api/v1/rule-workbench/assistant", dependencies=[Depends(require_operator_token)])
def assistant_catalog() -> dict[str, Any]:
    return {"recipes": [{key: recipe[key] for key in ("id", "title", "description", "parameters")}
                         for recipe in _ASSISTANT_RECIPES]}


@router.post("/operator/v1/rule-workbench/assistant/triage", dependencies=[Depends(require_operator_token)])
def assistant_triage(payload: AssistantTriageIn) -> dict[str, Any]:
    return _triage_objective(payload.objective.strip())


def _bounded_parameters(recipe: dict[str, Any], supplied: dict[str, Any]) -> dict[str, Any]:
    declared = {item["id"]: item for item in recipe["parameters"]}
    if set(supplied) - set(declared):
        raise HTTPException(422, "Provide only parameters listed for this recipe")
    result: dict[str, Any] = {}
    for key, spec in declared.items():
        value = supplied.get(key, spec["default"])
        if spec["type"] == "path":
            if (not isinstance(value, str) or not value.startswith("/") or len(value) > 200
                    or any(ord(character) < 0x20 for character in value)
                    or any(segment in {".", ".."} for segment in value.split("/"))):
                raise HTTPException(422, "Path must be an absolute path of at most 200 characters")
            normalized = value.rstrip("/") or "/"
            if recipe["id"] == "writes_under_path":
                roots = ("/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/root/.ssh")
                if not any(normalized == root or normalized.startswith(root + "/") for root in roots):
                    raise HTTPException(422, "Write paths must be under /etc, /usr/bin, /usr/sbin, /bin, /sbin, or /root/.ssh")
            result[key] = normalized if normalized == "/" else normalized + "/"
        elif spec["type"] == "integer_list":
            if not isinstance(value, list) or not 1 <= len(value) <= 8 or any(type(item) is not int or not 1 <= item <= 65535 for item in value):
                raise HTTPException(422, "Ports must contain one to eight integers from 1 through 65535")
            result[key] = sorted(set(value))
        elif spec["type"] == "string_list":
            if not isinstance(value, list) or not 1 <= len(value) <= 8 or any(not isinstance(item, str) or not item or len(item) > 80 or not re.fullmatch(r"[A-Za-z0-9_.-]+", item) for item in value):
                raise HTTPException(422, "Values must contain one to eight bounded executable names")
            result[key] = sorted({item.lower() for item in value})
    return result


@router.post("/operator/v1/rule-workbench/assistant/propose", dependencies=[Depends(require_operator_token)])
def assistant_propose(payload: AssistantProposalIn) -> dict[str, Any]:
    recipe = next((item for item in _ASSISTANT_RECIPES if item["id"] == payload.recipe_id), None)
    proposed_parameters = payload.parameters
    if recipe is None:
        if payload.objective:
            triage = _triage_objective(payload.objective.strip())
            if triage["selected_recipe_id"]:
                recipe = next(item for item in _ASSISTANT_RECIPES if item["id"] == triage["selected_recipe_id"])
                if not proposed_parameters and triage["suggested_parameters"]:
                    proposed_parameters = triage["suggested_parameters"]
            else:
                return {**triage, "rule": None, "fixtures": [], "checks": [], "requirements": [], "limitations": []}
        else:
            raise HTTPException(422, "Select a supported recipe or provide an objective for triage")
    values = _bounded_parameters(recipe, proposed_parameters)
    condition = _resolve_recipe_template(recipe["condition_template"], values)
    expression = render_expression(condition) if payload.expression is None else payload.expression
    try:
        compiled = parse_expression(expression)
        validate_custom_condition(compiled, target=recipe["target"])
    except (ExpressionError, ValueError) as exc:
        raise HTTPException(422, f"Candidate expression is invalid: {exc}") from exc

    fixtures, probe = recipe["example_builder"](values)
    positive = next(item for item in fixtures if item.fixture_id == "assistant-positive")
    events, by_id, labels = _fixture_events(fixtures, target=recipe["target"])
    outcomes: dict[str, str] = {}
    for item in events:
        actual_value, _reasons = evaluate_custom_condition_detailed(compiled, item, by_id)
        outcomes[item.event_id] = "match" if actual_value is True else "nonmatch" if actual_value is False else "unknown"
    probe_events, probe_by_id, _probe_labels = _fixture_events([probe], target=recipe["target"])
    probe_outcome, _probe_reasons = evaluate_custom_condition_detailed(compiled, probe_events[0], probe_by_id)
    probe_actual = "match" if probe_outcome is True else "nonmatch" if probe_outcome is False else "unknown"
    checks = [{"label": "positive", "expected": "match", "actual": outcomes[positive.fixture_id],
               "passed": outcomes[positive.fixture_id] == "match"},
              *[{"label": "negative control" if fixture.fixture_id == "assistant-negative" else "near-miss control",
                 "expected": "nonmatch", "actual": outcomes[fixture.fixture_id],
                 "passed": outcomes[fixture.fixture_id] == "nonmatch"}
                for fixture in fixtures if fixture.label == "negative"],
              {"label": "unknown probe", "expected": "unknown", "actual": probe_actual,
               "passed": probe_actual == "unknown"}]
    rule = {"slug": recipe["id"].replace("_", "-"), "name": recipe["title"],
            "description": recipe["description"], "category": "custom", "target": recipe["target"],
            "expression": render_expression(compiled), "severity_weight": 0.25,
            "confidence_weight": 0.25, "incident_eligible": False}
    return {"rule": rule, "fixtures": [fixture.model_dump(exclude_none=True) for fixture in fixtures],
            "probes": [probe.model_dump(exclude_none=True)],
            "checks": checks, "requirements": recipe["requirements"], "limitations": recipe["limitations"],
            "ready": all(check["passed"] for check in checks)}


def _evaluate_preview(rule: CustomDetectionRule, revision: CustomDetectionRuleRevision,
                      source: PreviewIn, db: Session, actor: str, kind: str) -> dict[str, Any]:
    content = _revision_content(revision)
    if source.fixtures:
        events, by_id, labels = _fixture_events(source.fixtures, target=content["target"])
        provenance = {"source": "labeled_local_fixtures", "event_count": len(events),
                      "labels": {"positive": sum(v == "positive" for v in labels.values()),
                                 "negative": sum(v == "negative" for v in labels.values())},
                      "fixture_ids": list(labels), "coverage": "software_fixture_only",
                      "identity": "synthetic_fixture_metadata_not_observed_telemetry"}
    else:
        events, by_id, provenance = _db_events(rule, source.event_ids, db)
        labels = {}
    if not events or len(events) > MAX_PREVIEW_EVENTS:
        raise HTTPException(422, "Preview must contain between 1 and 250 events")
    outcomes: list[dict[str, Any]] = []
    reason_counts: dict[str, int] = {}
    work_budget = EvaluationBudget(MAX_PREVIEW_EVALUATION_OPERATIONS)
    budget_exhausted = False
    for index, event in enumerate(events):
        try:
            outcome, reasons = evaluate_custom_condition_detailed(
                content["condition"], event, by_id, work_budget
            )
        except RuleEvaluationBudgetExceeded:
            budget_exhausted = True
            for unprocessed in events[index:]:
                outcomes.append({"event_id": unprocessed.event_id, "outcome": "unknown",
                                 "label": labels.get(unprocessed.event_id),
                                 "reasons": [{"field": "*", "operator": "*", "scope": "evaluation",
                                              "reason": "budget_exhausted"}]})
            reason_counts["*:budget_exhausted"] = len(events) - index
            break
        status = "match" if outcome is True else "nonmatch" if outcome is False else "unknown"
        outcomes.append({"event_id": event.event_id, "outcome": status,
                         "label": labels.get(event.event_id), "reasons": reasons[:8]})
        for reason in reasons:
            key = f"{reason.get('field', 'unknown')}:{reason.get('reason', 'unknown')}"
            reason_counts[key] = reason_counts.get(key, 0) + 1
    if len(json.dumps(outcomes)) > 96_000:
        raise HTTPException(422, "Preview result exceeds the bounded output size")
    result = {"match_count": sum(item["outcome"] == "match" for item in outcomes),
              "nonmatch_count": sum(item["outcome"] == "nonmatch" for item in outcomes),
              "unknown_count": sum(item["outcome"] == "unknown" for item in outcomes),
              "reason_counts": reason_counts, "outcomes": outcomes,
              "budget_exhausted": budget_exhausted,
              "work_operations": work_budget.used,
              "work_limit": MAX_PREVIEW_EVALUATION_OPERATIONS}
    if labels:
        result["labeled_outcomes"] = {
            label: {"count": sum(o["label"] == label for o in outcomes),
                    "match": sum(o["outcome"] == "match" and o["label"] == label for o in outcomes),
                    "nonmatch": sum(o["outcome"] == "nonmatch" and o["label"] == label for o in outcomes),
                    "unknown": sum(o["outcome"] == "unknown" and o["label"] == label for o in outcomes)}
            for label in ("positive", "negative")}
    receipt_id = str(uuid4())
    created_at = datetime.now(UTC)
    expires_at = created_at + timedelta(days=7)
    interpreter_hash = _sha(CUSTOM_RULE_INTERPRETER_CONTRACT)
    receipt_doc = {"receipt_id": receipt_id, "rule_id": rule.custom_rule_id,
                   "revision_hash": revision.revision_hash, "kind": kind,
                   "interpreter_hash": interpreter_hash,
                   "created_at": created_at.isoformat(), "expires_at": expires_at.isoformat(),
                   "provenance": provenance, "result": result}
    receipt_hash = _sha(receipt_doc)
    receipt = CustomDetectionRuleReceipt(
        receipt_id=receipt_id, custom_rule_id=rule.custom_rule_id,
        revision_hash=revision.revision_hash, kind=kind,
        interpreter_hash=interpreter_hash, provenance=provenance,
        result=result, receipt_hash=receipt_hash, reviewed_by=None,
        created_by=actor, created_at=created_at, expires_at=expires_at,
    )
    db.add(receipt)
    _insert_audit(db, rule.custom_rule_id, kind, actor, revision.revision_hash,
                  details={"receipt_hash": receipt_hash, "counts": {k: v for k, v in result.items() if k.endswith("_count")}})
    db.flush()
    old_receipt_ids = list(db.scalars(
        select(CustomDetectionRuleReceipt.receipt_id)
        .where(CustomDetectionRuleReceipt.custom_rule_id == rule.custom_rule_id)
        .order_by(desc(CustomDetectionRuleReceipt.created_at), desc(CustomDetectionRuleReceipt.receipt_id))
        .offset(50)
    ).all())
    if old_receipt_ids:
        db.execute(delete(CustomDetectionRuleReceipt).where(
            CustomDetectionRuleReceipt.receipt_id.in_(old_receipt_ids)
        ))
    return {**receipt_doc, "receipt_hash": receipt_hash}


def _current_revision(db: Session, rule: CustomDetectionRule) -> CustomDetectionRuleRevision:
    if not rule.current_revision_hash:
        raise HTTPException(409, "This legacy rule has no immutable authored revision")
    revision = db.get(CustomDetectionRuleRevision, rule.current_revision_hash)
    if revision is None or revision.custom_rule_id != rule.custom_rule_id:
        raise HTTPException(409, "Current rule revision is unavailable")
    _revision_content(revision)
    return revision


@router.post("/operator/v1/rule-workbench/rules/{rule_id}/preview", dependencies=[Depends(require_operator_token)])
def preview_rule(rule_id: str, payload: PreviewIn, db: Session = Depends(get_db)) -> dict[str, Any]:  # noqa: B008
    actor = _actor()
    rule = _get_rule(db, rule_id, for_update=True)
    if (rule.lifecycle_state == "active" and rule.current_revision_hash == rule.active_revision_hash
            and rule.candidate_state not in {"draft", "shadow"}):
        raise HTTPException(409, "The current revision is already live; edit a candidate before preview")
    revision = _current_revision(db, rule)
    if payload.expected_revision_hash != revision.revision_hash:
        raise HTTPException(409, "Preview must reference the current revision displayed to the operator")
    result = _evaluate_preview(rule, revision, payload, db, actor, "preview")
    db.commit()
    return result


@router.post("/operator/v1/rule-workbench/rules/{rule_id}/shadow", dependencies=[Depends(require_operator_token)])
def shadow_rule(rule_id: str, payload: PreviewIn, db: Session = Depends(get_db)) -> dict[str, Any]:  # noqa: B008
    actor = _actor()
    rule = _get_rule(db, rule_id, for_update=True)
    if (rule.lifecycle_state == "active" and rule.current_revision_hash == rule.active_revision_hash
            and rule.candidate_state not in {"draft", "shadow"}):
        raise HTTPException(409, "The current revision is already live; edit a candidate before shadow review")
    conflict = db.scalar(select(CustomDetectionRule).where(
        CustomDetectionRule.slug == rule.slug,
        CustomDetectionRule.custom_rule_id != rule.custom_rule_id,
        CustomDetectionRule.lifecycle_state != "disabled",
    ))
    if conflict:
        raise HTTPException(409, "Another non-disabled rule already uses this slug")
    revision = _current_revision(db, rule)
    if payload.expected_revision_hash != revision.revision_hash:
        raise HTTPException(409, "Shadow review must reference the current revision displayed to the operator")
    result = _evaluate_preview(rule, revision, payload, db, actor, "shadow")
    if not rule.enabled:
        rule.lifecycle_state = "shadow"
    rule.candidate_state = "shadow"
    rule.updated_at = datetime.now(UTC)
    _insert_audit(db, rule_id, "shadow_entered", actor, revision.revision_hash,
                  details={"receipt_hash": result["receipt_hash"]})
    db.commit()
    return result


def _candidate_staging_floor(db: Session, rule_id: str, revision_hash: str) -> datetime | None:
    staging_actions = {"draft_created", "revision_created", "rollback_staged"}
    rows = db.scalars(select(CustomDetectionRuleAudit).where(
        CustomDetectionRuleAudit.custom_rule_id == rule_id,
        CustomDetectionRuleAudit.revision_hash == revision_hash,
        CustomDetectionRuleAudit.action.in_(staging_actions),
    ).order_by(desc(CustomDetectionRuleAudit.created_at)).limit(1)).all()
    if not rows:
        return None
    created_at = rows[0].created_at
    return created_at.replace(tzinfo=UTC) if created_at.tzinfo is None else created_at


def _fresh_receipt(db: Session, rule_id: str, revision_hash: str, kind: str,
                   staging_floor: datetime | None = None) -> CustomDetectionRuleReceipt | None:
    receipts = db.scalars(select(CustomDetectionRuleReceipt).where(
        CustomDetectionRuleReceipt.custom_rule_id == rule_id,
        CustomDetectionRuleReceipt.revision_hash == revision_hash,
        CustomDetectionRuleReceipt.kind == kind,
    ).order_by(desc(CustomDetectionRuleReceipt.created_at), desc(CustomDetectionRuleReceipt.receipt_id)).limit(50)).all()
    receipt = next((item for item in receipts
                    if item.provenance.get("source") == "labeled_local_fixtures"), None)
    if receipt is None:
        return None
    created_at = receipt.created_at
    expires_at = receipt.expires_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    now = datetime.now(UTC)
    interpreter_hash = _sha(CUSTOM_RULE_INTERPRETER_CONTRACT)
    receipt_doc = {"receipt_id": receipt.receipt_id, "rule_id": receipt.custom_rule_id,
                   "revision_hash": receipt.revision_hash, "kind": receipt.kind,
                   "interpreter_hash": receipt.interpreter_hash,
                   "created_at": created_at.isoformat(), "expires_at": expires_at.isoformat(),
                   "provenance": receipt.provenance, "result": receipt.result}
    if (_sha(receipt_doc) != receipt.receipt_hash or receipt.interpreter_hash != interpreter_hash
            or created_at > now or expires_at <= now or expires_at - created_at > timedelta(days=7)):
        return None
    if (receipt.result.get("match_count", 0) <= 0 or receipt.result.get("unknown_count", 0) != 0
            or receipt.result.get("budget_exhausted", False)):
        return None
    if staging_floor is not None and created_at <= staging_floor:
        return None
    # Event-backed previews remain exploratory and cannot authorize activation.
    if receipt.provenance.get("source") != "labeled_local_fixtures":
        return None
    labeled = receipt.result.get("labeled_outcomes")
    positive = labeled.get("positive", {}) if isinstance(labeled, dict) else {}
    negative = labeled.get("negative", {}) if isinstance(labeled, dict) else {}
    if (positive.get("count", 0) <= 0 or negative.get("count", 0) <= 0
            or positive.get("match", 0) <= 0 or positive.get("nonmatch", 0) != 0
            or positive.get("unknown", 0) != 0 or negative.get("match", 0) != 0
            or negative.get("nonmatch", 0) <= 0 or negative.get("unknown", 0) != 0):
        return None
    audit = db.scalar(select(CustomDetectionRuleAudit.audit_id).where(
        CustomDetectionRuleAudit.custom_rule_id == rule_id,
        CustomDetectionRuleAudit.revision_hash == revision_hash,
        CustomDetectionRuleAudit.action == kind,
        CustomDetectionRuleAudit.details["receipt_hash"].as_string() == receipt.receipt_hash,
    ).limit(1))
    if audit is None:
        return None
    return receipt


def _has_fresh_receipt(db: Session, rule_id: str, revision_hash: str, kind: str,
                       staging_floor: datetime | None = None) -> bool:
    return _fresh_receipt(db, rule_id, revision_hash, kind, staging_floor) is not None


def _check_activation_capacity(db: Session, rule: CustomDetectionRule,
                               revision: CustomDetectionRuleRevision) -> None:
    """Serialize activations and refuse oversized sets without silently dropping rules."""
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": 0x505952474F4E})
    snapshot = resolve_active_snapshot(db)
    replaced_hashes = {item["revision_hash"] for item in snapshot["revisions"]
                       if item["rule_id"] == rule.custom_rule_id}
    proposed_rules = [item for item in snapshot["rules"]
                      if item.get("revision_hash") not in replaced_hashes]
    proposed_rules.append({**revision.document, "enabled": True, "revision_hash": revision.revision_hash})
    proposed_rules.sort(key=lambda item: (item["slug"], item["revision_hash"]))
    try:
        ruleset_hash = custom_ruleset_hash(proposed_rules)
    except RuleSetCapacityExceeded as exc:
        raise HTTPException(409, {"code": "ruleset_capacity_exceeded", "detail": str(exc)}) from exc
    revisions = [item for item in snapshot["revisions"] if item["rule_id"] != rule.custom_rule_id]
    revisions.append({"rule_id": rule.custom_rule_id, "slug": revision.document["slug"],
                      "revision_hash": revision.revision_hash, "content": revision.document,
                      "provenance": revision.provenance})
    revisions.sort(key=lambda item: (item["slug"], item["revision_hash"]))
    projection = {"schema": "porygon.custom-ruleset",
                  "interpreter_hash": snapshot["interpreter_hash"],
                  "revisions": revisions, "rules": proposed_rules,
                  "ruleset_hash": ruleset_hash}
    projection["snapshot_hash"] = "0" * 64
    size = len(_canonical(projection).encode("utf-8"))
    if size > MAX_CUSTOM_RULE_SNAPSHOT_BYTES:
        raise HTTPException(409, {"code": "ruleset_capacity_exceeded",
                                  "detail": "active custom rule snapshot exceeds the configured byte cap"})


def _activate(db: Session, rule: CustomDetectionRule, actor: str, reference: str,
              expected_revision_hash: str | None,
              revision: CustomDetectionRuleRevision) -> dict[str, Any]:
    if not expected_revision_hash or expected_revision_hash != revision.revision_hash:
        raise HTTPException(409, "Activation must reference the current revision displayed to the operator")
    if rule.candidate_state != "shadow":
        raise HTTPException(409, "Activation requires the current revision to complete shadow review")
    if rule.lifecycle_state not in {"draft", "shadow", "disabled", "active"}:
        raise HTTPException(409, "Rule state cannot be activated")
    staging_floor = _candidate_staging_floor(db, rule.custom_rule_id, revision.revision_hash)
    if staging_floor is None:
        raise HTTPException(409, "Activation requires a staged candidate revision")
    preview_receipt = _fresh_receipt(db, rule.custom_rule_id, revision.revision_hash,
                                     "preview", staging_floor)
    shadow_receipt = _fresh_receipt(db, rule.custom_rule_id, revision.revision_hash,
                                    "shadow", staging_floor)
    if preview_receipt is None:
        raise HTTPException(409, "Activation requires a matching, current preview with no unknown evidence")
    if shadow_receipt is None:
        raise HTTPException(409, "Activation requires a matching shadow evaluation")
    conflict = db.scalar(select(CustomDetectionRule).where(
        CustomDetectionRule.slug == rule.slug,
        CustomDetectionRule.custom_rule_id != rule.custom_rule_id,
        CustomDetectionRule.lifecycle_state != "disabled",
    ))
    if conflict:
        raise HTTPException(409, "Another non-disabled rule uses this stable slug")
    _check_activation_capacity(db, rule, revision)
    rule.lifecycle_state = "active"
    rule.enabled = True
    rule.active_revision_hash = revision.revision_hash
    rule.candidate_state = "none"
    rule.disabled_at = None
    rule.disabled_by = None
    rule.updated_at = datetime.now(UTC)
    _insert_audit(db, rule.custom_rule_id, "activated", actor, revision.revision_hash, reference,
                  {"preview_receipt_hash": preview_receipt.receipt_hash,
                   "shadow_receipt_hash": shadow_receipt.receipt_hash,
                   "review_basis": "explicit_authenticated_operator_review"})
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Another rule claimed this stable slug during activation") from exc
    db.refresh(rule)
    return _rule_output(rule, revision)


@router.post("/operator/v1/rule-workbench/rules/{rule_id}/activate", dependencies=[Depends(require_operator_token)])
def activate_rule(rule_id: str, payload: RuleTransitionIn, db: Session = Depends(get_db)) -> dict[str, Any]:  # noqa: B008
    actor = _actor()
    rule = _get_rule(db, rule_id, for_update=True)
    revision = _current_revision(db, rule)
    return _activate(db, rule, actor, payload.reference, payload.expected_revision_hash, revision)


@router.post("/operator/v1/rule-workbench/rules/{rule_id}/disable", dependencies=[Depends(require_operator_token)])
def disable_rule(rule_id: str, payload: RuleTransitionIn, db: Session = Depends(get_db)) -> dict[str, Any]:  # noqa: B008
    actor = _actor()
    rule = _get_rule(db, rule_id, for_update=True)
    if payload.expected_revision_hash and rule.current_revision_hash != payload.expected_revision_hash:
        raise HTTPException(409, "Rule revision changed since it was opened; refresh before disabling")
    if rule.lifecycle_state == "disabled" and not rule.enabled:
        return _rule_output(rule)
    rule.lifecycle_state = "disabled"
    affected_revision_hash = rule.active_revision_hash or rule.current_revision_hash
    rule.enabled = False
    rule.disabled_at = datetime.now(UTC)
    rule.disabled_by = actor
    rule.updated_at = rule.disabled_at
    _insert_audit(db, rule_id, "disabled", actor, affected_revision_hash, payload.reference,
                  {"candidate_revision_hash": rule.current_revision_hash})
    db.commit()
    db.refresh(rule)
    return _rule_output(rule)


@router.post("/operator/v1/rule-workbench/rules/{rule_id}/rollback", dependencies=[Depends(require_operator_token)])
def rollback_rule(rule_id: str, payload: RollbackIn, db: Session = Depends(get_db)) -> dict[str, Any]:  # noqa: B008
    actor = _actor()
    rule = _get_rule(db, rule_id, for_update=True)
    if not payload.expected_revision_hash or rule.current_revision_hash != payload.expected_revision_hash:
        raise HTTPException(409, "Rollback must reference the current revision displayed to the operator")
    revision = db.get(CustomDetectionRuleRevision, payload.revision_hash)
    if revision is None or revision.custom_rule_id != rule_id:
        raise HTTPException(404, "Immutable revision not found for this rule")
    _revision_content(revision)
    conflict = db.scalar(select(CustomDetectionRule).where(
        CustomDetectionRule.slug == revision.document["slug"],
        CustomDetectionRule.custom_rule_id != rule_id,
        CustomDetectionRule.lifecycle_state != "disabled",
    ))
    if conflict:
        raise HTTPException(409, "Another non-disabled rule currently owns this stable slug")
    previous_hash = rule.current_revision_hash
    content = revision.document
    rule.slug = content["slug"]
    rule.name = content["name"]
    rule.description = content["description"]
    rule.category = content["category"]
    rule.target = content["target"]
    rule.condition = content["condition"]
    rule.severity_weight = content["severity_weight"]
    rule.confidence_weight = content["confidence_weight"]
    rule.incident_eligible = content["incident_eligible"]
    rule.current_revision_hash = revision.revision_hash
    rule.candidate_state = "draft"
    if not rule.enabled and rule.lifecycle_state not in {"disabled", "legacy_active", "active"}:
        rule.lifecycle_state = "draft"
    rule.updated_at = datetime.now(UTC)
    _insert_audit(db, rule_id, "rollback_staged", actor, revision.revision_hash, payload.reference,
                  {"previous_revision_hash": previous_hash})
    db.commit()
    db.refresh(rule)
    return _rule_output(rule, revision)


@router.get("/api/v1/rule-workbench/runs/{run_id}/ruleset")
def get_run_ruleset(run_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:  # noqa: B008
    run = db.get(DetectionRun, run_id)
    if run is None:
        raise HTTPException(404, "Detection run not found")
    if run.custom_rule_snapshot is None:
        return {"status": "unavailable_legacy_content", "custom_ruleset_hash": run.custom_ruleset_hash}
    snapshot = run.custom_rule_snapshot
    if len(_canonical(snapshot).encode("utf-8")) > MAX_CUSTOM_RULE_SNAPSHOT_BYTES:
        raise HTTPException(409, "Stored detection ruleset snapshot exceeds its integrity bound")
    expected = snapshot.get("snapshot_hash")
    projection = {key: value for key, value in snapshot.items() if key != "snapshot_hash"}
    if _sha(projection) != expected or run.custom_rule_interpreter_hash != snapshot.get("interpreter_hash"):
        raise HTTPException(409, "Stored detection ruleset snapshot failed integrity verification")
    if custom_ruleset_hash(snapshot.get("rules", [])) != snapshot.get("ruleset_hash"):
        raise HTTPException(409, "Stored detection ruleset content failed integrity verification")
    return {"status": "available", **snapshot}


def resolve_active_snapshot(db: Session) -> dict[str, Any]:
    """Build and verify the exact active content passed to a newly-created run."""
    rows = db.scalars(select(CustomDetectionRule).where(
        CustomDetectionRule.lifecycle_state.in_(("legacy_active", "active")),
        CustomDetectionRule.enabled.is_(True),
    ).order_by(CustomDetectionRule.slug, CustomDetectionRule.custom_rule_id)
        .limit(MAX_ACTIVE_CUSTOM_RULES + 1)).all()
    if len(rows) > MAX_ACTIVE_CUSTOM_RULES:
        raise HTTPException(409, {"code": "ruleset_capacity_exceeded",
                                  "detail": "active custom rule count exceeds the configured cap"})
    rules: list[dict[str, Any]] = []
    revisions: list[dict[str, Any]] = []
    for row in rows:
        if row.lifecycle_state == "legacy_active" and row.active_revision_hash is None:
            if row.current_revision_hash:
                legacy_revision = db.get(CustomDetectionRuleRevision, row.current_revision_hash)
                if legacy_revision is None or legacy_revision.custom_rule_id != row.custom_rule_id:
                    raise HTTPException(409, "Legacy rule content is unavailable; refusing to invent active history")
                _revision_content(legacy_revision)
                row.active_revision_hash = legacy_revision.revision_hash
            else:
                # No historical authored revision exists; capture this exact legacy
                # enabled row as an explicit current-state migration artifact.
                content = {
                    "slug": row.slug, "name": row.name, "description": row.description,
                    "category": row.category, "target": row.target, "condition": row.condition,
                    "severity_weight": row.severity_weight, "confidence_weight": row.confidence_weight,
                    "incident_eligible": row.incident_eligible,
                }
                _validate_revision_document_bounds(content)
                revision_hash = _revision_hash(row.custom_rule_id, content)
                revision = db.get(CustomDetectionRuleRevision, revision_hash)
                if revision is None:
                    # Nested transaction prevents this provenance materialization from committing
                    # or rolling back the caller's assessment transaction.
                    try:
                        with db.begin_nested():
                            db.add(CustomDetectionRuleRevision(
                                revision_hash=revision_hash, custom_rule_id=row.custom_rule_id,
                                document=content, provenance="legacy_current_state",
                                created_by=row.created_by, created_at=row.created_at,
                            ))
                            db.flush()
                    except IntegrityError:
                        revision = db.get(CustomDetectionRuleRevision, revision_hash)
                row.current_revision_hash = revision_hash
                row.active_revision_hash = revision_hash
            row.candidate_state = "none"
        active_hash = row.active_revision_hash
        if not active_hash:
            raise HTTPException(409, "Active rule has no immutable active revision pointer")
        revision = db.get(CustomDetectionRuleRevision, active_hash)
        if revision is None or revision.custom_rule_id != row.custom_rule_id:
            raise HTTPException(409, "Active immutable rule revision is unavailable")
        content = _revision_content(revision)
        rules.append({**content, "enabled": True, "revision_hash": revision.revision_hash})
        revisions.append({"rule_id": row.custom_rule_id, "slug": row.slug,
                          "revision_hash": revision.revision_hash, "content": content,
                          "provenance": revision.provenance})
    rules.sort(key=lambda item: (item["slug"], item["revision_hash"]))
    revisions.sort(key=lambda item: (item["slug"], item["revision_hash"]))
    interpreter_hash = _sha(CUSTOM_RULE_INTERPRETER_CONTRACT)
    projection = {"schema": "porygon.custom-ruleset", "interpreter_hash": interpreter_hash,
                  "revisions": revisions, "rules": rules}
    try:
        ruleset_hash = custom_ruleset_hash(rules)
    except RuleSetCapacityExceeded as exc:
        raise HTTPException(409, {"code": "ruleset_capacity_exceeded", "detail": str(exc)}) from exc
    snapshot = {**projection, "ruleset_hash": ruleset_hash}
    if len(_canonical({**snapshot, "snapshot_hash": "0" * 64}).encode("utf-8")) > MAX_CUSTOM_RULE_SNAPSHOT_BYTES:
        raise HTTPException(409, {"code": "ruleset_capacity_exceeded",
                                  "detail": "active custom rule snapshot exceeds the configured byte cap"})
    snapshot["snapshot_hash"] = _sha(snapshot)
    return snapshot
