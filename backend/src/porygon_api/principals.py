"""Verified request identities; shared local credentials are explicitly legacy."""
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class Principal:
    subject: str
    kind: Literal['operator', 'service']
    roles: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    host_ids: tuple[str, ...] = ()
    credential_id: str | None = None
    service_name: str | None = None
    instance_id: str | None = None
    legacy: bool = False


LOCAL_INTERNAL_PRINCIPAL = Principal('local-internal', 'service', legacy=True)
LOCAL_OPERATOR_PRINCIPAL = Principal('local-operator', 'operator', roles=('admin',), legacy=True)
CURRENT_PRINCIPAL: ContextVar[Principal | None] = ContextVar('porygon_principal', default=None)


def current_principal() -> Principal | None:
    return CURRENT_PRINCIPAL.get()


def audit_subject(trusted_fallback: str) -> str:
    """HTTP actors come from credentials; direct Python callers remain trusted."""
    principal = current_principal()
    return principal.subject if principal is not None else trusted_fallback
