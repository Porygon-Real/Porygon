from __future__ import annotations

import secrets
from fastapi import Header, HTTPException
from porygon_api.config import get_settings
from porygon_api.principals import (
    Principal, LOCAL_INTERNAL_PRINCIPAL, LOCAL_OPERATOR_PRINCIPAL, current_principal,
)


def require_internal_token(
    x_porygon_internal_token: str | None = Header(default=None, alias='X-Porygon-Internal-Token'),
) -> Principal:
    principal = current_principal()
    if principal is not None:
        return principal  # HTTP permission matrix has already checked the route.
    settings = get_settings()
    if getattr(settings, 'access_mode', 'local') == 'local' and isinstance(x_porygon_internal_token, str):
        if secrets.compare_digest(x_porygon_internal_token, settings.internal_api_token.get_secret_value()):
            return LOCAL_INTERNAL_PRINCIPAL
    raise HTTPException(422 if x_porygon_internal_token is None else 401, 'Invalid internal credential')


def require_operator_token(
    x_porygon_operator_token: str | None = Header(default=None, alias='X-Porygon-Operator-Token'),
) -> Principal:
    principal = current_principal()
    if principal is not None:
        if principal.kind != 'operator':
            raise HTTPException(403, 'Operator credential required')
        return principal
    settings = get_settings()
    if getattr(settings, 'access_mode', 'local') == 'local' and isinstance(x_porygon_operator_token, str):
        if secrets.compare_digest(x_porygon_operator_token, settings.operator_api_token.get_secret_value()):
            return LOCAL_OPERATOR_PRINCIPAL
    raise HTTPException(422 if x_porygon_operator_token is None else 401, 'Invalid operator credential')
