"""Explicit route permission inventory; unclassified handlers fail closed."""
from fastapi import HTTPException
from porygon_api.principals import Principal

ROLE_PERMISSIONS = {
    'viewer': frozenset({'read'}),
    'analyst': frozenset({'read','analyst','assess'}),
    'responder': frozenset({'read','analyst','assess','respond'}),
    'admin': frozenset({'read','analyst','assess','respond','admin'}),
}
SERVICE_SCOPES = frozenset({'ingest_runtime','ingest_process','ingest_kernel','heartbeat','scan_worker','response_worker'})
SERVICE_PURPOSES = {
    'collector': frozenset({'ingest_runtime','heartbeat'}),
    'telemetry': frozenset({'ingest_process','ingest_kernel','heartbeat'}),
    'scanner': frozenset({'scan_worker','heartbeat'}),
    'responder': frozenset({'response_worker','heartbeat'}),
}
ROUTE_PERMISSIONS = {
    ('GET','/api/v1/health-metrics'): 'read',
    ('GET','/api/v1/notification-deliveries'): 'read',
    ('POST','/operator/v1/notification-deliveries/{delivery_id}/repair-config'): 'admin',
    ('POST','/operator/v1/advisory-models/{artifact_hash}/quality-lock'): 'admin',
    ('GET','/api/v1/runtime-evidence'): 'read',
    ('GET','/api/v1/runtime-evidence/{bundle_hash}'): 'read',
    ('POST','/operator/v1/advisory-models'): 'admin',
    ('POST','/operator/v1/advisory-models/{artifact_hash}/activate'): 'admin',
    ('GET', '/api/v1/assessment-targets/{target_id}/audit'): 'read',
    ('POST', '/operator/v1/assessment-targets'): 'admin',
    ('POST', '/operator/v1/assessment-targets/{target_id}/profiles'): 'analyst',
    ('POST', '/operator/v1/assessment-targets/{target_id}/profiles/{enrollment_id}/shadow'): 'analyst',
    ('POST', '/operator/v1/assessment-targets/{target_id}/profiles/{enrollment_id}/activate'): 'admin',
    ('POST', '/operator/v1/assessment-targets/{target_id}/profiles/{enrollment_id}/rollback'): 'admin',
    ('POST', '/operator/v1/assessment-targets/{target_id}/disable'): 'admin',
    ('POST', '/operator/v1/assessment-targets/{target_id}/reprocess'): 'analyst',
    ('GET', '/api/v1/assessment-targets'): 'read',
    ('GET', '/api/v1/assessment-targets/{target_id}/profiles'): 'read',
    ('GET', '/api/v1/assessment-jobs'): 'read',
    ('GET', '/api/v1/assessment-worker/status'): 'read',

    ('GET', '/api/v1/reconciliation/status'): 'read',
    ('GET', '/'): 'read',
    ('GET', '/health/live'): 'public',
    ('GET', '/health/ready'): 'public',
    ('POST', '/internal/v1/heartbeats'): 'heartbeat',
    ('POST', '/internal/v1/events/batch'): 'ingest_runtime',
    ('POST', '/internal/v1/process-events/reconcile'): 'admin',
    ('POST', '/internal/v1/process-events/batch'): 'ingest_process',
    ('GET', '/api/v1/services'): 'read',
    ('GET', '/api/v1/events'): 'read',
    ('GET', '/api/v1/events/summary'): 'read',
    ('GET', '/api/v1/events/{event_id}'): 'read',
    ('GET', '/api/v1/process-events'): 'read',
    ('GET', '/api/v1/process-events/summary'): 'read',
    ('GET', '/api/v1/process-events/{event_id}'): 'read',
    ('POST', '/internal/v1/baselines/build'): 'admin',
    ('POST', '/internal/v1/baselines/{profile_id}/activate'): 'admin',
    ('GET', '/api/v1/baselines'): 'read',
    ('GET', '/api/v1/baselines/active'): 'read',
    ('GET', '/api/v1/baselines/{profile_id}'): 'read',
    ('POST', '/internal/calibrated/rarity-models'): 'admin',
    ('GET', '/api/calibrated/rarity-models/{model_id}'): 'read',
    ('POST', '/internal/calibrated/rarity-scores'): 'assess',
    ('GET', '/api/calibrated/rarity-scores/{score_id}'): 'read',
    ('POST', '/internal/v1/anomaly-scores/compute'): 'assess',
    ('GET', '/api/v1/anomaly-scores/config'): 'read',
    ('GET', '/api/v1/anomaly-scores'): 'read',
    ('GET', '/api/v1/anomaly-scores/{score_id}'): 'read',
    ('GET', '/api/v1/detection-rules/config'): 'read',
    ('GET', '/api/v1/detection-allowlists'): 'read',
    ('POST', '/internal/v1/detection-allowlists'): 'analyst',
    ('POST', '/internal/v1/detection-allowlists/{allowlist_id}/deactivate'): 'analyst',
    ('GET', '/api/v1/custom-detection-rules'): 'read',
    ('POST', '/operator/v1/custom-detection-rules'): 'admin',
    ('POST', '/operator/v1/custom-detection-rules/{custom_rule_id}/disable'): 'admin',
    ('POST', '/operator/v1/custom-detection-rules/{custom_rule_id}/enable'): 'admin',
    ('POST', '/internal/v1/detections/run'): 'assess',
    ('GET', '/api/v1/detection-runs'): 'read',
    ('GET', '/api/v1/detection-runs/{run_id}'): 'read',
    ('GET', '/api/v1/incidents'): 'read',
    ('GET', '/api/v1/incidents/{incident_id}'): 'read',
    ('GET', '/api/v1/incidents/{incident_id}/timeline'): 'read',
    ('POST', '/internal/v1/incidents/{incident_id}/status'): 'analyst',
    ('POST', '/operator/v1/incidents/{incident_id}/status'): 'analyst',
    ('POST', '/operator/v1/incidents/clean-all'): 'analyst',
    ('GET', '/api/v1/images'): 'read',
    ('GET', '/api/v1/containers'): 'read',
    ('POST', '/api/v1/ai/audit'): 'analyst',
    ('GET', '/api/v1/ml/model-info'): 'read',
    ('POST', '/api/v1/ml/classify'): 'read',
    ('POST', '/api/v1/ml/classify-container/{container_id}'): 'read',
    ('POST', '/api/v1/ml/classify-features'): 'read',
    ('GET', '/api/v1/system/info'): 'read',
    ('GET', '/api/v1/response-policy'): 'read',
    ('POST', '/operator/v1/incidents/{incident_id}/response-recommendations'): 'respond',
    ('GET', '/api/v1/response-recommendations'): 'read',
    ('GET', '/api/v1/response-recommendations/{recommendation_id}'): 'read',
    ('POST', '/operator/v1/response-recommendations/{recommendation_id}/approve'): 'respond',
    ('POST', '/operator/v1/response-recommendations/{recommendation_id}/reject'): 'respond',
    ('POST', '/internal/v1/response-executions/claim'): 'response_worker',
    ('POST', '/internal/v1/response-executions/{execution_id}/complete'): 'response_worker',
    ('POST', '/operator/v1/response-executions/{execution_id}/rollback'): 'respond',
    ('POST', '/operator/v1/response-executions/{execution_id}/retry'): 'respond',
    ('GET', '/api/v1/response-executions'): 'read',
    ('GET', '/api/v1/response-executions/{execution_id}'): 'response_status',
    ('GET', '/api/v1/incidents/{incident_id}/response-audit'): 'read',
    ('GET', '/api/v1/vulnerability-policy'): 'read',
    ('POST', '/operator/v1/image-scans'): 'analyst',
    ('POST', '/internal/v1/image-scans/claim'): 'scan_worker',
    ('POST', '/internal/v1/image-scans/{scan_id}/renew'): 'scan_worker',
    ('POST', '/internal/v1/image-scans/{scan_id}/complete'): 'scan_worker',
    ('POST', '/internal/v1/image-scans/{scan_id}/fail'): 'scan_worker',
    ('GET', '/api/v1/image-scans'): 'read',
    ('GET', '/api/v1/image-scans/{scan_id}'): 'read',
    ('GET', '/api/v1/image-scans/{scan_id}/report'): 'read',
    ('GET', '/api/v1/image-scans/{scan_id}/sbom'): 'read',
    ('GET', '/api/v1/vulnerabilities'): 'read',
    ('GET', '/api/v1/vulnerability-intel/{cve_id}'): 'read',
    ('POST', '/internal/v1/retention/run'): 'admin',
    ('POST', '/internal/v1/kernel-events/batch'): 'ingest_kernel',
    ('GET', '/api/v1/kernel-events'): 'read',
    ('GET', '/api/v1/kernel-events/summary'): 'read',
    ('POST', '/operator/v1/kernel-events/reconcile'): 'admin',
    ('GET', '/api/v1/kernel-events/{event_id}'): 'read',
    ('GET', '/docs'): 'read',
    ('GET', '/docs/oauth2-redirect'): 'read',
    ('GET', '/redoc'): 'read',
    ('GET', '/openapi.json'): 'read',
    ('GET', '/operator/v1/credentials'): 'admin',
    ('POST', '/operator/v1/credentials'): 'admin',
    ('POST', '/operator/v1/credentials/{credential_id}/rotate'): 'admin',
    ('POST', '/operator/v1/credentials/{credential_id}/revoke'): 'admin',
}


def require_permission(principal: Principal, permission: str, path: str) -> None:
    if permission == 'public':
        return
    if principal.legacy:
        if path.startswith('/operator/') and principal.kind != 'operator':
            raise HTTPException(401, 'Operator credential required')
        return
    allowed = (set().union(*(ROLE_PERMISSIONS.get(role, ()) for role in principal.roles))
               if principal.kind == 'operator' else set(principal.scopes))
    if permission == 'response_status' and ({'read','response_worker'} & allowed):
        return
    if permission not in allowed:
        raise HTTPException(403, 'Credential lacks the required permission')


def authorization_routes(app):
    """Use FastAPI's public effective-route API, including nested prefixes.

    The pinned FastAPI dependency exposes iter_route_contexts; unsupported router
    objects have no usable path/match and therefore never receive permission.
    """
    from fastapi.routing import iter_route_contexts
    yield from iter_route_contexts(app.router.routes)
