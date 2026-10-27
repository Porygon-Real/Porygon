"""Every method/path must carry an explicit authorization decision."""
from porygon_api import main
from porygon_api.permissions import ROUTE_PERMISSIONS, require_permission, authorization_routes
from porygon_api.principals import Principal
from fastapi import HTTPException
import pytest


def test_all_routes_have_explicit_permissions():
    for route in authorization_routes(main.app):
        for method in getattr(route, 'methods', ()):
            canonical = 'GET' if method == 'HEAD' else method
            assert (canonical, route.path) in ROUTE_PERMISSIONS, (method, route.path)


def test_viewer_cannot_write_and_service_never_inherits_legacy_admin():
    for principal in [Principal('human','operator',roles=('viewer',)),
                      Principal('collector','service',scopes=('ingest_runtime',))]:
        for action in ['admin','analyst','respond','assess']:
            with pytest.raises(HTTPException) as denied:
                require_permission(principal, action, '/operator/v1/example')
            assert denied.value.status_code == 403


def test_nested_prefixed_includes_have_effective_path_and_match():
    from fastapi import FastAPI, APIRouter
    from starlette.routing import Match
    outer=APIRouter()
    inner=APIRouter()
    @inner.get('/resource/{identifier}')
    def resource(identifier: str):
        return {'id':identifier}
    outer.include_router(inner,prefix='/inner')
    app=FastAPI()
    app.include_router(outer,prefix='/outer')
    routes=list(authorization_routes(app))
    route=next(item for item in routes if item.path=='/outer/inner/resource/{identifier}')
    assert route.methods=={'GET'}
    match,_=route.matches({'type':'http','path':'/outer/inner/resource/value','method':'GET','root_path':''})
    assert match==Match.FULL
    assert ('GET',route.path) not in ROUTE_PERMISSIONS
