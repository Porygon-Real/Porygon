#!/usr/bin/env python3
"""Provision opaque credentials without printing or returning secret material."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import urllib.error
import urllib.request
from urllib.parse import urlsplit

PURPOSES = {
    'collector': ['ingest_runtime', 'heartbeat'],
    'telemetry': ['ingest_process', 'ingest_kernel', 'heartbeat'],
    'scanner': ['scan_worker', 'heartbeat'],
    'responder': ['response_worker', 'heartbeat'],
}


class NoCredentialRedirects(urllib.request.HTTPRedirectHandler):
    """Never forward an enrollment body or credential to a redirected origin."""
    def redirect_request(self, request, fp, code, message, headers, new_url):
        raise urllib.error.HTTPError(request.full_url, code, 'Credential redirects are disabled', headers, fp)


def secure_open(request, timeout=30):
    return urllib.request.build_opener(NoCredentialRedirects()).open(request, timeout=timeout)


def private_write(path: Path, value: str) -> None:
    """Exclusive creation prevents accidental replacement and symlink traversal."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:3000')
    auth = parser.add_mutually_exclusive_group(required=True)
    auth.add_argument('--admin-token-file', type=Path)
    auth.add_argument('--bootstrap-env', type=Path)
    sub = parser.add_subparsers(dest='command', required=True)
    enroll = sub.add_parser('enroll')
    enroll.add_argument('--subject', required=True)
    enroll.add_argument('--role', choices=['viewer','analyst','responder','admin'])
    enroll.add_argument('--service', choices=list(PURPOSES))
    enroll.add_argument('--instance')
    enroll.add_argument('--host')
    enroll.add_argument('--output', required=True, type=Path)
    enroll.add_argument('--worker-env', type=Path)
    rotate = sub.add_parser('rotate')
    rotate.add_argument('credential_id')
    rotate.add_argument('--output', required=True, type=Path)
    rotate.add_argument('--overlap-seconds', type=int, default=0)
    revoke = sub.add_parser('revoke')
    revoke.add_argument('credential_id')
    sub.add_parser('list')
    sub.add_parser('verify')
    args = parser.parse_args(argv)
    origin = urlsplit(args.url)
    if (origin.scheme not in {'http','https'} or not origin.hostname or origin.username
            or origin.password or origin.query or origin.fragment
            or (origin.scheme == 'http' and origin.hostname not in {'localhost','127.0.0.1','::1'})):
        parser.error('Use loopback HTTP or a trusted HTTPS origin without URL credentials')
    if args.admin_token_file:
        admin = args.admin_token_file.read_text().strip()
    else:
        values = dict(line.split('=',1) for line in args.bootstrap_env.read_text().splitlines()
                      if line and not line.startswith('#') and '=' in line)
        admin = values.get('PORYGON_OPERATOR_API_TOKEN', '').strip().strip('\"\'')
    if not admin:
        parser.error('Admin credential is missing')
    if args.command == 'verify':
        checks = [('/health/live', False, 200), ('/api/v1/services', False, 401),
                  ('/openapi.json', False, 401), ('/api/v1/services', True, 200)]
        result = []
        for check_path, authenticated, expected in checks:
            check = urllib.request.Request(args.url.rstrip('/') + check_path,
                headers={'Authorization':'Bearer '+admin} if authenticated else {})
            try:
                with secure_open(check, timeout=30) as response:
                    actual = response.status
            except urllib.error.HTTPError as exc:
                actual = exc.code
                exc.close()
            except urllib.error.URLError:
                parser.exit(1, 'Access verification could not reach the API.\n')
            result.append({'path':check_path,'authenticated':authenticated,'status':actual,
                           'passed':actual==expected})
        print(json.dumps(result,indent=2))
        return 0 if all(item['passed'] for item in result) else 1
    body = None
    method = 'GET'
    path = '/operator/v1/credentials'
    secret = None
    if args.command in {'enroll','rotate'}:
        if args.output.exists():
            parser.error('Output must be a new file')
        secret = secrets.token_urlsafe(32)
        body = {'token': secret}
        method = 'POST'
        if args.command == 'enroll':
            if bool(args.role) == bool(args.service):
                parser.error('Choose exactly one human role or service purpose')
            if args.service and (not args.host or not args.instance):
                parser.error('Service enrollment requires host and instance')
            if args.worker_env and (not args.service or args.worker_env.exists()):
                parser.error('Worker env requires a service and a new output file')
            body.update(subject=args.subject, kind='service' if args.service else 'operator',
                        roles=[args.role] if args.role else [], scopes=PURPOSES.get(args.service,[]),
                        host_ids=[args.host] if args.service else [],
                        service_name=args.service, instance_id=args.instance)
        else:
            path += '/' + args.credential_id + '/rotate'
            body['overlap_seconds'] = args.overlap_seconds
        # Persist before registration: a transport interruption cannot lose the
        # only copy of a successfully enrolled token. Failed attempts are safe
        # to discard; retry using a fresh output path.
        private_write(args.output, secret + '\n')
    elif args.command == 'revoke':
        method = 'POST'
        path += '/' + args.credential_id + '/revoke'
    request = urllib.request.Request(args.url.rstrip('/') + path,
        data=json.dumps(body).encode() if body else (b'{}' if method == 'POST' else None),
        method=method, headers={'Content-Type':'application/json', 'X-Porygon-Operator-Token':admin})
    try:
        with secure_open(request, timeout=30) as response:
            metadata = json.load(response)
    except (urllib.error.URLError, ValueError):
        parser.exit(1, 'Credential operation failed; inspect API availability and access. Secret files were not printed.\n')
    if args.command == 'enroll' and args.worker_env:
        private_write(args.worker_env, args.service.upper() + '_API_TOKEN=' + secret + '\n')
    print(json.dumps(metadata, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
