#!/usr/bin/env python3
"""Runs the real Migration.preflight() and provision() (and the DNS zones of a Plesk website) for MigrationProvisioningTest.

Every REST call is written to stdout as one JSON line and answered on stdin by
the PHP test, which dispatches it to the actual API controllers. SSH, file and
SQL steps are replaced; everything that talks to the API is the shipped code.
"""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('migration', ROOT / 'site-migration/migrate.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
CHANNEL = sys.stdout
sys.stdout = sys.stderr  # Migration progress output must not corrupt the bridge protocol.


class BridgeApi(m.Api):
    def __init__(self, url, key_file=None, *, key=None):
        self.key = key  # None: the test's administrator key

    def request(self, method, path, payload=None):
        CHANNEL.write(json.dumps({'method': method, 'path': path, 'payload': payload, 'key': self.key}) + '\n')
        CHANNEL.flush()
        reply = json.loads(sys.stdin.readline())
        if reply['status'] >= 400:
            summary = m.problem_summary(json.dumps(reply['body']))
            raise m.ApiError('REST %s %s returned HTTP %s%s' % (method, path, reply['status'], ': ' + summary if summary else ''),
                             reply['status'])
        return reply['body'], None

    def wait(self, change, timeout=600):
        pass


def main():
    request = json.loads(sys.stdin.readline())
    m.Api = BridgeApi
    with tempfile.TemporaryDirectory(prefix='migration-bridge-') as state:
        if request.get('state'):
            m.atomic_json(Path(state) / 'state.json', request['state'])
        migration = m.Migration(request['config'], state, request['domain'], request['client_id'])
        migration.state['inventory'] = request['inventory']
        migration.state['source_size'] = request['source_size']
        migration.state['cron_jobs'] = request.get('cron_jobs', [])
        migration.check_target = lambda **kwargs: None
        migration.db_io = lambda *args, **kwargs: None
        if request.get('legacy_database_payload'):
            # Reproduce hosting <= 1.2.3, which omitted database_quota.
            create = migration.create

            def legacy(name, endpoint, payload):
                payload = dict(payload)
                if endpoint == '/sites/databases':
                    del payload['database_quota']
                return create(name, endpoint, payload)
            migration.create = legacy
        migration.verify_dns = lambda plan: None  # no DNS server answers in the test
        try:
            try:
                if not request.get('dns_only'):
                    migration.php_version = request.get('php')
                    migration.select_php()
                    migration.preflight()
                    migration.provision()
                if request.get('dns'):
                    # Plesk's zone rows and public DNS are given; the zones are planned and created by the shipped code.
                    public = request['dns']['public']
                    plan = migration.prepare_dns(rows=request['dns']['rows'],
                                                 lookup=lambda name: (public.get(name, []), None if name in public else 'NXDOMAIN'))
                    m.check_counts(migration.usage_summary(), migration.dns_counts())
                    migration.create_dns(plan)
            finally:
                key = migration.state.get('client_key', {})
                if 'id' in key:
                    migration.admin.request('PUT', '/system/api-keys/' + str(key['id']), {'active': False})
            result = {'ok': True}
        except m.MigrationError as exc:
            result = {'ok': False, 'error': str(exc)}
        result['state'] = migration.state
    CHANNEL.write(json.dumps({'done': result}) + '\n')
    CHANNEL.flush()


if __name__ == '__main__':
    main()
