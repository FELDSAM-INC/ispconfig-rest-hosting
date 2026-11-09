#!/usr/bin/env python3
"""Focused offline tests; integration coverage lives in integration.py."""
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / 'site-migration'
spec = importlib.util.spec_from_file_location('migration', TOOLS / 'migrate.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_dns import FakeDns  # noqa: E402


class MigrationTests(unittest.TestCase):
    def test_disk_quota_uses_remaining_allocation_not_measured_usage(self):
        summary = {'client_id': 6, 'web_disk': {'limit_bytes': 5120 * 1048576,
                   'allocated_bytes': 1024 * 1048576, 'used_bytes': 1}}
        self.assertEqual(4096, m.available_disk_mb(summary, 6))
        summary['web_disk']['allocated_bytes'] = 0
        self.assertEqual(5120, m.available_disk_mb(summary, 6))
        summary['web_disk']['limit_bytes'] = None
        self.assertEqual(-1, m.available_disk_mb(summary, 6))

    def test_missing_wrong_or_exhausted_quota_stops_before_provisioning(self):
        for summary in [{}, {'client_id': 7}, {'client_id': 6, 'web_disk': {}},
                        {'client_id': 6, 'web_disk': {'limit_bytes': 5120}},
                        {'client_id': 6, 'web_disk': {'limit_bytes': 5120, 'allocated_bytes': 5120}}]:
            with self.subTest(summary=summary), self.assertRaises(m.MigrationError):
                m.available_disk_mb(summary, 6)

    def summary(self, disk=5120, traffic=None, database=1024, allocated_database=0, counts=None):
        def metric(limit, allocated=0):
            return {'limit_bytes': None if limit is None else limit * 1048576, 'allocated_bytes': allocated * 1048576}
        return {'client_id': 6, 'web_disk': metric(disk), 'web_traffic_this_month': metric(traffic),
                'database_size': metric(database, allocated_database), 'counts': counts or {}}

    def migration(self, objects=None, databases=None):
        migration = object.__new__(m.Migration)
        migration.client_id = 6
        databases = databases or {'c57shop': 40 * 1048576}
        migration.state = {'objects': objects or {}, 'source_size': {'web_bytes': 800 * 1048576, 'databases': databases},
                           'inventory': {'children': [{'domain_id': '195', 'type': 'alias'}],
                                         'databases': [{'database_name': name} for name in databases]}}
        return migration

    def test_retry_and_sync_keep_already_created_quotas(self):
        migration = self.migration({'site': {'record': {'hd_quota': 5120, 'traffic_quota': -1}},
                                    'db:c57shop': {'record': {'database_quota': 1024}}})
        # The account is now fully allocated by this migration's own objects.
        quotas = migration.allocation(self.summary(disk=5120, database=1024, allocated_database=1024))
        self.assertEqual({'disk_mb': 5120, 'traffic_mb': -1, 'databases_mb': {'c57shop': 1024}}, quotas)

    def test_database_quota_is_never_omitted_and_splits_by_source_size(self):
        self.assertEqual({'c57shop': 1024}, m.database_quotas(self.summary(), 6, {'c57shop': 40 * 1048576}))
        self.assertEqual({'app': 256, 'shop': 768},
                         m.database_quotas(self.summary(), 6, {'app': 100 * 1048576, 'shop': 300 * 1048576}))
        self.assertEqual({'a': 512}, m.database_quotas(self.summary(allocated_database=512), 6, {'a': 1}))
        self.assertEqual({'a': -1}, m.database_quotas(self.summary(database=None), 6, {'a': 1}))
        for remaining, sizes in [(0, {'a': 1}), (1024, {'a': 2000 * 1048576}), (1, {'a': 1, 'b': 1})]:
            with self.subTest(sizes=sizes), self.assertRaises(m.MigrationError):
                m.database_quotas(self.summary(database=remaining), 6, sizes)

    def test_traffic_quota_follows_the_client_instead_of_configuration(self):
        self.assertEqual(-1, m.available_traffic_mb(self.summary(), 6))
        summary = self.summary(traffic=20480)
        summary['web_traffic_this_month']['allocated_bytes'] = 4096 * 1048576
        self.assertEqual(16384, m.available_traffic_mb(summary, 6))
        with self.assertRaises(m.MigrationError):
            m.available_traffic_mb(self.summary(traffic=0), 6)

    def test_count_limits_and_source_sizes_are_checked_before_writes(self):
        migration = self.migration()
        self.assertEqual({'web_domains': 1, 'web_alias_domains': 1, 'web_subdomains': 0, 'database_users': 1, 'databases': 1},
                         migration.needed_counts())
        counts = {key: {'used': 0, 'limit': None} for key in m.COUNT_LIMITS}
        counts['databases'] = {'used': 0, 'limit': 1}
        m.check_counts(self.summary(counts=counts), migration.needed_counts())
        counts['databases']['used'] = 1
        with self.assertRaisesRegex(m.MigrationError, 'databases is too small: limit 1, used 1'):
            m.check_counts(self.summary(counts=counts), migration.needed_counts())
        with self.assertRaisesRegex(m.MigrationError, 'web_domains usage count'):
            m.check_counts(self.summary(counts={}), migration.needed_counts())
        with self.assertRaisesRegex(m.MigrationError, 'exceed the website disk quota'):
            migration.allocation(self.summary(disk=512))
        resumed = self.migration({'site': {'record': {'hd_quota': 5120}}, 'child:195': {'record': {}},
                                  'user:c57shop': {'record': {}}})
        self.assertEqual({'web_domains': 0, 'web_alias_domains': 0, 'web_subdomains': 0, 'database_users': 0, 'databases': 1},
                         resumed.needed_counts())

    def test_problem_summary_exposes_limits_without_reflected_credentials(self):
        problem = {'type': 'https://github.com/FELDSAM-INC/ispconfig-rest/blob/main/docs/problems.md#quota-exceeded',
                   'detail': 'password=private-secret', 'title': 'private-secret',
                   'limit': {'name': 'limit_web_quota', 'scope': 'client', 'max': 5120, 'used': 0, 'requested': 10240}}
        result = m.problem_summary(json.dumps(problem))
        self.assertEqual('quota-exceeded: limit_web_quota (client); max=5120; used=0; requested=10240', result)
        self.assertNotIn('private-secret', result)
        for body in ['<html>private-secret</html>', '[]', '{"detail":"private-secret"}']:
            self.assertEqual('', m.problem_summary(body))

    def patch_wp(self, source):
        payload = {'content': base64.b64encode(source.encode()).decode(), 'databases': {
            'old_db': {'old_user': 'old_user', 'name': 'c3new', 'user': 'c3newuser', 'password': "a'\\b$9", 'host': 'db0'}}}
        return subprocess.run(['php', str(TOOLS / 'wordpress-config.php')], input=json.dumps(payload).encode(), capture_output=True)

    def test_wordpress_only_changes_credentials_without_executing_code(self):
        source = """<?php
// define('DB_NAME', 'comment');
file_put_contents('/tmp/ispcp-customer-code-executed', 'bad');
define( 'DB_NAME', 'old_db' );
define('DB_USER', "old_user");
define('DB_PASSWORD', 'old-password');
define('DB_HOST', 'localhost');
$text = "DEFINER=root old_db";
"""
        result = self.patch_wp(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        content = base64.b64decode(json.loads(result.stdout)['content']).decode()
        self.assertIn("define( 'DB_NAME', 'c3new' );", content)
        self.assertIn("define('DB_PASSWORD', 'a\\'\\\\b$9');", content)
        self.assertIn("// define('DB_NAME', 'comment');", content)
        self.assertFalse(Path('/tmp/ispcp-customer-code-executed').exists())
        self.assertEqual(self.patch_wp(content).stdout, result.stdout, 'retry must recognize already updated files')

    def test_dynamic_duplicate_or_method_defines_need_review(self):
        prefix = "<?php define('DB_USER','old_user'); define('DB_PASSWORD','secret'); define('DB_HOST','localhost');"
        for definition in ["define('DB_NAME', getenv('DB_NAME'));", "define('DB_NAME','old_db');define('DB_NAME','old_db');",
                           "$x->define('DB_NAME','old_db');"]:
            result = self.patch_wp(prefix + definition)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b'secret', result.stderr)
            self.assertFalse(result.stdout)

    def test_sql_normalization_keeps_data_and_changes_object_headers(self):
        data = "'DEFINER=`root`@`localhost` old_db.item " + 'x' * 300000 + "'"
        sql = 'CREATE DEFINER=`root`@`localhost` VIEW `v` AS SELECT * FROM `old_db`.`item`;\nINSERT INTO `item` VALUES (' + data + ');\n'
        result = subprocess.run(['php', str(TOOLS / 'normalize-sql.php'), 'old_db', 'c3new'], input=sql.encode(), capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'CREATE DEFINER=CURRENT_USER VIEW', result.stdout)
        self.assertIn(b'FROM `c3new`.`item`', result.stdout)
        self.assertIn(data.encode(), result.stdout)

    def test_links_are_portable_and_external_links_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            (tree / 'web').mkdir()
            (tree / 'private').mkdir()
            (tree / 'private/data').write_text('data')
            (tree / 'web/link').symlink_to('/var/www/clients/client1/web2/private/data')
            m.normalize_links(tree, '/var/www/clients/client1/web2')
            self.assertEqual(os.readlink(tree / 'web/link'), '../private/data')
            (tree / 'web/outside').symlink_to('/etc/passwd')
            with self.assertRaises(m.MigrationError):
                m.normalize_links(tree, '/var/www/clients/client1/web2')

    def test_uncertain_creation_never_retries_post(self):
        class Api:
            posts = 0
            def request(self, *args):
                self.posts += 1
                raise m.MigrationError('response lost')
        migration = object.__new__(m.Migration)
        migration.state = {'objects': {}}
        migration.save = lambda: None
        migration.api = Api()
        for _ in range(2):
            with self.assertRaises(m.MigrationError):
                migration.create('site', '/sites/web-domains', {'domain': 'example.com'})
        self.assertEqual(migration.api.posts, 1)

    def test_api_credentials_are_never_forwarded_to_redirects(self):
        self.assertIsNone(m.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.example/'))

    def test_rejected_creation_clears_intent_for_retry(self):
        class Api:
            def request(self, *args):
                raise m.ApiError('quota rejected', 422)
        migration = object.__new__(m.Migration)
        migration.state = {'objects': {}}
        migration.save = lambda: None
        migration.api = Api()
        with self.assertRaises(m.ApiError):
            migration.create('site', '/sites/web-domains', {})
        self.assertEqual(migration.state['objects'], {})

    def test_non_wordpress_database_stops_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            migration = object.__new__(m.Migration)
            migration.domain, migration.client_id = 'example.com', 123
            migration.state = {'databases': {'old_db': {'name': 'new_db'}}}
            migration.save = lambda: None
            tree = Path(directory) / 'tree'
            tree.mkdir()
            migration.configure(tree)
            self.assertTrue(migration.state['manual_configuration'])
            migration.state['phase'] = 'prepared'
            with self.assertRaisesRegex(m.MigrationError, 'staged tree'):
                migration.publish()

    def test_final_sync_requires_target_quiesced_before_new_round(self):
        migration = object.__new__(m.Migration)
        migration.state = {'phase': 'copied', 'round': 0}
        with self.assertRaisesRegex(m.MigrationError, 'target application'):
            migration.run(sync=True, source_quiesced=True)
        self.assertEqual(migration.state['round'], 0)

    def test_host_option_injection_and_public_state_rejected(self):
        for host in ['-oProxyCommand=sh', 'root@host;id', 'host\ncommand', 'root@[::1]']:
            with self.assertRaises(m.MigrationError):
                m.ssh_host(host)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o755)
            with self.assertRaises(m.MigrationError):
                m.private_directory(directory)

    def test_state_may_live_on_the_web_file_system_outside_website_roots(self):
        with tempfile.TemporaryDirectory() as base:
            base = Path(base).resolve()
            with patch.object(m, 'WEB_ROOTS', (base / 'clients',)):
                self.assertEqual(base / 'ispcp-migration/example.com', m.private_directory(base / 'ispcp-migration/example.com'))
                with self.assertRaises(m.MigrationError):
                    m.private_directory(base / 'clients/client6/web4/private/state')
                (base / 'example.com').symlink_to(base / 'clients/client6/web4')
                with self.assertRaises(m.MigrationError):
                    m.private_directory(base / 'example.com/state')
                shared = base / 'shared'
                shared.mkdir(mode=0o700)
                shared.chmod(0o777)  # another user could swap the state directory
                with self.assertRaises(m.MigrationError):
                    m.private_directory(shared / 'example.com')

    def test_moving_state_dir_keeps_the_fingerprint(self):
        config = {'source': {'panel_ssh': 'root@old', 'web_ssh': 'root@old', 'db_ssh': {'1': 'root@old'}},
                  'target': {'api_url': 'https://panel.example/api/v1', 'api_key_file': '/unused', 'web_ssh': 'root@new',
                             'db_ssh': 'root@db', 'web_server_id': 4, 'db_server_id': 5, 'db_host': 'db0'}}
        with tempfile.TemporaryDirectory() as state, patch.object(m, 'Api', MagicMock()):
            first = m.Migration(config, state, 'example.com', 6)
            first.save()
            moved = m.Migration(dict(config, state_dir='/var/www/ispcp-migration'), state, 'example.com', 6)
            self.assertEqual(first.state['fingerprint'], moved.state['fingerprint'])
            with self.assertRaisesRegex(m.MigrationError, 'Configuration/domain/client changed'):
                m.Migration(dict(config, target=dict(config['target'], db_host='other')), state, 'example.com', 6)

    def test_plan_stops_when_the_state_file_system_cannot_hold_the_staging_copy(self):
        migration = self.migration(databases={'c57shop': 100 * 1048576})
        with tempfile.TemporaryDirectory() as state:
            migration.directory = Path(state)
            migration.state.update(phase='planned', round=0)
            usage = shutil.disk_usage(state)._replace(free=900 * 1048576)
            with patch.object(m.shutil, 'disk_usage', return_value=usage):
                with self.assertRaisesRegex(m.MigrationError, 'about 1256 MB needed, 900 MB free in .*state_dir'):
                    migration.check_free_space()
                # A final sync also backs up the target website.
                migration.state['phase'] = 'copied'
                with self.assertRaisesRegex(m.MigrationError, 'about 2056 MB needed'):
                    migration.check_free_space()
                migration.state['source_size']['web_bytes'] = 100 * 1048576
                self.assertEqual((656 * 1048576, 900 * 1048576), migration.check_free_space())

    def test_configured_state_dir_refuses_to_start_over_while_the_state_was_not_moved(self):
        with tempfile.TemporaryDirectory() as base:
            base = Path(base)
            legacy, moved = base / 'legacy', base / 'moved'
            (legacy / 'example.com').mkdir(parents=True, mode=0o700)
            (legacy / 'example.com/state.json').write_text('{}')
            config = base / 'config.json'
            config.write_text(json.dumps({'state_dir': str(moved)}))
            with patch.object(m, 'DEFAULT_STATE', legacy), patch.object(m.shutil, 'which', return_value='/usr/bin/x'), \
                    patch('sys.stderr') as stderr:
                self.assertEqual(1, m.main(['--simple', 'example.com', '6', '--config', str(config)]))
            message = ''.join(call.args[0] for call in stderr.write.call_args_list)
            self.assertIn('is still in %s/example.com. Move it first: mv' % legacy, message)
            self.assertFalse(moved.exists(), 'no new empty state may be created')

    def test_php_version_resolves_to_one_active_fpm_configuration(self):
        rows = [{'id': 2, 'name': 'PHP 5.6', 'active': True, 'client_id': 0, 'php_fpm_ini_dir': '/etc/php/5.6/fpm'},
                {'id': 3, 'name': 'PHP 8.3', 'active': True, 'client_id': 0, 'php_fpm_ini_dir': '/etc/php/8.3/fpm'},
                {'id': 4, 'name': 'Legacy', 'active': True, 'client_id': 0, 'php_fpm_ini_dir': '/etc/php/5.3/fpm'},
                {'id': 5, 'name': 'PHP 7.4', 'active': False, 'client_id': 0, 'php_fpm_ini_dir': '/etc/php/7.4/fpm'},
                {'id': 6, 'name': 'PHP 8.1', 'active': True, 'client_id': 9, 'php_fpm_ini_dir': '/etc/php/8.1/fpm'},
                {'id': 7, 'name': 'PHP 8.2 CGI', 'active': True, 'client_id': 0, 'php_fpm_ini_dir': ''}]
        self.assertEqual(2, m.php_configuration(rows, '5.6', 6))
        self.assertEqual(3, m.php_configuration(rows, '8.3', 6))
        self.assertEqual(4, m.php_configuration(rows, '5.3', 6))  # found by its FPM path
        self.assertEqual(6, m.php_configuration(rows, '8.1', 9))
        for version in ['7.4', '8.1', '8.2', '8', '5.6;id', '15.6']:
            with self.subTest(version=version), self.assertRaises(m.MigrationError):
                m.php_configuration(rows, version, 6)
        with self.assertRaisesRegex(m.MigrationError, 'IDs 2, 8'):
            m.php_configuration(rows + [dict(rows[0], id=8)], '5.6', 6)
        with self.assertRaises(SystemExit), patch('sys.stderr'):
            m.parse_args(['--simple', 'example.com', '6', '--php', 'latest'])
        self.assertEqual('5.6', m.parse_args(['--simple', 'example.com', '6', '--php=5.6']).php)

    def test_php_option_cannot_silently_differ_from_an_existing_website(self):
        migration = self.migration({'site': {'record': {'hd_quota': 5120, 'server_php_id': 14}}})
        migration.target = {'web_server_id': 4}
        migration.admin = MagicMock()
        migration.admin.all.return_value = [{'id': 14, 'name': 'PHP 8.3', 'active': True, 'client_id': 0, 'php_fpm_ini_dir': '/x'},
                                            {'id': 2, 'name': 'PHP 5.6', 'active': True, 'client_id': 0, 'php_fpm_ini_dir': '/y'}]
        migration.php_version = '8.3'
        self.assertEqual({'version': '8.3', 'server_php_id': 14}, migration.select_php())
        migration.php_version = '5.6'
        with self.assertRaisesRegex(m.MigrationError, 'already created with PHP configuration ID 14'):
            migration.select_php()
        migration.php_version = None
        self.assertEqual(14, migration.select_php()['server_php_id'])

    def test_remote_mysql_uses_web_ssh_identity_and_never_db_ssh(self):
        migration = object.__new__(m.Migration)
        connection = {'host': 'old-db.example.net', 'port': 3306, 'defaults_file': '/root/reader.cnf'}
        migration.source = {'web_ssh': 'root@old-web.example.net', 'db_via_web': connection}
        db = {'server_id': '2', 'database_name': 'old_db'}
        migration.state = {'inventory': {'site': {'server_id': '1'}, 'databases': [db]}}
        host, request = migration.source_database_route(db)
        self.assertEqual(host, 'root@old-web.example.net')
        self.assertEqual(request['server_id'], '1')
        self.assertEqual(request['source_connection'], connection)
        migration.state['inventory']['databases'].append({'server_id': '3'})
        with self.assertRaises(m.MigrationError):
            migration.source_database_route(db)

    def test_direct_mysql_ssh_route_remains_available(self):
        migration = object.__new__(m.Migration)
        migration.source = {'db_ssh': {'2': 'root@db-old'}}
        migration.state = {'inventory': {}}
        self.assertEqual(migration.source_database_route({'server_id': '2'}),
                         ('root@db-old', {'server_id': '2'}))

    def test_two_arguments_derive_config_and_private_state(self):
        args = m.parse_args(['--simple', 'Example.COM', '123'])
        self.assertEqual(('example.com', 123, 'interactive'), (args.domain, args.client_id, args.command))
        self.assertEqual('/etc/ispconfig-rest-migration/config.json', args.config)
        self.assertIsNone(args.state)  # state_dir/DOMAIN, derived once the configuration is read
        self.assertEqual(Path('/var/lib/ispconfig-rest-migration'), m.state_root({}))
        self.assertEqual(Path('/var/www/ispcp-migration'), m.state_root({'state_dir': '/var/www/ispcp-migration'}))
        for value in ['relative', 7, '/x\n']:
            with self.assertRaises(m.MigrationError):
                m.state_root({'state_dir': value})
        self.assertEqual('plan', m.parse_args(['--simple', 'example.com', '123', '--plan']).command)

    def test_declining_simple_command_never_runs_or_publishes(self):
        migration = MagicMock(state={'phase': 'planned'})
        with patch.object(m.sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value=''):
            with self.assertRaisesRegex(m.MigrationError, 'Not started'):
                m.interactive(migration)
        migration.plan.assert_called_once_with()
        migration.run.assert_not_called()
        migration.publish.assert_not_called()

    def test_simple_command_requires_explicit_quiescence_answer(self):
        migration = MagicMock(state={'phase': 'planned'})
        with patch.object(m.sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value='ano'):
            m.interactive(migration)
        migration.plan.assert_called_once_with()
        migration.run.assert_called_once_with(sync=False, source_quiesced=True, target_quiesced=False, plan_ready=True)

    def test_simple_command_does_not_accept_redirected_yes(self):
        migration = MagicMock(state={'phase': 'planned'})
        with patch.object(m.sys.stdin, 'isatty', return_value=False), patch('builtins.input') as reader:
            with self.assertRaisesRegex(m.MigrationError, 'terminal'):
                m.interactive(migration)
        reader.assert_not_called()
        migration.run.assert_not_called()

    def test_repeat_command_publishes_reviewed_custom_configuration(self):
        migration = MagicMock(state={'phase': 'prepared', 'round': 0, 'manual_configuration': True}, directory=Path('/private/state'))
        with patch.object(m.sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value='yes'):
            m.interactive(migration)
        migration.publish.assert_called_once_with(config_reviewed=True)
        migration.run.assert_not_called()


OLD_WEB, NEW_WEB = '198.51.100.20', '198.51.100.119'


def website(domain_id, domain, kind='vhost', parent=0, subdomain='none', active='y', **extra):
    row = {'domain_id': str(domain_id), 'server_id': '1', 'parent_domain_id': str(parent), 'domain': domain,
           'type': kind, 'subdomain': subdomain, 'active': active, 'ip_address': '*', 'ipv6_address': '',
           'document_root': '' if kind in ('alias', 'subdomain') else '/var/www/clients/client5/web%d' % domain_id,
           'redirect_type': '', 'redirect_path': ''}
    row.update(extra)
    return row


# Shape of source-sites.php output (string columns, objects for databases/traffic).
SITES_INVENTORY = {
    'websites': [
        website(10, 'live.sk', subdomain='www', client_id='5', client_username='c5', client_company='Firma s.r.o.', client_contact='Jan'),
        website(11, 'live-alias.sk', 'alias', parent=10),
        website(12, 'off-alias.sk', 'alias', parent=10, active='n'),
        website(20, 'moved.sk'),
        website(30, 'cdn.sk', subdomain='www'),
        website(40, 'dead.sk', active='n'),
        website(41, 'shop.dead.sk', 'vhostsubdomain', parent=40),
        website(50, 'own-ip.sk', ip_address='198.51.100.21'),
        website(60, 'db-ip.sk'),
    ],
    'databases': {'10': 2},
    'servers': [{'server_id': '1', 'server_name': 'web0.old.test'}, {'server_id': '2', 'server_name': 'db0.old.test'}],
    'ips': [{'server_id': '1', 'ip_address': OLD_WEB}, {'server_id': '2', 'ip_address': '198.51.100.30'}],
    'traffic': {'live.sk': 3 * 1024 ** 3, 'cdn.sk': 5 * 1048576},
}
SITES_DNS = {
    'live.sk': [('A', OLD_WEB)], 'www.live.sk': [('CNAME', 'live.sk')], 'live-alias.sk': [('A', '104.21.9.9')],
    'off-alias.sk': [('A', OLD_WEB)], 'moved.sk': [('A', NEW_WEB)], 'cdn.sk': [('A', '104.21.1.1')],
    'www.cdn.sk': [('CNAME', 'cdn.sk')], 'own-ip.sk': [('A', '198.51.100.21')], 'db-ip.sk': [('A', '198.51.100.30')],
    'web0.old.test': [('A', '198.51.100.25'), ('AAAA', '2001:db8:100::20')], 'web0.new.test': [('AAAA', '2001:db8:100::119')],
}
SITES_CONFIG = {'source': {'panel_ssh': 'root@web0.old.test'},
                'target': {'api_url': 'https://panel.test:8090/api/v1', 'api_key_file': '/root/key',
                           'web_ssh': 'root@web0.new.test', 'web_server_id': 4}}


class ServerAddressApi:
    def __init__(self, url, key_file):
        pass

    def all(self, path):
        assert path == '/servers/4/ip-addresses', path
        return [{'ip_address': NEW_WEB, 'ip_type': 'IPv4'}]


class SiteInventoryTests(unittest.TestCase):
    def resolver(self, records=None, **options):
        server = FakeDns(SITES_DNS if records is None else records, **options)
        self.addCleanup(server.close)
        return server

    def test_resolve_follows_cnames_and_reads_ipv4_and_ipv6(self):
        dns = self.resolver({'example.sk': [('A', OLD_WEB), ('AAAA', '2001:db8:100:0::20')], 'www.example.sk': [('CNAME', 'example.sk')]})
        self.assertEqual({'addresses': [OLD_WEB, '2001:db8:100::20'], 'cname': ['example.sk'], 'error': None},
                         m.resolve('WWW.Example.sk.', [dns.address]))

    def test_a_cname_answered_alone_is_asked_for_its_target(self):
        dns = self.resolver({'shop.example.sk': [('CNAME', 'edge.cdn.test')], 'edge.cdn.test': [('A', '104.21.1.1')]},
                            cname_only={'shop.example.sk'})
        result = m.resolve('shop.example.sk', [dns.address])
        self.assertEqual((['104.21.1.1'], ['edge.cdn.test'], None), (result['addresses'], result['cname'], result['error']))
        self.assertIn(('edge.cdn.test', m.DNS_A, 'udp'), dns.queries)

    def test_nxdomain_is_final_but_a_server_failure_asks_the_next_resolver(self):
        failing, working = self.resolver(rcode=2), self.resolver({'example.sk': [('A', OLD_WEB)]})
        self.assertEqual([OLD_WEB], m.resolve('example.sk', [failing.address, working.address])['addresses'])
        self.assertEqual('SERVFAIL', m.resolve('example.sk', [failing.address])['error'])
        first, second = self.resolver({}), self.resolver({'gone.sk': [('A', OLD_WEB)]})
        self.assertEqual('NXDOMAIN', m.resolve('gone.sk', [first.address, second.address])['error'])
        self.assertEqual([], second.queries)

    def test_silent_resolver_times_out_and_the_next_one_answers(self):
        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent.bind(('127.0.0.1', 0))
        self.addCleanup(silent.close)
        dns = self.resolver({'example.sk': [('A', OLD_WEB)]})
        self.assertEqual([OLD_WEB], m.resolve('example.sk', [silent.getsockname(), dns.address], timeout=0.2)['addresses'])
        self.assertEqual('timeout', m.resolve('example.sk', [silent.getsockname()], timeout=0.2)['error'])

    def test_truncated_answer_is_repeated_over_tcp(self):
        dns = self.resolver({'big.example.sk': [('A', OLD_WEB)]}, truncate={'big.example.sk'})
        self.assertEqual([OLD_WEB], m.resolve('big.example.sk', [dns.address])['addresses'])
        self.assertIn(('big.example.sk', m.DNS_A, 'tcp'), dns.queries)

    def test_malformed_answers_and_names_are_rejected(self):
        with self.assertRaises(m.DnsError):
            m.dns_read_name(b'\xc0\x00', 0)  # compression pointer loop
        with self.assertRaises(m.DnsError):
            m.dns_read_name(b'\x05abc', 0)
        self.assertEqual('invalid name', m.resolve('a..b', [('127.0.0.1', 9)])['error'])
        self.assertEqual('xn--bcher-kva.de', m.ascii_hostname('Bücher.de'))

    def report(self, **options):
        dns = self.resolver()
        with patch.object(m, 'Api', ServerAddressApi):
            return m.site_inventory(SITES_CONFIG, resolvers=[dns.address], inventory=SITES_INVENTORY, **options)

    def test_websites_are_classified_by_where_their_public_dns_points(self):
        report = self.report()
        sites = {site['domain']: site for site in report['websites']}
        self.assertEqual({'live.sk': 'old', 'moved.sk': 'new', 'cdn.sk': 'other', 'dead.sk': 'none',
                          'shop.dead.sk': 'none', 'own-ip.sk': 'old', 'db-ip.sk': 'other'},
                         {domain: site['status'] for domain, site in sites.items()})
        live = sites['live.sk']
        # An inactive alias is not served, so its DNS does not count.
        self.assertEqual(['live.sk', 'www.live.sk', 'live-alias.sk'], live['hostnames'])
        self.assertEqual(['old', 'old', 'other'], [entry['state'] for entry in live['dns']])
        self.assertEqual((2, 3 * 1024 ** 3, 'c5 Firma s.r.o.'), (live['databases'], live['traffic_30d_bytes'], live['client']))
        self.assertEqual(('dead.sk', False), (sites['shop.dead.sk']['parent'], sites['dead.sk']['active']))
        self.assertEqual('NXDOMAIN', sites['dead.sk']['dns'][0]['error'])
        # Old: server_ip of web servers, website IPs and the server name in DNS; never another server's IPs.
        self.assertEqual({OLD_WEB, '198.51.100.21', '198.51.100.25', '2001:db8:100::20'}, set(report['old_addresses']))
        self.assertEqual({NEW_WEB: 'API server 4', '2001:db8:100::119': 'DNS web0.new.test'}, report['new_addresses'])
        self.assertEqual([], report['warnings'])

    def test_missing_api_addresses_warn_and_manual_addresses_apply(self):
        dns = self.resolver()
        with patch.object(m, 'Api', side_effect=m.MigrationError('API key file must be a regular private file (0600)')):
            report = m.site_inventory(SITES_CONFIG, resolvers=[dns.address], inventory=SITES_INVENTORY,
                                      extra_new=[NEW_WEB], extra_old=['104.21.1.1'])
        sites = {site['domain']: site['status'] for site in report['websites']}
        self.assertEqual(('new', 'old'), (sites['moved.sk'], sites['cdn.sk']))
        self.assertIn('--new-ip', report['warnings'][0])

    def test_table_and_json_output(self):
        report = self.report()
        out = io.StringIO()
        m.print_sites(report, out=out)
        text = out.getvalue()
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith('Old web server addresses: 198.51.100.20 (web0.old.test)'), lines[0])
        rows = [line.split()[:2] for line in lines if line.split()[:1] in (['old'], ['new'], ['other'], ['none'])][:7]
        self.assertEqual([['old', 'live.sk'], ['old', 'own-ip.sk'], ['new', 'moved.sk'], ['other', 'cdn.sk'],
                          ['other', 'db-ip.sk'], ['none', 'dead.sk'], ['none', 'shop.dead.sk']], rows)
        live = next(line for line in lines if line.startswith('old') and 'live.sk' in line)
        self.assertIn('c5 Firma s.r.o.', live)
        self.assertIn('3.0 GB', live)
        self.assertTrue(live.endswith('live.sk=old www=old live-alias.sk=104.21.9.9'), live)
        self.assertIn('shop.dead.sk (in dead.sk)', text)
        self.assertIn('dead.sk=NXDOMAIN', text)
        self.assertRegex(text, r'\nold +2  DNS points to the old server')
        self.assertIn('Inactive old websites (ACT n): 1', text)
        out = io.StringIO()
        m.print_sites(report, ('old',), as_json=True, out=out)
        shown = json.loads(out.getvalue())
        self.assertEqual(['live.sk', 'own-ip.sk'], [site['domain'] for site in shown['websites']])
        self.assertEqual(['104.21.9.9'], shown['websites'][0]['dns'][2]['addresses'])

    def test_sites_command_line(self):
        args = m.parse_args(['--simple', '--sites', '--status', 'old, none', '--resolver', '9.9.9.9', '--new-ip', '2001:db8:100::119'])
        self.assertEqual(('sites', ('old', 'none'), [('9.9.9.9', 53)]), (args.command, args.states, args.resolvers))
        self.assertEqual([('1.1.1.1', 53), ('8.8.8.8', 53)], m.parse_args(['sites', '--config', '/c.json']).resolvers)
        for bad in (['--status', 'live'], ['--resolver', 'dns.google'], ['--old-ip', 'web0']):
            with self.subTest(bad=bad), self.assertRaises(SystemExit), patch('sys.stderr', io.StringIO()):
                m.parse_args(['--simple', '--sites'] + bad)

    def test_old_panel_failure_reports_the_ssh_or_helper_message(self):
        failure = subprocess.CompletedProcess([], 255, b'', b'warning: pq kex\nHost key verification failed.\r\n')
        with patch.object(m.subprocess, 'run', return_value=failure):
            with self.assertRaisesRegex(m.MigrationError, 'root@web0.old.test failed \\(exit 255\\): Host key verification failed.$'):
                m.source_sites(SITES_CONFIG)


def plesk_domain(id, name, *, webspace=0, parent=0, root=None, home='/var/www/vhosts/shop.test', htype='vrt_hst', status=0,
                 login='shopuser', handler='alt-php81-fpm', client='shop', zone=None):
    return {'t': 'domain', 'id': id, 'name': name, 'htype': htype, 'status': status, 'webspace_id': webspace, 'parent_id': parent,
            'dns_zone_id': zone,
            'www_root': root if htype == 'vrt_hst' else None, 'login': login if htype == 'vrt_hst' else None,
            'home': home if htype == 'vrt_hst' else None, 'shell': '/usr/local/psa/bin/chrootsh', 'php_handler': handler,
            'client': client, 'company': 'Shop s.r.o.', 'contact': 'Jana'}


HOME = '/var/www/vhosts/shop.test'
PLESK_ROWS = [
    plesk_domain(1, 'shop.test', root=HOME + '/httpdocs', zone=31),
    plesk_domain(2, '_.shop.test', webspace=1, parent=1, root=HOME + '/httpdocs'),
    plesk_domain(3, 'blog.shop.test', webspace=1, parent=1, root=HOME + '/httpdocs/blog', handler='alt-php74-fpm', zone=35),
    plesk_domain(4, 'same.shop.test', webspace=1, parent=1, root=HOME + '/httpdocs'),
    plesk_domain(5, 'own.shop.test', webspace=1, parent=1, root=HOME + '/own.shop.test', zone=36),
    plesk_domain(6, 'go.shop.test', webspace=1, parent=1, htype='std_fwd'),
    plesk_domain(7, 'addon.test', webspace=1, root=HOME + '/addon.test'),
    plesk_domain(8, 'off.test', root='/var/www/vhosts/off.test/httpdocs', home='/var/www/vhosts/off.test', status=16, login='off'),
    plesk_domain(9, 'mail.test', htype='none'),
    plesk_domain(10, 'nested.test', root='/var/www/vhosts/nested.test/httpdocs/public', home='/var/www/vhosts/nested.test', login='n'),
    {'t': 'alias', 'id': 1, 'dom_id': 1, 'name': 'shop.example', 'status': 0, 'web': 'true', 'seo_redirect': 'true', 'dns_zone_id': 32},
    {'t': 'alias', 'id': 2, 'dom_id': 1, 'name': 'shop.other', 'status': 0, 'web': 'true', 'seo_redirect': 'false', 'dns_zone_id': None},
    {'t': 'alias', 'id': 3, 'dom_id': 1, 'name': 'mail-only.test', 'status': 0, 'web': 'false', 'seo_redirect': 'false', 'dns_zone_id': 34},
    {'t': 'database', 'id': 11, 'name': 'shop_wp', 'type': 'mysql', 'dom_id': 1, 'server_id': 1, 'default_user_id': None},
    {'t': 'database', 'id': 12, 'name': 'shop-old_db', 'type': 'mysql', 'dom_id': 1, 'server_id': 1, 'default_user_id': 22},
    {'t': 'database', 'id': 13, 'name': 'addon_wp', 'type': 'mysql', 'dom_id': 1, 'server_id': 1, 'default_user_id': None},
    {'t': 'dbuser', 'id': 21, 'login': 'shop_wpuser', 'db_id': 11, 'dom_id': 1},
    {'t': 'dbuser', 'id': 22, 'login': 'shop_old', 'db_id': 12, 'dom_id': 1},
    {'t': 'dbuser', 'id': 23, 'login': 'shop_all', 'db_id': 0, 'dom_id': 1},
    {'t': 'dbserver', 'id': 1, 'host': 'localhost', 'port': 3306, 'type': 'mysql'},
    {'t': 'dbserver', 'id': 2, 'host': 'db.remote', 'port': 3306, 'type': 'mysql'},
    {'t': 'charset', 'name': 'shop_wp', 'charset': 'utf8mb4'},
    {'t': 'ip', 'address': '203.0.113.5'},
    {'t': 'traffic', 'dom_id': 1, 'bytes': 2048},
]
PLESK_CRONTAB = """MAILTO=""
SHELL="/bin/sh"
#@desc: Running wp-cron.php for WordPress at https://shop.test
3,33\t*\t*\t*\t*\t/opt/alt/php74/usr/bin/php -f 'httpdocs/wp-cron.php'
#@desc: Spuštěn soubor wp-cron.php pro WordPress na adrese https://shop.test
3,33\t*\t*\t*\t*\t/opt/alt/php81/usr/bin/php -f 'httpdocs/wp-cron.php'
0 * * * * curl -fsS 'https://shop.test/wp-cron.php?doing_wp_cron'
#@desc: Feed import
7,37\t*\t*\t*\t*\t/opt/alt/php74/usr/bin/php -f 'httpdocs/feed.php'
7,37\t*\t*\t*\t*\t/opt/alt/php81/usr/bin/php -f 'httpdocs/feed.php'
SHELL="/usr/local/psa/bin/chrootsh"
*/5 * * * * /opt/plesk/php/8.2/bin/php -q /var/www/vhosts/shop.test/httpdocs/blog/cron.php >/dev/null 2>&1
0 4 * * * /httpdocs/tools/run --root=/httpdocs/var
15 * * * * php /addon.test/cron.php
0 * * * * curl -fsS 'https://shop.test/cron?token=x'
0 * * * * wget -q -O /dev/null https://elsewhere.test/ping
*/1 * * * * /httpdocs/fast.sh
@reboot /httpdocs/start.sh
0 1 * * * cd /httpdocs && php run.php
0 2 * * * /httpdocs/copy.sh /logs/access_log
"""
PLESK_ACCOUNT = {'uid': 10001, 'gid': 1004, 'group': 'psacln', 'crontab': PLESK_CRONTAB,
                 'entries': ['.cagefs', '.ssh', 'addon.test', 'bin', 'httpdocs', 'logs', 'own.shop.test', 'private-data', 'wordpress-backups']}


class PleskTests(unittest.TestCase):
    def inventory(self, domain='shop.test', **kwargs):
        return m.plesk_inventory(PLESK_ROWS, PLESK_ACCOUNT, domain, **kwargs)

    def test_website_children_and_notes_follow_the_plesk_layout(self):
        inventory = self.inventory()
        site = inventory['site']
        self.assertEqual(('/var/www/vhosts/shop.test', HOME + '/httpdocs', 'shopuser', 'psacln', 10001, 1004, '8.1', '*', 'shop.test'),
                         (site['document_root'], site['www_root'], site['system_user'], site['system_group'], site['uid'],
                          site['gid'], site['php_version'], site['subdomain'], site['subscription']))
        children = {child['domain']: child for child in inventory['children']}
        self.assertEqual({'blog.shop.test', 'same.shop.test', 'shop.example', 'shop.other'}, set(children))
        self.assertEqual(('vhostsubdomain', 'web/blog'), (children['blog.shop.test']['type'], children['blog.shop.test']['web_folder']))
        self.assertEqual(('subdomain', 'none'), (children['same.shop.test']['type'], children['same.shop.test']['subdomain']))
        self.assertEqual(('R=301,L', '[scheme]://shop.test/'), (children['shop.example']['redirect_type'], children['shop.example']['redirect_path']))
        self.assertEqual(('', 'www'), (children['shop.other']['redirect_type'], children['shop.other']['subdomain']))
        notes = '\n'.join(inventory['notes'])
        for expected in ('own.shop.test has its own folder', 'go.shop.test has no website hosting', 'mail-only.test is not used',
                         'Other websites of this Plesk subscription, migrated separately: addon.test', 'Duplicate cron job skipped'):
            self.assertIn(expected, notes)
        # Chroot/Plesk files are not reported; folders of the subscription's other websites neither.
        self.assertEqual(['private-data', 'wordpress-backups'], inventory['not_copied'])

    def test_databases_users_and_explicit_selection(self):
        databases = {db['database_name']: db for db in self.inventory()['databases']}
        self.assertEqual(['addon_wp', 'shop-old_db', 'shop_wp'], sorted(databases))
        self.assertEqual(('shop_wpuser', ['shop_all', 'shop_wpuser'], 'utf8mb4'),
                         (databases['shop_wp']['database_user'], databases['shop_wp']['database_users'], databases['shop_wp']['database_charset']))
        self.assertEqual('shop_old', databases['shop-old_db']['database_user'])  # Plesk's default user
        self.assertEqual('shop_all', databases['addon_wp']['database_user'])  # only the subscription-wide user
        addon = m.plesk_inventory(PLESK_ROWS, PLESK_ACCOUNT, 'addon.test', databases=['addon_wp'])
        self.assertEqual(['addon_wp'], [db['database_name'] for db in addon['databases']])
        # Subdomains in the main website's folder go with it; one with its own folder is migrated on its own.
        self.assertIn('Other websites of this Plesk subscription, migrated separately: own.shop.test, shop.test', '\n'.join(addon['notes']))
        with self.assertRaisesRegex(m.MigrationError, 'Not a database of this Plesk subscription: other_db'):
            self.inventory(databases=['other_db'])
        remote = PLESK_ROWS + [{'t': 'database', 'id': 14, 'name': 'far', 'type': 'mysql', 'dom_id': 1, 'server_id': 2, 'default_user_id': None}]
        with self.assertRaisesRegex(m.MigrationError, 'not on the local MySQL server'):
            m.plesk_inventory(remote, PLESK_ACCOUNT, 'shop.test')

    def test_websites_that_cannot_be_migrated_stop_with_the_reason(self):
        for domain, message in (('off.test', 'suspended or disabled'), ('mail.test', 'no website hosting'),
                                ('_.shop.test', 'wildcard subdomain'), ('nested.test', 'subfolder of the webspace folder'),
                                ('missing.test', 'not on the Plesk server')):
            with self.subTest(domain=domain), self.assertRaisesRegex(m.MigrationError, message):
                m.plesk_site(PLESK_ROWS, domain)

    def test_plesk_php_versions_carry_over_to_the_website_and_its_subdomains(self):
        migration = object.__new__(m.Migration)
        migration.kind, migration.client_id, migration.php_version = 'plesk', 6, None
        migration.target = {'web_server_id': 4, 'server_php_id': 0}
        rows = [{'id': 11, 'name': 'PHP 7.4', 'active': 'y', 'php_fpm_ini_dir': '/etc/php/7.4/fpm', 'client_id': 0},
                {'id': 12, 'name': 'PHP 8.1', 'active': 'y', 'php_fpm_ini_dir': '/etc/php/8.1/fpm', 'client_id': 0}]
        migration.admin = MagicMock()
        migration.admin.all.return_value = rows
        migration.state = {'objects': {}, 'inventory': self.inventory()}  # alt-php81-fpm, blog.shop.test alt-php74-fpm
        self.assertEqual({'version': '8.1', 'server_php_id': 12, 'source': 'plesk'}, migration.select_php())
        self.assertEqual({'s3': {'version': '7.4', 'server_php_id': 11}}, migration.state['php_children'])
        # A subdomain version the new web server lacks gets the website's PHP.
        migration.admin.all.return_value = rows[1:]
        del migration.state['php']
        migration.select_php()
        self.assertEqual({'s3': {'version': '7.4', 'server_php_id': None}}, migration.state['php_children'])
        # --php sets the website and its subdomains.
        migration.php_version = '7.4'
        migration.admin.all.return_value = rows
        self.assertEqual({'version': '7.4', 'server_php_id': 11}, migration.select_php())
        self.assertEqual({}, migration.state['php_children'])
        # The website's version missing on the new web server stops the plan.
        migration.php_version = None
        del migration.state['php']
        migration.admin.all.return_value = rows[:1]
        with self.assertRaisesRegex(m.MigrationError, r'The Plesk website runs PHP 8.1 \(alt-php81-fpm\), which the new web server '
                                                      r'does not offer: .*available: PHP 7.4.*--php VERSION'):
            migration.select_php()

    def test_cron_jobs_map_webspace_paths_and_list_the_rest_for_review(self):
        jobs = {job['source']: job for job in self.inventory()['cron']}
        client = {'limit_cron_type': 'full', 'limit_cron_frequency': 5}
        root = '/var/www/clients/client3/web9'

        def target(source, cron_type='full'):
            job = jobs[source]
            self.assertIsNone(m.cron_decision(job, client), source)
            return m.render_cron(job, document_root=root, cron_type=cron_type, php_cli='/usr/bin/php8.1')

        self.assertEqual('/usr/bin/php8.1 -f %s/web/feed.php' % root, target("/opt/alt/php74/usr/bin/php -f 'httpdocs/feed.php'"))
        self.assertEqual('/usr/bin/php8.1 -f /web/feed.php', target("/opt/alt/php74/usr/bin/php -f 'httpdocs/feed.php'", 'chrooted'))
        self.assertEqual('/usr/bin/php8.1 -q %s/web/blog/cron.php >/dev/null 2>&1' % root,
                         target('/opt/plesk/php/8.2/bin/php -q /var/www/vhosts/shop.test/httpdocs/blog/cron.php >/dev/null 2>&1'))
        self.assertEqual('%s/web/tools/run --root=%s/web/var' % (root, root), target('/httpdocs/tools/run --root=/httpdocs/var'))
        self.assertEqual('https://shop.test/cron?token=x', target("curl -fsS 'https://shop.test/cron?token=x'"))
        self.assertEqual('Feed import', jobs["/opt/alt/php74/usr/bin/php -f 'httpdocs/feed.php'"]['description'])
        # WP Toolkit's WordPress cron is turned on in the panel instead, whatever its PHP, description or form.
        self.assertEqual([], [source for source in jobs if 'wp-cron' in source])
        self.assertIn('WordPress cron (WP Toolkit, 3 job(s) running wp-cron.php) is not migrated', '\n'.join(self.inventory()['notes']))
        for command, wordpress in (("php -f 'httpdocs/wp-cron.php'", True), ('wget -q -O - https://a.test/wp-cron.php', True),
                                   ('php /httpdocs/wp-cron.php >/dev/null 2>&1', True), ('php httpdocs/my-wp-cron.php', False),
                                   ('php httpdocs/wp-cron.php.bak', False)):
            with self.subTest(command=command):
                self.assertEqual(wordpress, bool(m.WORDPRESS_CRON.search(command)))
        # Another website's job stays with its own migration; a URL of another host belongs to the subscription.
        self.assertNotIn('php /addon.test/cron.php', jobs)
        self.assertIn('wget -q -O /dev/null https://elsewhere.test/ping', jobs)
        for source, reason in (('/httpdocs/fast.sh', '\\*/1'), ('/httpdocs/start.sh', '@reboot'),
                               ('cd /httpdocs && php run.php', 'shell syntax'), ('/httpdocs/copy.sh /logs/access_log', 'not migrated: logs/access_log')):
            with self.subTest(source=source):
                self.assertRegex(m.cron_decision(jobs[source], client), reason)
        addon = m.plesk_inventory(PLESK_ROWS, PLESK_ACCOUNT, 'addon.test')
        self.assertEqual(['php /addon.test/cron.php'], [job['source'] for job in addon['cron']])
        self.assertEqual('php %s/web/cron.php' % root, m.render_cron(addon['cron'][0], document_root=root, cron_type='full', php_cli='php'))

    def test_cron_limits_follow_the_client_plan(self):
        job = {'schedule': ['*/5', '*', '*', '*', '*'], 'words': ['/web/run.sh'], 'suffix': ''}
        self.assertRegex(m.cron_decision(job, {'limit_cron_type': 'url'}), 'only URL cron jobs')
        self.assertIsNone(m.cron_decision(dict(job, url='https://a.test/'), {'limit_cron_type': 'url'}))
        self.assertRegex(m.cron_decision(job, {'limit_cron_type': 'chrooted', 'limit_cron_frequency': 10}), 'every 5 minutes')
        self.assertIsNone(m.cron_decision(job, {'limit_cron_type': 'chrooted', 'limit_cron_frequency': 5}))
        # The same intervals as ISPConfig's validate_cron (CronJob::minIntervalMinutes).
        for fields, interval in ((['27,57', '*', '*', '*', '*'], 30), (['0', '*', '*', '*', '*'], 60), (['*/5', '*', '*', '*', '*'], 5),
                                 (['0', '3', '*', '*', '*'], 1440), (['0', '0', '1', '*', '*'], 1440), (['0', '0', '*', '*', '1,4,7'], 1440)):
            with self.subTest(fields=fields):
                self.assertEqual(interval, m.cron_interval(fields))
        for name, minimum, maximum, value, valid in (('min', 0, 59, '*/1', False), ('min', 0, 59, '5-3', False), ('wday', 0, 7, 'mon', False),
                                                     ('min', 0, 59, '0-30/10', True), ('hour', 0, 23, '24', False)):
            with self.subTest(value=value):
                self.assertEqual(valid, m.cron_field_valid(minimum, maximum, value))

    def test_sites_inventory_lists_websites_aliases_and_traffic(self):
        sites = {site['domain']: site for site in m.site_list(m.plesk_sites_inventory(PLESK_ROWS, 'plesk.test'))}
        self.assertEqual({'shop.test', 'blog.shop.test', 'own.shop.test', 'go.shop.test', 'addon.test', 'off.test', 'nested.test'}, set(sites))
        shop = sites['shop.test']
        self.assertEqual(['shop.test', 'www.shop.test', 'same.shop.test', 'www.same.shop.test', 'shop.example', 'www.shop.example',
                          'shop.other', 'www.shop.other'], shop['hostnames'])
        self.assertEqual((3, 2048, 'shop Shop s.r.o.', 'plesk.test'), (shop['databases'], shop['traffic_30d_bytes'], shop['client'], shop['server']))
        self.assertEqual(('vhostalias', 'shop.test'), (sites['addon.test']['type'], sites['addon.test']['parent']))
        self.assertEqual(('vhostsubdomain', 'shop.test'), (sites['blog.shop.test']['type'], sites['blog.shop.test']['parent']))
        self.assertFalse(sites['off.test']['active'])
        self.assertEqual('forwarding', sites['go.shop.test']['redirect'])

    def test_plesk_source_selection_keeps_existing_fingerprints(self):
        target = {'api_url': 'https://panel.example/api/v1', 'api_key_file': '/unused', 'web_ssh': 'root@new',
                  'db_ssh': 'root@db', 'web_server_id': 4, 'db_server_id': 5, 'db_host': 'db0'}
        config = {'source': {'panel_ssh': 'root@old', 'web_ssh': 'root@old', 'db_ssh': {'1': 'root@old'}}, 'target': target}
        with_sources = dict(config, sources={'plesk': {'type': 'plesk', 'ssh': 'root@plesk.test'}})
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second, patch.object(m, 'Api', MagicMock()):
            self.assertEqual(m.Migration(config, first, 'example.com', 6).state['fingerprint'],
                             m.Migration(m.select_source(with_sources, None), second, 'example.com', 6).state['fingerprint'])
        plesk = m.select_source(with_sources, 'plesk')
        self.assertEqual({'type': 'plesk', 'ssh': 'root@plesk.test'}, plesk['source'])
        self.assertNotIn('sources', plesk)
        with self.assertRaisesRegex(m.MigrationError, 'no source "cpanel"'):
            m.select_source(with_sources, 'cpanel')
        with tempfile.TemporaryDirectory() as state, patch.object(m, 'Api', MagicMock()):
            self.assertEqual('plesk', m.Migration(plesk, state, 'shop.test', 6).kind)
            with self.assertRaisesRegex(m.MigrationError, 'exactly "type": "plesk" and "ssh"'):
                m.Migration(dict(plesk, source={'type': 'plesk', 'ssh': 'root@p', 'web_ssh': 'root@p'}), state, 'shop.test', 6)
        args = m.parse_args(['--simple', 'shop.test', '6', '--from', 'plesk', '--database', 'a_db', '--database', 'b_db'])
        self.assertEqual(('plesk', ['a_db', 'b_db']), (args.source_name, args.database))
        self.assertEqual('plesk', m.parse_args(['--simple', '--sites', '--from', 'plesk']).source_name)

    def test_helper_runs_with_the_python_of_rhel8_and_never_as_a_shell_string(self):
        import ast
        code = (TOOLS / 'plesk-source.py').read_text()
        ast.parse(code, feature_version=(3, 6))
        self.assertNotIn('capture_output', code)  # Python 3.7+
        command = m.plesk_command('root@plesk.test')
        self.assertEqual(['root@plesk.test'], command[-2:-1])
        self.assertIn('/usr/libexec/platform-python', command[-1])

    def test_staged_configuration_naming_the_old_webspace_is_reported(self):
        with tempfile.TemporaryDirectory() as tree:
            web = Path(tree, 'web')
            (web / 'wp-content').mkdir(parents=True)
            (web / '.user.ini').write_text("auto_prepend_file = '/var/www/vhosts/shop.test/httpdocs/wordfence-waf.php'\n")
            (web / 'index.php').write_text('<?php // /var/www/vhosts/shop.test/httpdocs\n')
            (web / 'wp-content/cache.php').write_text('/var/www/vhosts/shop.test/httpdocs/x')  # deeper PHP: not scanned
            (web / 'wp-content/.htaccess').write_text('php_value include_path /var/www/vhosts/shop.test.old/x')  # other site
            self.assertEqual(['web/.user.ini', 'web/index.php'], m.old_path_references(tree, '/var/www/vhosts/shop.test'))

    def test_absolute_links_into_the_plesk_document_root_become_relative(self):
        with tempfile.TemporaryDirectory() as tree:
            (Path(tree) / 'web/wp-content').mkdir(parents=True)
            (Path(tree) / 'private').mkdir()
            (Path(tree) / 'web/wp-content/uploads').mkdir()
            (Path(tree) / 'web/media').symlink_to(HOME + '/httpdocs/wp-content/uploads')
            m.normalize_links(tree, [(HOME + '/httpdocs', 'web')])
            self.assertEqual('wp-content/uploads', os.readlink(Path(tree) / 'web/media'))
            (Path(tree) / 'web/logs').symlink_to(HOME + '/logs')
            with self.assertRaisesRegex(m.MigrationError, 'External absolute symlink'):
                m.normalize_links(tree, [(HOME + '/httpdocs', 'web')])


def zone_row(id, name, **values):
    return dict({'t': 'zone', 'id': id, 'name': name, 'status': 0, 'type': 'master', 'email': 'admin@provider.test', 'ttl': 7200,
                 'refresh': 14400, 'retry': 3600, 'expire': 604800, 'minimum': 3600}, **values)


def record_row(id, zone, kind, host, value, opt='', ttl=None):
    return {'t': 'record', 'id': id, 'zone_id': zone, 'type': kind, 'host': host, 'val': value, 'opt': opt, 'ttl': ttl}


PLESK_IPV4, PLESK_IPV6 = '203.0.113.5', '2001:db8:5::5'
NOVA_IPV4, NOVA_IPV6 = '198.51.100.119', '2001:db8:100::a877'
SHOP_RECORDS = [
    record_row(1, 31, 'NS', 'shop.test.', 'ns.provider.test.'), record_row(2, 31, 'NS', 'shop.test.', 'ns2.provider.test.'),
    record_row(3, 31, 'A', 'shop.test.', PLESK_IPV4), record_row(4, 31, 'AAAA', 'shop.test.', '2001:0db8:5:0::5', ttl=60),
    record_row(5, 31, 'A', 'ipv4.shop.test.', PLESK_IPV4, ttl=60), record_row(6, 31, 'A', 'mail.shop.test.', '198.51.100.7'),
    record_row(7, 31, 'CNAME', 'www.shop.test.', 'shop.test.'), record_row(8, 31, 'CNAME', '*.shop.test.', 'shop.test.'),
    record_row(9, 31, 'MX', 'shop.test.', 'mail.provider.test.', '10', 7200),
    record_row(10, 31, 'SRV', '_autodiscover._tcp.shop.test.', 'mail.provider.test.', '5 25 443'),
    record_row(11, 31, 'TXT', 'shop.test.', 'v=spf1 +a +mx -all', ttl=86400),
    record_row(12, 31, 'TXT', '_dmarc.shop.test.', 'v=DMARC1; p=none'), record_row(21, 31, 'TXT', 'dkim._domainkey.shop.test.', 'v=DKIM1; k=rsa; p=MIIB'),
    record_row(13, 31, 'TXT', 'quoted.shop.test.', 'say "hi"'), record_row(14, 31, 'CAA', 'shop.test.', 'letsencrypt.org', 'issue'),
    record_row(15, 31, 'A', 'elsewhere.test.', PLESK_IPV4), record_row(16, 31, 'AXFR', '', '198.51.100.1'),
    record_row(17, 31, 'NS', 'dev.shop.test.', 'ns.provider.test.'), record_row(18, 31, 'NS', 'ext.shop.test.', 'ns1.other.test.'),
    record_row(19, 31, 'A', 'a' * 60 + '.shop.test.', '198.51.100.8'), record_row(20, 31, 'TXT', '*.shop.test.', 'wild', ttl=30),
]


class HostingApi:
    """Admin reads of dns_plan(): the client's hosting addresses and the zones already in the new ISPConfig."""
    zones = []

    def get(self, path):
        assert path == '/me/hosting-addresses?client_id=6', path
        return {'client_id': 6, 'web': [{'server_id': 4, 'server_name': 'web0.target.test', 'is_default': True,
                                         'ipv4': [NOVA_IPV4], 'ipv6': [NOVA_IPV6]}],
                'mail': [], 'dns': [{'server_id': 7, 'server_name': 'ns1.target.test', 'is_default': True, 'nameservers': [
                    {'name': 'ns1.target.test', 'ipv4': ['192.0.2.53'], 'ipv6': []}, {'name': 'ns2.target.test', 'ipv4': [], 'ipv6': []}]}]}

    def all(self, path, **query):
        assert path == '/dns/soa' and set(query) == {'origin'}, (path, query)
        return [zone for zone in self.zones if zone['origin'] == query['origin']]


class PleskDnsTests(unittest.TestCase):
    def zone(self, records=SHOP_RECORDS, **values):
        return m.nova_zone(zone_row(31, 'shop.test', **values), records, plesk_addresses={PLESK_IPV4, PLESK_IPV6},
                           ipv4=NOVA_IPV4, ipv6=NOVA_IPV6, nameservers=['ns1.target.test', 'ns2.target.test'])

    def test_zone_copy_changes_only_the_name_servers_and_the_plesk_addresses(self):
        zone = self.zone()
        self.assertEqual({'origin': 'shop.test.', 'ns': 'ns1.target.test.', 'mbox': 'admin.provider.test.', 'ttl': 7200, 'refresh': 14400,
                          'retry': 3600, 'expire': 604800, 'minimum': 3600, 'active': False}, zone['soa'])

        found = {(record['name'], record['type'], m.record_value(record)): record for record in zone['records']}
        long_name = 'a' * 60
        self.assertEqual({
            ('shop.test.', 'NS', 'ns1.target.test.'), ('shop.test.', 'NS', 'ns2.target.test.'),
            ('shop.test.', 'A', NOVA_IPV4), ('shop.test.', 'AAAA', NOVA_IPV6), ('ipv4.shop.test.', 'A', NOVA_IPV4),
            ('mail.shop.test.', 'A', '198.51.100.7'), ('www.shop.test.', 'CNAME', 'shop.test.'), ('*.shop.test.', 'CNAME', 'shop.test.'),
            ('shop.test.', 'MX', '10 mail.provider.test.'), ('_autodiscover._tcp.shop.test.', 'SRV', '5 25 443 mail.provider.test.'),
            ('shop.test.', 'SPF', 'v=spf1 mx a -all'), ('dkim._domainkey.shop.test.', 'DKIM', 'v=DKIM1; k=rsa; p=MIIB'),
            ('_dmarc.shop.test.', 'DMARC', 'v=DMARC1; p=none'),
            ('dev.shop.test.', 'NS', 'ns1.target.test.'), ('dev.shop.test.', 'NS', 'ns2.target.test.'),
            ('ext.shop.test.', 'NS', 'ns1.other.test.'), (long_name, 'A', '198.51.100.8'), ('*.shop.test.', 'TXT', 'wild'),
        }, set(found))
        # TTLs: the record's own, else the zone's; ISPConfig's minimum is 60 s.
        self.assertEqual([7200, 60, 7200, 86400, 60], [found[key]['ttl'] for key in (
            ('shop.test.', 'A', NOVA_IPV4), ('shop.test.', 'AAAA', NOVA_IPV6), ('shop.test.', 'MX', '10 mail.provider.test.'),
            ('shop.test.', 'SPF', 'v=spf1 mx a -all'), ('*.shop.test.', 'TXT', 'wild'))])
        self.assertEqual({'type': 'SRV', 'name': '_autodiscover._tcp.shop.test.', 'priority': 5, 'weight': 25, 'port': 443,
                          'hostname': 'mail.provider.test.', 'ttl': 7200, 'active': True},
                         found[('_autodiscover._tcp.shop.test.', 'SRV', '5 25 443 mail.provider.test.')])
        # DMARC is created last: ISPConfig checks for the DKIM and SPF records then. SPF as ISPConfig writes it.
        self.assertEqual('DMARC', zone['records'][-1]['type'])
        self.assertEqual([{'name': 'shop.test', 'old': 'v=spf1 +a +mx -all', 'new': 'v=spf1 mx a -all'}], zone['rewritten'])
        self.assertEqual([('ipv4.shop.test', 'A'), ('shop.test', 'A'), ('shop.test', 'AAAA')],
                         sorted((item['name'], item['type']) for item in zone['remapped']))
        self.assertEqual(['elsewhere.test A %s (outside the zone)' % PLESK_IPV4,
                          'quoted.shop.test TXT say "hi" (value ISPConfig does not accept as is)',
                          'shop.test CAA letsencrypt.org (CAA records are not copied)'], sorted(zone['manual']))

    def test_name_server_glue_stays_and_a_missing_ipv6_is_left_to_the_operator(self):
        records = [record_row(1, 40, 'NS', 'provider.test.', 'ns.provider.test.'), record_row(2, 40, 'A', 'ns.provider.test.', PLESK_IPV4),
                   record_row(3, 40, 'A', 'www.provider.test.', PLESK_IPV4), record_row(4, 40, 'AAAA', 'www.provider.test.', PLESK_IPV6)]
        zone = m.nova_zone(zone_row(40, 'provider.test', email='Jana.Novak@provider.test', ttl=30), records,
                           plesk_addresses={PLESK_IPV4, PLESK_IPV6}, ipv4=NOVA_IPV4, ipv6=None, nameservers=['ns1.target.test'])
        self.assertEqual({('ns.provider.test.', PLESK_IPV4), ('www.provider.test.', NOVA_IPV4)},
                         {(record['name'], record['data']) for record in zone['records'] if record['type'] == 'A'})
        self.assertEqual(['www.provider.test AAAA %s (the new web server has no IPv6 address)' % PLESK_IPV6], zone['manual'])
        self.assertEqual(('jana.novak.provider.test.', 60), (zone['soa']['mbox'], zone['soa']['ttl']))
        self.assertEqual('hostmaster.provider.test.', m.nova_zone(zone_row(40, 'provider.test', email='x y@z'), records,
                         plesk_addresses=set(), ipv4=None, ipv6=None, nameservers=['ns1.target.test'])['soa']['mbox'])

    def test_spf_and_dmarc_become_the_fields_of_their_ispconfig_records_or_are_left_to_the_operator(self):
        fields = m.spf_fields('v=spf1 +a +mx +a:plesk.example.net ip4:192.0.2.0/24 ip6:2001:db8::1 include:_spf.provider.test ~all')
        self.assertEqual({'allow_mx': True, 'allow_a': True, 'hostname': 'plesk.example.net', 'ipv4_address': '192.0.2.0/24',
                          'ipv6_address': '2001:db8::1', 'include': '_spf.provider.test', 'policy': 'softfail'}, fields)
        self.assertEqual('v=spf1 mx a ip4:192.0.2.0/24 ip6:2001:db8::1 a:plesk.example.net include:_spf.provider.test ~all', m.spf_text(fields))
        for text in ('v=spf1 include:x.test', 'v=spf1 a +all', 'v=spf1 ptr -all', 'v=spf1 -ip4:192.0.2.1 -all', 'v=spf1 redirect=x.test',
                     'v=spf1 -all a', 'v=spf1 ip4:2001:db8::1 -all', 'v=spf1 mx:mail.test -all'):
            with self.subTest(text=text):
                self.assertIsNone(m.spf_fields(text))
        fields = m.dmarc_fields('v=DMARC1; p=reject; rua=mailto:a@x.test, mailto:b@y.test; pct=50; aspf=s')
        self.assertEqual({'policy': 'reject', 'rua': 'mailto:a@x.test,mailto:b@y.test', 'pct': 50, 'aspf': 's'}, fields)
        self.assertEqual('v=DMARC1; p=reject; rua=mailto:a@x.test,mailto:b@y.test; aspf=s; pct=50', m.dmarc_text(fields))
        for text in ('v=DMARC1; rua=mailto:a@x.test', 'v=DMARC1; p=none; fo=d', 'v=DMARC1; p=all', 'v=DMARC1; p=none; rua=a@x.test'):
            with self.subTest(text=text):
                self.assertIsNone(m.dmarc_fields(text))
        # Without a DKIM record ISPConfig refuses DMARC: left to the operator, like DMARC it cannot express.
        zone = self.zone([record_row(1, 31, 'TXT', '_dmarc.shop.test.', 'v=DMARC1; p=quarantine; adkim=s; aspf=s'),
                          record_row(2, 31, 'TXT', 'shop.test.', 'v=spf1 a mx -all'),
                          record_row(3, 31, 'TXT', '_dmarc.shop.test.', 'v=DMARC1; p=none; fo=d')])
        self.assertEqual(['_dmarc.shop.test TXT v=DMARC1; p=none; fo=d (DMARC that ISPConfig cannot hold as is)',
                          '_dmarc.shop.test TXT v=DMARC1; p=quarantine; adkim=s; aspf=s (ISPConfig accepts DMARC only in a zone with a '
                          'DKIM record)'], sorted(zone['manual']))

    def test_inventory_lists_the_zones_of_the_website_its_aliases_and_subdomains(self):
        inventory = m.plesk_inventory(PLESK_ROWS, PLESK_ACCOUNT, 'shop.test')
        self.assertEqual([(31, 'shop.test', 'website'), (35, 'blog.shop.test', 'subdomain'), (34, 'mail-only.test', 'alias'),
                          (32, 'shop.example', 'alias')],
                         [(zone['id'], zone['domain'], zone['role']) for zone in inventory['dns_zones']])

    def migration(self, objects=None):
        migration = object.__new__(m.Migration)
        migration.client_id, migration.kind, migration.target = 6, 'plesk', {'web_server_id': 4}
        migration.admin = migration.api = HostingApi()
        migration.state = {'objects': objects or {}, 'inventory': {'dns_zones': [
            {'id': 31, 'domain': 'shop.test', 'role': 'website'}, {'id': 32, 'domain': 'shop.example', 'role': 'alias'},
            {'id': 33, 'domain': 'gone.example', 'role': 'alias'}, {'id': 34, 'domain': 'mail-only.test', 'role': 'alias'},
            {'id': 35, 'domain': 'blog.shop.test', 'role': 'subdomain'}, {'id': 36, 'domain': 'other.test', 'role': 'alias'}]}}
        migration.save = lambda: None
        return migration

    def test_only_zones_public_dns_delegates_to_plesk_are_planned(self):
        rows = [zone_row(31, 'shop.test'), zone_row(32, 'shop.example'), zone_row(34, 'mail-only.test', status=16),
                zone_row(35, 'blog.shop.test'), zone_row(36, 'other.test'), {'t': 'ip', 'address': PLESK_IPV4}] + SHOP_RECORDS + [
            record_row(30, 32, 'NS', 'shop.example.', 'ns.provider.test.'), record_row(31, 35, 'NS', 'blog.shop.test.', 'ns.provider.test.'),
            record_row(32, 36, 'NS', 'other.test.', 'ns.provider.test.')]
        public = {'shop.test': (['ns.provider.test', 'ns2.provider.test'], None), 'shop.example': (['ns1.registrar.test'], None),
                  'blog.shop.test': (['ns.provider.test'], None), 'other.test': ([], 'NXDOMAIN')}
        HostingApi.zones = [{'id': 90, 'origin': 'blog.shop.test.'}]
        self.addCleanup(setattr, HostingApi, 'zones', [])
        plan = self.migration().dns_plan(rows=rows, lookup=public.get)
        self.assertEqual(['shop.test'], [zone['origin'] for zone in plan['zones']])
        self.assertEqual((7, NOVA_IPV4, NOVA_IPV6), (plan['zones'][0]['soa']['server_id'], plan['ipv4'], plan['ipv6']))
        self.assertEqual([
            'shop.example: public DNS does not use the Plesk name servers (ns1.registrar.test)',
            'gone.example: no DNS zone in Plesk',
            'mail-only.test: DNS is switched off in Plesk',
            'blog.shop.test: the zone already exists in the new ISPConfig (zone ID 90) and is left unchanged',
            'other.test: public DNS does not use the Plesk name servers (NXDOMAIN)'], plan['skipped'])
        # A zone this migration created is its own, not "already exists".
        HostingApi.zones = [{'id': 90, 'origin': 'shop.test.'}]
        plan = self.migration({'zone:shop.test': {'record': {'id': 90}}}).dns_plan(rows=rows, lookup=public.get)
        self.assertEqual(['shop.test', 'blog.shop.test'], [zone['origin'] for zone in plan['zones']])

    def test_dns_counts_and_the_client_without_a_dns_server(self):
        migration = self.migration({'zone:shop.test': {'record': {'id': 90}}, 'rr:shop.test:0': {'record': {'id': 1}}})
        migration.state['dns'] = {'zones': [{'origin': 'shop.test', 'records': [{}, {}, {}]}, {'origin': 'shop.example', 'records': [{}]}]}
        self.assertEqual({'dns_zones': 1, 'dns_records': 3}, migration.dns_counts())
        migration.dns = False
        self.assertEqual({}, migration.dns_counts())
        migration.admin = MagicMock()
        migration.admin.get.return_value = {'web': [], 'dns': []}
        with self.assertRaisesRegex(m.MigrationError, 'no DNS server .* \\(--no-dns\\)'):
            migration.hosting_addresses()

    def test_public_name_servers_come_from_the_resolver(self):
        dns = FakeDns({'shop.test': [('NS', 'ns.provider.test'), ('NS', 'NS2.provider.test')], 'www.shop.test': [('A', PLESK_IPV4)]})
        self.addCleanup(dns.close)
        self.assertEqual((['ns.provider.test', 'ns2.provider.test'], None), m.public_nameservers('Shop.Test.', [dns.address]))
        self.assertEqual(([], 'NXDOMAIN'), m.public_nameservers('gone.test', [dns.address]))
        self.assertEqual(([], 'no NS records'), m.public_nameservers('www.shop.test', [dns.address]))  # not a zone of its own

    def test_dns_command_shows_or_creates_only_the_zones(self):
        migration = self.migration()
        migration.domain, migration.release_client_key = 'shop.test', MagicMock()
        plan = {'nameservers': [{'name': 'ns1.target.test', 'ipv4': []}], 'skipped': [], 'zones': [
            {'origin': 'shop.test', 'records': [{}], 'remapped': [{'name': 'shop.test', 'type': 'A', 'old': PLESK_IPV4, 'new': NOVA_IPV4}],
             'rewritten': [], 'manual': ['x (y)']}]}
        migration.prepare_dns, migration.create_dns = MagicMock(return_value=plan), MagicMock()
        migration.usage_summary = MagicMock(return_value={'counts': {key: {'used': 0, 'limit': None} for key in m.COUNT_LIMITS}})
        output = io.StringIO()
        with patch('sys.stdout', output):
            migration.dns_only(plan_only=True)
        migration.create_dns.assert_not_called()
        for line in ('DNS: shop.test → ISPConfig client 6', '  shop.test: 1 records; A/AAAA of the Plesk server (%s -> %s) become the '
                     "new web server's for: shop.test" % (PLESK_IPV4, NOVA_IPV4), '  MANUAL x (y)', 'change the domains\' name servers'):
            self.assertIn(line, output.getvalue())
        with patch('sys.stdout', io.StringIO()):
            migration.dns_only()
        migration.create_dns.assert_called_once_with(plan)
        self.assertEqual(2, migration.release_client_key.call_count)  # the client key is switched off in every case
        migration.kind = 'ispconfig'
        with self.assertRaisesRegex(m.MigrationError, '--dns creates the DNS zones of a Plesk website'):
            migration.dns_only()

    def test_dns_options(self):
        self.assertTrue(m.parse_args(['--simple', 'shop.test', '6', '--from', 'plesk', '--dns']).dns)
        self.assertEqual('plan', m.parse_args(['--simple', 'shop.test', '6', '--dns', '--plan']).command)
        self.assertTrue(m.parse_args(['--simple', 'shop.test', '6', '--no-dns']).no_dns)
        for argv in (['--dns', '--no-dns'], ['--dns', '--sync']):
            with self.subTest(argv=argv), self.assertRaises(SystemExit), patch('sys.stderr', io.StringIO()):
                m.parse_args(['--simple', 'shop.test', '6'] + argv)
        self.assertEqual('dns', m.parse_args(['dns', '--config', 'c', '--domain', 'shop.test', '--client-id', '6', '--state', 's']).command)


if __name__ == '__main__':
    unittest.main()
