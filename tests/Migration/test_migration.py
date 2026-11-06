#!/usr/bin/env python3
"""Focused offline tests; integration coverage lives in integration.py."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / 'site-migration'
spec = importlib.util.spec_from_file_location('migration', TOOLS / 'migrate.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


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
        databases = databases or {'c57zana': 40 * 1048576}
        migration.state = {'objects': objects or {}, 'source_size': {'web_bytes': 800 * 1048576, 'databases': databases},
                           'inventory': {'children': [{'domain_id': '195', 'type': 'alias'}],
                                         'databases': [{'database_name': name} for name in databases]}}
        return migration

    def test_retry_and_sync_keep_already_created_quotas(self):
        migration = self.migration({'site': {'record': {'hd_quota': 5120, 'traffic_quota': -1}},
                                    'db:c57zana': {'record': {'database_quota': 1024}}})
        # The account is now fully allocated by this migration's own objects.
        quotas = migration.allocation(self.summary(disk=5120, database=1024, allocated_database=1024))
        self.assertEqual({'disk_mb': 5120, 'traffic_mb': -1, 'databases_mb': {'c57zana': 1024}}, quotas)

    def test_database_quota_is_never_omitted_and_splits_by_source_size(self):
        self.assertEqual({'c57zana': 1024}, m.database_quotas(self.summary(), 6, {'c57zana': 40 * 1048576}))
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
                                  'user:c57zana': {'record': {}}})
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
        migration = self.migration(databases={'c57zana': 100 * 1048576})
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
        connection = {'host': 'db0.feldhost.cz', 'port': 3306, 'defaults_file': '/root/reader.cnf'}
        migration.source = {'web_ssh': 'root@web0.feldhost.cz', 'db_via_web': connection}
        db = {'server_id': '2', 'database_name': 'old_db'}
        migration.state = {'inventory': {'site': {'server_id': '1'}, 'databases': [db]}}
        host, request = migration.source_database_route(db)
        self.assertEqual(host, 'root@web0.feldhost.cz')
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


if __name__ == '__main__':
    unittest.main()
