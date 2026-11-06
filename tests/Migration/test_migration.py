#!/usr/bin/env python3
"""Focused offline tests; integration coverage lives in integration.py."""
import base64
import importlib.util
import json
import os
from pathlib import Path
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
        self.assertEqual('/var/lib/ispconfig-rest-migration/example.com', args.state)
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
