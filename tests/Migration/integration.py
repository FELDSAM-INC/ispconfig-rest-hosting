#!/usr/bin/env python3
"""Disposable-container test: real SSH, rsync, MariaDB and privilege drop.

The REST control plane is a contract-shaped fake; this is not a live ISPConfig test.
Run only inside tests/Migration/integration.sh's disposable container.
"""
import base64
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('migration', ROOT / 'site-migration/migrate.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def sql(command):
    return subprocess.check_output(['mysql', '--batch', '--skip-column-names'], input=command.encode()).decode().strip()


def directory(root, user, group):
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o755)
    for folder in ('web', 'private'):
        (root / folder).mkdir(exist_ok=True)
        shutil.chown(root / folder, user, group)


def install_tool():
    # Exercise the same remote dispatcher invoked by server-tools, from a
    # reviewed root-owned stage. The API's web-owned checkout is never installed directly.
    stage = Path('/root/migration-release')
    shutil.copytree(ROOT / 'site-migration', stage / 'site-migration')
    (stage / 'worker').mkdir()
    (stage / 'server-tools').mkdir()
    shutil.copyfile(ROOT / 'worker/SqlDump.php', stage / 'worker/SqlDump.php')
    shutil.copyfile(ROOT / 'server-tools/remote.php', stage / 'server-tools/remote.php')
    install = ['php', '-r', "define('ISPCP_SERVER_TOOLS_TEST',true); require $argv[1]; ServerToolsRemote::install($argv[2],['migration']);", str(stage / 'server-tools/remote.php'), str(stage)]
    subprocess.run(install, check=True)
    help_text = subprocess.check_output(['/usr/local/sbin/ispcp-migrate', '--help']).decode()
    assert 'domain client_id' in help_text
    assert '--plan' in help_text
    probe = subprocess.check_output(['php', '-r', "define('ISPCP_SERVER_TOOLS_TEST',true); require $argv[1]; echo json_encode(ServerToolsRemote::probe(['server_id'=>1],['migration'],1));", str(stage / 'server-tools/remote.php')])
    probe = json.loads(probe)
    assert probe['requirements'] == [] and probe['grants']['missing'] == []
    assert 'migration' in probe['installed']
    config = Path('/etc/ispconfig-rest-migration/config.json')
    config.write_text('{"keep":"administrator settings"}\n')
    saved = config.read_bytes()
    state = Path('/var/lib/ispconfig-rest-migration/sentinel')
    state.write_text('migration state')
    subprocess.run(install, check=True)
    assert config.read_bytes() == saved and state.read_text() == 'migration state'
    # Do not replace code while the installed launcher holds its shared lock.
    with open('/var/lib/ispconfig-rest-migration/.install.lock', 'r') as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        failure = subprocess.run(install, capture_output=True)
        assert failure.returncode != 0 and b'A migration is running' in failure.stderr
    # Existing symlinks must not turn a root update into a write outside its code directory.
    entry = Path('/usr/local/lib/ispconfig-rest-migration/migrate.py')
    backup = entry.with_suffix('.saved')
    entry.rename(backup)
    entry.symlink_to(state)
    failure = subprocess.run(install, capture_output=True)
    assert failure.returncode != 0 and state.read_text() == 'migration state'
    entry.unlink()
    backup.rename(entry)
    subprocess.run(['/usr/local/sbin/ispcp-migrate', '--help'], check=True, stdout=subprocess.DEVNULL)
    assert config.stat().st_mode & 0o777 == 0o600


class FakeApi:
    rows = {}
    posts = 0

    def __init__(self, url, key_file=None, *, key=None):
        self.key = key

    def get(self, path):
        if path == '/clients/3':
            return {'id': 3, 'username': 'whmcs-provisioned', 'web_servers': [1], 'db_servers': [1]}
        if path == '/usage/summary?client_id=3':
            allocated = sum(row['hd_quota'] for key, row in self.rows.items() if key.startswith('/sites/web-domains/'))
            return {'client_id': 3, 'web_disk': {'limit_bytes': 5120 * 1048576, 'allocated_bytes': allocated * 1048576}}
        return self.rows[path]

    def all(self, path, **query):
        return [value for key, value in self.rows.items() if key.rsplit('/', 1)[0] == path]

    def wait(self, change):
        pass

    def request(self, method, endpoint, payload):
        if endpoint.startswith('/system/api-keys'):
            assert self.key is None
            if method == 'POST':
                self.posts += 1
                self.rows['/system/api-keys/501'] = dict(payload, id=501, active=True, key='test-scoped-key')
            else:
                self.rows[endpoint].update(payload)
            return self.rows['/system/api-keys/501'], None
        assert method == 'POST'
        assert self.key == 'test-scoped-key', 'Resource provisioning must enforce client permissions'
        self.posts += 1
        row = dict(payload, id=104, sys_groupid=3)
        if endpoint == '/sites/web-domains':
            assert payload['hd_quota'] == 5120, 'Website must use the client quota, not the legacy 10 GB setting'
            row.update(document_root='/var/www/clients/client3/web104', system_user='web104', system_group='client3')
            root = Path(row['document_root'])
            directory(root, 'web104', 'client3')
            (root / 'web/index.html').write_text('ISPConfig skeleton')
            shutil.chown(root / 'web/index.html', 'web104', 'client3')
        elif endpoint == '/sites/database-users':
            row['database_user_prefix'] = 'c3'
            username = 'c3' + payload['database_user']
            password = payload['database_password']
            assert "'" not in password
            sql("CREATE USER '%s'@'localhost' IDENTIFIED BY '%s';" % (username, password))
        elif endpoint == '/sites/databases':
            row['database_name_full'] = 'c3' + payload['database_name']
            username = 'c3' + self.rows['/sites/database-users/104']['database_user']
            sql("CREATE DATABASE `%s`; GRANT ALL ON `%s`.* TO '%s'@'localhost';" % (row['database_name_full'], row['database_name_full'], username))
        elif endpoint == '/sites/web-child-domains':
            assert payload['parent_domain_id'] == 104
        else:
            raise AssertionError(endpoint)
        self.rows[endpoint + '/104'] = row
        return row, None


def main():
    assert Path('/.dockerenv').exists(), 'Never run fixture setup on a real host'
    os.umask(0o077)
    subprocess.run(['groupadd', 'client7'], check=True)
    subprocess.run(['groupadd', 'client3'], check=True)
    subprocess.run(['useradd', '-g', 'client7', 'web4'], check=True)
    subprocess.run(['useradd', '-g', 'client3', 'web104'], check=True)
    source_root = Path('/var/www/clients/client7/web4')
    directory(source_root, 'web4', 'client7')
    # Parent roots must remain traversable after the target helper drops privilege.
    for path in [Path('/var/www'), Path('/var/www/clients'), Path('/var/www/clients/client3'), Path('/var/www/clients/client7'), source_root]:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o755)
    source_root.joinpath('web/index.php').write_text('<?php echo "site";')
    source_root.joinpath('web/wp-config.php').write_text("<?php\nfile_put_contents('/tmp/ispcp-customer-code-executed','bad');\ndefine('DB_NAME','old_db');\ndefine('DB_USER','old_user');\ndefine('DB_PASSWORD','old secret');\ndefine('DB_HOST','localhost');\n")
    source_root.joinpath('private/config.txt').write_text('private file')
    source_root.joinpath('web/link').symlink_to(str(source_root / 'private/config.txt'))
    source_root.joinpath('web/delete-on-sync.txt').write_text('delete later')
    sql("""CREATE DATABASE old_db;
        CREATE TABLE old_db.items(id INT PRIMARY KEY, content LONGBLOB) ENGINE=InnoDB;
        INSERT INTO old_db.items VALUES (1, 0x006173642753514c206f6c645f64622e6974656d73);
        CREATE DEFINER=root@localhost VIEW old_db.item_view AS SELECT * FROM old_db.items;
        CREATE DATABASE dbispconfig;
        CREATE TABLE dbispconfig.web_domain(domain_id INT, server_id INT, domain VARCHAR(255), type VARCHAR(20), document_root VARCHAR(255), system_user VARCHAR(32), system_group VARCHAR(32), php VARCHAR(20), server_php_id INT, subdomain VARCHAR(10), hd_quota INT, traffic_quota INT, active CHAR(1), parent_domain_id INT, redirect_type VARCHAR(20), redirect_path VARCHAR(255));
        INSERT INTO dbispconfig.web_domain VALUES (4,1,'example.test','vhost','/var/www/clients/client7/web4','web4','client7','php-fpm',0,'www',1024,-1,'y',0,'','');
        INSERT INTO dbispconfig.web_domain VALUES (5,1,'alias.test','alias','','','','',0,'www',0,0,'y',4,'','');
        CREATE TABLE dbispconfig.web_database(database_id INT, server_id INT, database_name VARCHAR(64), database_charset VARCHAR(20), type VARCHAR(20), active CHAR(1), database_user_id INT, parent_domain_id INT);
        INSERT INTO dbispconfig.web_database VALUES(1,1,'old_db','utf8mb4','mysql','y',1,4);
        CREATE TABLE dbispconfig.web_database_user(database_user_id INT, database_user VARCHAR(32));
        INSERT INTO dbispconfig.web_database_user VALUES(1,'old_user');
        CREATE TABLE dbispconfig.server(server_id INT, server_name VARCHAR(255));
        INSERT INTO dbispconfig.server VALUES(1,'localhost');
    """)
    config_dir = Path('/usr/local/ispconfig/server/lib')
    config_dir.mkdir(parents=True)
    (config_dir / 'config.inc.php').write_text("<?php $conf=array('server_id'=>1,'db_host'=>'localhost','db_user'=>'root','db_password'=>'','db_database'=>'dbispconfig');")
    (config_dir / 'mysql_clientdb.conf').write_text("<?php $clientdb_host='localhost'; $clientdb_user='root'; $clientdb_password='';")
    install_tool()
    # The transfer exercises the helpers and SQL normalizer actually installed by the dispatcher.
    m.HERE = Path('/usr/local/lib/ispconfig-rest-migration')
    config = {
        'source': {'panel_ssh': 'root@127.0.0.1', 'web_ssh': 'root@127.0.0.1', 'db_ssh': {'1': 'root@127.0.0.1'}},
        'target': {'api_url': 'https://panel.example/api/v1', 'api_key_file': '/unused', 'web_ssh': 'root@127.0.0.1',
                   'db_ssh': 'root@127.0.0.1', 'web_server_id': 1, 'db_server_id': 1, 'db_host': 'db.example',
                   'db_remote_ips': '10.20.30.21,10.20.30.20', 'hd_quota_mb': 10240, 'traffic_quota_mb': -1},
    }
    mode = os.environ.get('ISPCP_TEST_SOURCE_MODE', 'direct')
    if mode == 'via-web':
        # Installed CLI defaults to local target access even with an unchanged
        # legacy web_ssh setting. This address has no DNS/SSH setup in the fixture.
        config['target']['web_ssh'] = 'root@target-no-ssh.invalid'
        # An old ISPConfig schema lacks this newer column; exercise the entire
        # migration against it, not just a mocked inventory response.
        sql('ALTER TABLE dbispconfig.web_domain DROP COLUMN server_php_id;')
        # DB server identity intentionally differs from the SSH web host. The SQL
        # connection uses TCP from web; the DB host is never an SSH destination.
        sql("UPDATE dbispconfig.web_database SET server_id=2; INSERT INTO dbispconfig.server VALUES(2,'db-only.invalid');")
        for account_host in ('localhost', '127.0.0.1'):
            sql("CREATE USER 'migration_reader'@'%s' IDENTIFIED BY 'source-test-password';"
                "GRANT SELECT, SHOW VIEW, TRIGGER, EVENT ON old_db.* TO 'migration_reader'@'%s';"
                "GRANT SELECT ON mysql.proc TO 'migration_reader'@'%s';" % (account_host, account_host, account_host))
        credential_file = Path('/root/source-reader.cnf')
        # Host and socket must be overridden by the explicit route, not accidentally
        # used from the credential file. No source secrets are copied into state.
        credential_file.write_text('[client]\nuser=migration_reader\npassword=source-test-password\nhost=unreachable.invalid\nsocket=/nonexistent/mysql.sock\n')
        credential_file.chmod(0o600)
        del config['source']['db_ssh']
        config['source']['db_via_web'] = {'host': '127.0.0.1', 'port': 3306, 'defaults_file': str(credential_file)}
    else:
        config['target']['web_transport'] = 'ssh'
        sql('UPDATE dbispconfig.web_domain SET server_php_id=17 WHERE domain_id=4;')
    # Check the remote PHP helper's inventory before substituting REST.
    m.Api = FakeApi
    with tempfile.TemporaryDirectory(prefix='migration-test-') as state:
        migration = m.Migration(config, state, 'example.test', 3)
        assert migration.local_web == (mode == 'via-web')
        if mode == 'via-web':
            # A mistaken local destination must fail before provisioning anything.
            (config_dir / 'config.inc.php').write_text("<?php $conf=array('server_id'=>99);")
            try:
                migration.check_web_server()
            except m.MigrationError:
                pass
            else:
                raise AssertionError('wrong local ISPConfig server accepted')
            (config_dir / 'config.inc.php').write_text("<?php $conf=array('server_id'=>1,'db_host'=>'localhost','db_user'=>'root','db_password'=>'','db_database'=>'dbispconfig');")
        migration.plan()
        assert FakeApi.posts == 0
        assert 'old_db' in (Path(state) / 'inventory.json').read_text()
        assert migration.state['inventory']['site']['server_php_id'] == ('0' if mode == 'via-web' else '17')
        # A genuine schema error must identify its query and MySQL cause on
        # stderr, with no partial JSON and no exception trace containing config.
        sql('ALTER TABLE dbispconfig.web_database CHANGE database_charset charset_fixture VARCHAR(20);')
        inventory_command = m.php_remote(config['source']['panel_ssh'], 'source-inventory.php')
        failure = subprocess.run(inventory_command, input=b'{"domain":"example.test"}\n', capture_output=True)
        assert failure.returncode != 0 and failure.stdout == b''
        assert b'Source inventory query failed [databases] (MySQL 1054)' in failure.stderr
        assert b'database_charset' in failure.stderr and b'Stack trace' not in failure.stderr
        sql('ALTER TABLE dbispconfig.web_database CHANGE charset_fixture database_charset VARCHAR(20);')
        if mode == 'via-web':
            route_host, route = migration.source_database_route(migration.state['inventory']['databases'][0])
            assert route_host == config['source']['web_ssh'] and route['server_id'] == '1'
            # Test the fallback to trusted ISPConfig credentials as well as the
            # private defaults-file path used by the full migration below.
            (config_dir / 'mysql_clientdb.conf').write_text("<?php $clientdb_host='localhost'; $clientdb_user='migration_reader'; $clientdb_password='source-test-password';")
            auto_route = dict(route, source_connection={'host': '127.0.0.1', 'port': 3306})
            migration.db_io({'action': 'dump', 'source': True, 'database': 'old_db', **auto_route}, host=route_host)
            credential_file.chmod(0o644)
            try:
                migration.db_io({'action': 'dump', 'source': True, 'database': 'old_db', **route}, host=route_host)
            except m.MigrationError:
                pass
            else:
                raise AssertionError('world-readable credentials accepted')
            credential_file.chmod(0o600)
            try:
                migration.db_io({'action': 'import', 'source': True, 'database': 'old_db', **route}, host=route_host)
            except m.MigrationError:
                pass
            else:
                raise AssertionError('source write accepted')
        # Inject a failed import once; the next run must reuse the captured snapshot.
        original_io = migration.db_io
        failed = [False]
        def fail_once(request, **kwargs):
            if request['action'] == 'import' and not failed[0]:
                failed[0] = True
                raise m.MigrationError('simulated interruption')
            return original_io(request, **kwargs)
        migration.db_io = fail_once
        try:
            migration.run(source_quiesced=True)
        except m.MigrationError as exc:
            assert str(exc) == 'simulated interruption', str(exc)
        else:
            raise AssertionError('expected simulated interruption')
        target_root = Path('/var/www/clients/client3/web104')
        # Fake provisioning respects real ISPConfig's traversable root.
        target_root.chmod(0o755)
        migration = m.Migration(config, state, 'example.test', 3)
        migration.run(source_quiesced=True)
        assert migration.state['phase'] == 'copied'
        assert not FakeApi.rows['/system/api-keys/501']['active']
        assert FakeApi.rows['/sites/web-child-domains/104']['domain'] == 'alias.test'
        db = migration.state['databases']['old_db']
        assert sql('SELECT HEX(content) FROM `%s`.items' % db['name']) == sql('SELECT HEX(content) FROM old_db.items')
        assert sql('SELECT COUNT(*) FROM `%s`.item_view' % db['name']) == '1'
        assert sql("SELECT DEFINER FROM information_schema.VIEWS WHERE TABLE_SCHEMA='%s'" % db['name']) == db['user'] + '@localhost'
        target_wp = (target_root / 'web/wp-config.php').read_text()
        assert db['name'] in target_wp and db['password'] in target_wp and "'db.example'" in target_wp
        assert not Path('/tmp/ispcp-customer-code-executed').exists()
        assert (target_root / 'web/link').read_text() == 'private file'
        assert not (target_root / 'web/index.html').exists()
        assert (Path(state) / 'round-000/before/web/index.html').read_text() == 'ISPConfig skeleton'
        assert (target_root / 'web/wp-config.php').stat().st_uid == __import__('pwd').getpwnam('web104').pw_uid
        assert (target_root / 'private').stat().st_mode & 0o777 == 0o700
        assert (target_root / 'private/config.txt').stat().st_mode & 0o777 == 0o600
        posts = FakeApi.posts
        migration.run(source_quiesced=True)
        assert FakeApi.posts == posts
        sql("INSERT INTO old_db.items VALUES(2,'new row');")
        (source_root / 'web/delete-on-sync.txt').unlink()
        (source_root / 'web/new.txt').write_text('new file')
        migration.run(sync=True, source_quiesced=True, target_quiesced=True)
        assert sql('SELECT COUNT(*) FROM `%s`.items' % db['name']) == '2'
        assert not (target_root / 'web/delete-on-sync.txt').exists()
        assert (target_root / 'web/new.txt').read_text() == 'new file'
        assert FakeApi.posts == posts
        # SQL shell escapes and global writes are rejected by the scoped importer.
        attack = Path(state) / 'unsafe.sql'
        attack.write_text('\\! touch /tmp/ispcp-sql-shell-executed\nCREATE DATABASE forbidden_global;\n')
        try:
            with attack.open('rb') as handle:
                migration.db_io({'action': 'import', **migration.credentials(db)}, input_file=handle)
        except m.MigrationError:
            pass
        else:
            raise AssertionError('unsafe SQL accepted')
        assert not Path('/tmp/ispcp-sql-shell-executed').exists()
        assert not sql("SHOW DATABASES LIKE 'forbidden_global'")
        if mode == 'via-web':
            assert credential_file.is_file(), 'externally supplied credentials must not be deleted'
            assert credential_file.stat().st_mode & 0o777 == 0o600
            assert 'source-test-password' not in (Path(state) / 'state.json').read_text()
        print('PASS (%s): inventory, plan, provisioning contract, real SSH/rsync/SQL, interrupted import resume, WordPress config, symlinks, ownership, backups, final sync and scoped SQL import' % mode)


if __name__ == '__main__':
    main()
