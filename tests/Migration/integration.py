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
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('migration', ROOT / 'site-migration/migrate.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_dns import FakeDns  # noqa: E402


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
            databases = sum(row['database_quota'] for key, row in self.rows.items() if key.startswith('/sites/databases/'))
            return {'client_id': 3, 'web_disk': {'limit_bytes': 5120 * 1048576, 'allocated_bytes': allocated * 1048576},
                    'web_traffic_this_month': {'limit_bytes': None, 'allocated_bytes': 0},
                    'database_size': {'limit_bytes': 1024 * 1048576, 'allocated_bytes': databases * 1048576},
                    'counts': {key: {'used': 0, 'limit': None} for key in m.COUNT_LIMITS}}
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
            assert payload['traffic_quota'] == -1, 'Traffic follows the unlimited client allowance'
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
            assert payload['database_quota'] == 1024, 'Database must use the client database quota, never unlimited'
            row['database_name_full'] = 'c3' + payload['database_name']
            username = 'c3' + self.rows['/sites/database-users/104']['database_user']
            sql("CREATE DATABASE `%s`; GRANT ALL ON `%s`.* TO '%s'@'localhost';" % (row['database_name_full'], row['database_name_full'], username))
        elif endpoint == '/sites/web-child-domains':
            assert payload['parent_domain_id'] == 104
        else:
            raise AssertionError(endpoint)
        self.rows[endpoint + '/104'] = row
        return row, None


def check_sites(config, mode):
    """--sites: source-sites.php over real SSH and MariaDB, then DNS through a local resolver.

    Direct mode keeps the minimal fixture schema (no owner, server IP or traffic tables);
    via-web adds them as in a full ISPConfig schema.
    """
    if mode == 'via-web':
        sql("""ALTER TABLE dbispconfig.web_domain ADD sys_groupid INT DEFAULT 8, ADD ip_address VARCHAR(39) DEFAULT '*';
            CREATE TABLE dbispconfig.sys_group(groupid INT, name VARCHAR(64), client_id INT);
            INSERT INTO dbispconfig.sys_group VALUES (8, 'client7', 7);
            CREATE TABLE dbispconfig.client(client_id INT, username VARCHAR(64), company_name VARCHAR(64), contact_name VARCHAR(64));
            INSERT INTO dbispconfig.client VALUES (7, 'c7', 'Firma \u017e', 'Jan');
            CREATE TABLE dbispconfig.server_ip(server_ip_id INT, server_id INT, ip_type VARCHAR(4), ip_address VARCHAR(39));
            INSERT INTO dbispconfig.server_ip VALUES (1, 1, 'IPv4', '127.0.0.1');
            CREATE TABLE dbispconfig.web_traffic(hostname VARCHAR(255), traffic_date DATE, traffic_bytes BIGINT UNSIGNED);
            INSERT INTO dbispconfig.web_traffic VALUES ('example.test', CURDATE(), 2048),
                ('example.test', DATE_SUB(CURDATE(), INTERVAL 40 DAY), 99999);""")
    inventory = m.source_sites(config)
    dns = FakeDns({'example.test': [('A', '127.0.0.1')], 'www.example.test': [('CNAME', 'example.test')],
                   'alias.test': [('A', '203.0.113.9')]})
    try:
        report = m.site_inventory(config, resolvers=[dns.address], inventory=inventory,
                                  extra_old=[] if mode == 'via-web' else ['127.0.0.1'])
    finally:
        dns.close()
    site, = report['websites']
    assert (site['domain'], site['status'], site['databases']) == ('example.test', 'old', 1), site
    assert site['hostnames'] == ['example.test', 'www.example.test', 'alias.test', 'www.alias.test'], site
    assert [entry['state'] for entry in site['dns']] == ['old', 'old', 'other', 'none'], site['dns']
    if mode == 'via-web':
        assert (site['client'], site['traffic_30d_bytes']) == ('c7 Firma \u017e', 2048), site
        assert report['old_addresses'] == {'127.0.0.1': 'localhost'}, report
    else:
        assert (site['client'], site['traffic_30d_bytes'], report['traffic']) == ('', None, False), site
    # The REST key is not configured in the fixture: listed as a warning, not a failure.
    assert any('--new-ip' in warning for warning in report['warnings']), report['warnings']


PLESK_HOME = Path('/var/www/vhosts/shop.test')
PLESK_SHADOW = '$AES-128-CBC$Zm9v+YmFy/w==$cXV4'


class PleskFakeApi(FakeApi):
    """The target contract of FakeApi plus subdomains with their own folder, cron jobs, PHP settings and the client's plan."""
    next_id = 105
    php_puts = []

    def get(self, path):
        if path == '/clients/3':
            return dict(super().get(path), limit_wildcard=True, limit_cron_type='full', limit_cron_frequency=5)
        row = super().get(path)
        if path.startswith('/sites/web-domains/'):
            # New websites start with OPcache off (the API's new-site defaults).
            return dict(row, php_settings={'values': {'opcache.enable': row.get('opcache', 'off')}, 'editable': ['opcache.enable']})
        return row

    def request(self, method, endpoint, payload):
        if method == 'PUT' and endpoint.startswith('/sites/web-domains/'):
            assert self.key == 'test-scoped-key' and list(payload) == ['php_settings'], payload
            PleskFakeApi.php_puts.append((endpoint, payload))
            self.rows[endpoint]['opcache'] = 'on' if payload['php_settings']['opcache.enable'] else 'off'
            return self.rows[endpoint], None
        if method == 'POST' and (endpoint == '/sites/cron-jobs' or endpoint == '/sites/web-domains' and payload.get('type') == 'vhostsubdomain'):
            assert self.key == 'test-scoped-key'
            self.posts += 1
            PleskFakeApi.next_id += 1
            row = dict(payload, id=PleskFakeApi.next_id, sys_groupid=3)
            if endpoint == '/sites/web-domains':
                row['document_root'] = self.rows['/sites/web-domains/104']['document_root']
                row['hd_quota'] = 0  # ISPConfig: children share the parent's quota
            self.rows['%s/%d' % (endpoint, row['id'])] = row
            return row, None
        if method == 'POST' and endpoint in ('/sites/database-users', '/sites/databases'):
            # Two databases: own IDs, and quotas that share the client's 1024 MB.
            assert self.key == 'test-scoped-key'
            self.posts += 1
            PleskFakeApi.next_id += 1
            row = dict(payload, id=PleskFakeApi.next_id, sys_groupid=3)
            if endpoint == '/sites/database-users':
                row['database_user_prefix'] = 'c3'
                sql("CREATE USER 'c3%s'@'localhost' IDENTIFIED BY '%s';" % (payload['database_user'], payload['database_password']))
            else:
                assert 0 < payload['database_quota'] < 1024, payload
                row['database_name_full'] = 'c3' + payload['database_name']
                user = 'c3' + self.rows['/sites/database-users/%d' % payload['database_user_id']]['database_user']
                sql("CREATE DATABASE `%s`; GRANT ALL ON `%s`.* TO '%s'@'localhost';" % (row['database_name_full'], row['database_name_full'], user))
            self.rows['%s/%d' % (endpoint, row['id'])] = row
            return row, None
        return super().request(method, endpoint, payload)


class PleskDnsApi(PleskFakeApi):
    """The client's hosting addresses and the DNS zone/record writes (with the client's key)."""

    def all(self, path, **query):
        if path == '/servers/1/php-versions':  # the Plesk website runs alt-php81-fpm
            return [{'id': 31, 'name': 'PHP 8.1', 'active': 'y', 'client_id': 0, 'php_fpm_ini_dir': '/etc/php/8.1/fpm',
                     'php_cli_binary': '/usr/bin/php8.1'}]
        return super().all(path, **query)

    def get(self, path):
        if path == '/me/hosting-addresses?client_id=3':
            return {'client_id': 3, 'web': [{'server_id': 1, 'server_name': 'web0.target.test', 'is_default': True,
                                             'ipv4': ['192.0.2.104'], 'ipv6': ['2001:db8::104']}], 'mail': [],
                    'dns': [{'server_id': 9, 'server_name': 'ns1.target.test', 'is_default': True,
                             'nameservers': [{'name': 'ns1.target.test', 'ipv4': [], 'ipv6': []},
                                             {'name': 'ns2.target.test', 'ipv4': [], 'ipv6': []}]}]}
        return super().get(path)

    def request(self, method, endpoint, payload):
        if endpoint.startswith('/dns/'):
            assert self.key == 'test-scoped-key', 'DNS zones belong to the client'
            if method == 'PUT':
                self.rows[endpoint].update(payload)
                return self.rows[endpoint], None
            self.posts += 1
            PleskFakeApi.next_id += 1
            row = dict(payload, id=PleskFakeApi.next_id, sys_groupid=3)
            self.rows['%s/%d' % (endpoint, row['id'])] = row
            return row, None
        return super().request(method, endpoint, payload)


def plesk_fixture():
    """A Plesk server in the container: `plesk db` over a psa schema, the subscription's system user and its crontab."""
    Path('/usr/local/psa').mkdir(parents=True)
    Path('/usr/local/psa/version').write_text('18.0.81 Ubuntu 24.04 1800261102.16\n')
    Path('/usr/local/bin/plesk').write_text('#!/bin/sh\n[ "$1" = db ] || { echo "fake plesk: $*" >&2; exit 1; }\nshift\nexec mysql psa "$@"\n')
    Path('/usr/local/bin/plesk').chmod(0o755)
    Path('/etc/psa').mkdir()
    Path('/etc/psa/.psa.shadow').write_text(PLESK_SHADOW + '\n')
    Path('/etc/psa/.psa.shadow').chmod(0o600)
    sql("""CREATE USER 'admin'@'localhost' IDENTIFIED BY '%s'; GRANT ALL ON *.* TO 'admin'@'localhost';
        CREATE DATABASE psa;
        CREATE TABLE psa.domains(id INT, name VARCHAR(255), htype VARCHAR(16), status INT, webspace_id INT, parentDomainId INT, cl_id INT,
            dns_zone_id INT);
        CREATE TABLE psa.hosting(dom_id INT, www_root VARCHAR(255), sys_user_id INT, php_handler_id VARCHAR(64));
        CREATE TABLE psa.sys_users(id INT, login VARCHAR(64), home VARCHAR(255), shell VARCHAR(255));
        CREATE TABLE psa.clients(id INT, login VARCHAR(64), cname VARCHAR(255), pname VARCHAR(255));
        CREATE TABLE psa.domain_aliases(id INT, dom_id INT, name VARCHAR(255), status INT, web ENUM('false','true'), dns ENUM('false','true'),
            seoRedirect ENUM('false','true'), dns_zone_id INT);
        CREATE TABLE psa.dns_zone(id INT, name VARCHAR(255), status INT, type ENUM('slave','master'), email VARCHAR(255), ttl INT,
            refresh INT, retry INT, expire INT, minimum INT);
        CREATE TABLE psa.dns_recs(id INT, dns_zone_id INT, type VARCHAR(16), host VARCHAR(255), val TEXT, opt VARCHAR(255), ttl INT);
        CREATE TABLE psa.data_bases(id INT, name VARCHAR(64), type VARCHAR(16), dom_id INT, db_server_id INT, default_user_id INT);
        CREATE TABLE psa.db_users(id INT, login VARCHAR(64), db_id INT, dom_id INT);
        CREATE TABLE psa.DatabaseServers(id INT, host VARCHAR(255), port INT, type VARCHAR(16));
        CREATE TABLE psa.IP_Addresses(id INT, ip_address VARCHAR(64));
        CREATE TABLE psa.DomainsTraffic(dom_id INT, date DATE, http_in BIGINT, http_out BIGINT);
        INSERT INTO psa.domains VALUES (1,'shop.test','vrt_hst',0,0,0,1,1), (2,'_.shop.test','vrt_hst',0,1,1,1,NULL),
            (3,'blog.shop.test','vrt_hst',0,1,1,1,NULL), (4,'addon.test','vrt_hst',0,1,0,1,3);
        INSERT INTO psa.hosting VALUES (1,'%s/httpdocs',1,'alt-php81-fpm'), (2,'%s/httpdocs',1,'alt-php81-fpm'),
            (3,'%s/httpdocs/blog',1,'alt-php81-fpm'), (4,'%s/addon.test',1,'alt-php81-fpm');
        INSERT INTO psa.sys_users VALUES (1,'shopuser','%s','/usr/local/psa/bin/chrootsh');
        INSERT INTO psa.clients VALUES (1,'shop','Shop s.r.o.','Jana');
        INSERT INTO psa.domain_aliases VALUES (1,1,'shop.example',0,'true','true','true',2);
        INSERT INTO psa.dns_zone VALUES (1,'shop.test',0,'master','admin@plesk.test',7200,14400,3600,604800,3600),
            (2,'shop.example',0,'master','admin@plesk.test',7200,14400,3600,604800,3600),
            (3,'addon.test',0,'master','admin@plesk.test',7200,14400,3600,604800,3600);
        INSERT INTO psa.dns_recs VALUES (1,1,'NS','shop.test.','ns.plesk.test.','',NULL), (2,1,'A','shop.test.','127.0.0.1','',60),
            (3,1,'CNAME','www.shop.test.','shop.test.','',NULL), (4,1,'MX','shop.test.','mail.provider.test.','10',NULL),
            (5,1,'TXT','shop.test.','v=spf1 +a +mx -all','',NULL), (6,1,'TXT','_dmarc.shop.test.','v=DMARC1; p=none','',NULL),
            (7,1,'A','ftp.shop.test.','198.51.100.7','',NULL), (8,1,'AXFR','','10.0.0.1','',NULL),
            (9,2,'NS','shop.example.','ns.plesk.test.','',NULL), (10,2,'A','shop.example.','127.0.0.1','',NULL),
            (11,3,'NS','addon.test.','ns.plesk.test.','',NULL);
        INSERT INTO psa.data_bases VALUES (11,'shop_wp','mysql',1,1,NULL), (12,'shop-old_db','mysql',1,1,22);
        INSERT INTO psa.db_users VALUES (21,'shop_wpuser',11,1), (22,'shop_old',12,1);
        INSERT INTO psa.DatabaseServers VALUES (1,'localhost',3306,'mysql');
        INSERT INTO psa.IP_Addresses VALUES (1,'127.0.0.1');
        INSERT INTO psa.DomainsTraffic VALUES (1,CURDATE(),100,2000);
        CREATE DATABASE shop_wp; CREATE TABLE shop_wp.items(id INT PRIMARY KEY, content LONGBLOB) ENGINE=InnoDB;
        INSERT INTO shop_wp.items VALUES (1, 0x00736563726574);
        CREATE DATABASE `shop-old_db`; CREATE TABLE `shop-old_db`.notes(id INT PRIMARY KEY, body TEXT);
        INSERT INTO `shop-old_db`.notes VALUES (1, 'old');""" % ((PLESK_SHADOW,) + (str(PLESK_HOME),) * 5))
    subprocess.run(['groupadd', 'psacln'], check=True)
    subprocess.run(['useradd', '-g', 'psacln', '-d', str(PLESK_HOME), '-M', 'shopuser'], check=True)
    httpdocs = PLESK_HOME / 'httpdocs'
    for path in (httpdocs / 'wp-content/uploads', httpdocs / 'blog', PLESK_HOME / 'private-data', PLESK_HOME / 'addon.test', PLESK_HOME / 'logs'):
        path.mkdir(parents=True, exist_ok=True)
    httpdocs.joinpath('index.php').write_text('<?php echo "shop";')
    httpdocs.joinpath('wp-config.php').write_text("<?php\nfile_put_contents('/tmp/ispcp-customer-code-executed','bad');\n"
                                                  "define('DB_NAME','shop_wp');\ndefine('DB_USER','shop_wpuser');\n"
                                                  "define('DB_PASSWORD','old secret');\ndefine('DB_HOST','localhost');\n")
    httpdocs.joinpath('.user.ini').write_text("auto_prepend_file = '%s/httpdocs/wordfence-waf.php'\n" % PLESK_HOME)
    httpdocs.joinpath('wordfence-waf.php').write_text("<?php define('WFWAF_LOG_PATH', '%s/httpdocs/wp-content/wflogs/');\n" % PLESK_HOME)
    httpdocs.joinpath('.htaccess').write_text('AuthUserFile %s/private-data/.htpasswd\n' % PLESK_HOME)  # not copied: review
    httpdocs.joinpath('wp-content/uploads/photo.txt').write_text('photo')
    httpdocs.joinpath('media').symlink_to(str(httpdocs / 'wp-content/uploads'))
    httpdocs.joinpath('blog/index.html').write_text('blog')
    httpdocs.joinpath('delete-on-sync.txt').write_text('delete later')
    (PLESK_HOME / 'private-data/secret.txt').write_text('not migrated')
    (PLESK_HOME / 'addon.test/index.html').write_text('another website')
    subprocess.run(['chown', '-R', 'shopuser:psacln', str(PLESK_HOME)], check=True)
    for path in (Path('/var/www'), Path('/var/www/vhosts')):
        path.chmod(0o755)
    PLESK_HOME.chmod(0o710)
    # WP Toolkit's WordPress cron stays behind; the feed import is migrated.
    crontab = ('MAILTO=""\nSHELL="/bin/sh"\n#@desc: Running wp-cron.php for WordPress at https://shop.test\n'
               "3,33\t*\t*\t*\t*\t/opt/alt/php81/usr/bin/php -f 'httpdocs/wp-cron.php'\n"
               "#@desc: Feed import\n7,37\t*\t*\t*\t*\t/opt/alt/php81/usr/bin/php -f 'httpdocs/feed.php'\n"
               '0 * * * * php %s/addon.test/cron.php\n' % PLESK_HOME)
    subprocess.run(['crontab', '-u', 'shopuser', '-'], input=crontab.encode(), check=True)
    # PHP settings: the website's php.ini leaves OPcache to alt-php81, which loads it; the blog switched it off in Plesk.
    for path, text in ((Path('/opt/alt/php81/link/conf/default.ini'), 'zend_extension=/opt/alt/php81/usr/lib64/php/modules/opcache.so\n'),
                       (Path('/var/www/vhosts/system/shop.test/etc/php.ini'), '[PHP]\nmemory_limit = 128M\n'),
                       (Path('/var/www/vhosts/system/blog.shop.test/etc/php.ini'), '[PHP]\nopcache.enable = off\n')):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def plesk_main():
    """Plesk source: inventory, --sites, plan, privilege-dropped reads, provisioning, publish and final sync."""
    os.umask(0o077)
    subprocess.run(['groupadd', 'client3'], check=True)
    subprocess.run(['useradd', '-g', 'client3', 'web104'], check=True)
    for path in [Path('/var/www/clients'), Path('/var/www/clients/client3')]:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o755)
    config_dir = Path('/usr/local/ispconfig/server/lib')
    config_dir.mkdir(parents=True)
    (config_dir / 'config.inc.php').write_text("<?php $conf=array('server_id'=>1,'db_host'=>'localhost','db_user'=>'root','db_password'=>'','db_database'=>'dbispconfig');")
    plesk_fixture()
    install_tool()
    m.HERE = Path('/usr/local/lib/ispconfig-rest-migration')
    config = m.select_source({
        'source': {'panel_ssh': 'root@unused.invalid', 'web_ssh': 'root@unused.invalid', 'db_ssh': {'1': 'root@unused.invalid'}},
        'sources': {'plesk': {'type': 'plesk', 'ssh': 'root@127.0.0.1'}},
        'target': {'api_url': 'https://panel.example/api/v1', 'api_key_file': '/unused', 'web_ssh': 'root@target-no-ssh.invalid',
                   'db_ssh': 'root@127.0.0.1', 'web_server_id': 1, 'db_server_id': 1, 'db_host': 'db.example',
                   'db_remote_ips': '10.20.30.21,10.20.30.20'},
    }, 'plesk')
    dns = FakeDns({'shop.test': [('A', '127.0.0.1')], 'www.shop.test': [('CNAME', 'shop.test')], 'addon.test': [('A', '203.0.113.9')]})
    try:
        report = m.site_inventory(config, resolvers=[dns.address])
    finally:
        dns.close()
    sites = {site['domain']: site for site in report['websites']}
    assert (sites['shop.test']['status'], sites['shop.test']['databases'], sites['shop.test']['traffic_30d_bytes']) == ('old', 2, 2100), sites
    assert sites['shop.test']['hostnames'][:4] == ['shop.test', 'www.shop.test', 'shop.example', 'www.shop.example'], sites['shop.test']
    assert (sites['addon.test']['status'], sites['addon.test']['parent']) == ('other', 'shop.test'), sites['addon.test']
    assert report['old_addresses'] == {'127.0.0.1': '127.0.0.1'}, report['old_addresses']
    m.Api = PleskDnsApi
    temporary = set(os.listdir('/tmp'))
    # Public DNS: shop.test is served by the Plesk name server, its alias by another provider.
    public = FakeDns({'shop.test': [('NS', 'ns.plesk.test')], 'shop.example': [('NS', 'ns1.registrar.test')]})
    with tempfile.TemporaryDirectory(prefix='migration-test-') as state:
        migration = m.Migration(config, state, 'shop.test', 3)
        migration.resolvers = [public.address]
        migration.plan()
        assert FakeApi.posts == 0
        inventory = migration.state['inventory']
        assert inventory['site']['subdomain'] == '*' and inventory['site']['system_user'] == 'shopuser'
        assert [(child['domain'], child['type']) for child in inventory['children']] == [('blog.shop.test', 'vhostsubdomain'), ('shop.example', 'alias')]
        assert inventory['not_copied'] == ['private-data'], inventory['not_copied']
        assert inventory['dns_zones'][-1] == {'id': 2, 'domain': 'shop.example', 'role': 'alias', 'sync': True, 'child': 'a1'}, inventory['dns_zones']
        assert inventory['opcache'] == {'shop.test': 'on', 'blog.shop.test': 'off'}, inventory['opcache']
        assert [job['source'] for job in migration.state['cron_jobs']] == ["/opt/alt/php81/usr/bin/php -f 'httpdocs/feed.php'"]
        assert any(note.startswith('WordPress cron (WP Toolkit, 1 job(s)') for note in inventory['notes']), inventory['notes']
        sizes = migration.state['source_size']
        assert sizes['web_bytes'] > 0 and sizes['databases']['shop_wp'] > 0 and 'shop-old_db' in sizes['databases'], sizes
        # Files are read as the subscription's user: something only root can read stops the copy.
        unreadable = PLESK_HOME / 'httpdocs/root-only.txt'
        unreadable.write_text('root only')
        unreadable.chmod(0o600)
        try:
            migration.run(source_quiesced=True)
        except m.MigrationError as exc:
            assert 'rsync' in str(exc), str(exc)
        else:
            raise AssertionError('root-only source file copied')
        unreadable.unlink()
        Path('/var/www/clients/client3/web104').chmod(0o755)
        migration = m.Migration(config, state, 'shop.test', 3)
        migration.resolvers = [public.address]
        try:
            migration.run(source_quiesced=True)
        except m.MigrationError as exc:
            assert 'Edit configs in the staged tree' in str(exc), str(exc)
        else:
            raise AssertionError('old webspace path in .htaccess published without review')
        tree = Path(state) / 'round-000/tree'
        report = m.read_json(tree.parent / 'configuration-report.json')
        assert report['old_path_references'] == ['web/.htaccess'] and report['wordpress_updated'] == ['web/wp-config.php'], report
        assert report['old_paths_rewritten'] == ['web/.user.ini', 'web/wordfence-waf.php'], report
        target_root = Path('/var/www/clients/client3/web104')
        assert (tree / 'web/.user.ini').read_text() == "auto_prepend_file = '%s/web/wordfence-waf.php'\n" % target_root
        (tree / 'web/.htaccess').write_text('AuthUserFile %s/private/.htpasswd\n' % target_root)
        assert not any(key.startswith('/dns/') for key in PleskFakeApi.rows), 'DNS zones only once the copy is complete'
        migration.publish(config_reviewed=True)
        assert migration.state['phase'] == 'copied'
        zones = {row['origin']: row for key, row in PleskFakeApi.rows.items() if key.startswith('/dns/soa/')}
        assert list(zones) == ['shop.test.'] and zones['shop.test.']['active'] is True, zones
        assert (zones['shop.test.']['ns'], zones['shop.test.']['server_id']) == ('ns1.target.test.', 9), zones
        records = sorted((row['name'], row['type'], m.record_value(row), row['ttl']) for key, row in PleskFakeApi.rows.items()
                         if key.startswith('/dns/records/'))
        assert records == [('ftp.shop.test.', 'A', '198.51.100.7', 7200), ('shop.test.', 'A', '192.0.2.104', 60),
                           ('shop.test.', 'MX', '10 mail.provider.test.', 7200), ('shop.test.', 'NS', 'ns1.target.test.', 7200),
                           ('shop.test.', 'NS', 'ns2.target.test.', 7200), ('shop.test.', 'SPF', 'v=spf1 mx a -all', 7200),
                           ('www.shop.test.', 'CNAME', 'shop.test.', 7200)], records
        dns = migration.state['dns']
        assert dns['done'] and dns['zones'][0]['manual'] == [
            '_dmarc.shop.test TXT v=DMARC1; p=none (ISPConfig accepts DMARC only in a zone with a DKIM record)'], dns
        assert dns['skipped'] == ['shop.example: public DNS does not use the Plesk name servers (ns1.registrar.test)'], dns['skipped']
        assert PleskFakeApi.rows['/system/api-keys/501']['active'] is False, 'the client key is switched off after the DNS zones'
        assert (target_root / 'web/index.php').read_text() == '<?php echo "shop";'
        assert (target_root / 'web/.user.ini').read_text() == "auto_prepend_file = '%s/web/wordfence-waf.php'\n" % target_root
        assert (target_root / 'web/blog/index.html').read_text() == 'blog'
        assert os.readlink(target_root / 'web/media') == 'wp-content/uploads' and (target_root / 'web/media/photo.txt').read_text() == 'photo'
        assert not list(target_root.rglob('secret.txt')) and not (target_root / 'web/addon.test').exists()
        assert (target_root / 'web/index.php').stat().st_uid == __import__('pwd').getpwnam('web104').pw_uid
        assert not Path('/tmp/ispcp-customer-code-executed').exists()
        for key, query in (('shop_wp', 'SELECT HEX(content) FROM `%s`.items'), ('shop-old_db', 'SELECT body FROM `%s`.notes')):
            assert sql(query % migration.state['databases'][key]['name']) == sql(query % key), key
        wp = migration.state['databases']['shop_wp']
        target_wp = (target_root / 'web/wp-config.php').read_text()
        assert wp['name'] in target_wp and wp['password'] in target_wp and "'db.example'" in target_wp
        rows = PleskFakeApi.rows
        site = rows['/sites/web-domains/104']
        assert (site['subdomain'], site['domain']) == ('*', 'shop.test'), site
        alias = rows['/sites/web-child-domains/104']
        assert (alias['domain'], alias['redirect_type'], alias['redirect_path']) == ('shop.example', 'R=301,L', '[scheme]://shop.test/'), alias
        blog = [row for key, row in rows.items() if key.startswith('/sites/web-domains/') and row.get('type') == 'vhostsubdomain']
        assert [(row['domain'], row['web_folder']) for row in blog] == [('blog.shop.test', 'web/blog')], blog
        cron = [row for key, row in rows.items() if key.startswith('/sites/cron-jobs/')]
        assert [(row['command'], row['active'], row['run_min']) for row in cron] == [
            ('/usr/bin/php8.1 -f %s/web/feed.php' % target_root, False, '7,37')], cron
        assert (site['server_php_id'], blog[0]['server_php_id']) == (31, 31), 'PHP 8.1 as on Plesk'
        # OPcache as in Plesk: switched on where the new-site defaults turned it off; the blog keeps it off.
        assert PleskFakeApi.php_puts == [('/sites/web-domains/104', {'php_settings': {'opcache.enable': True}})], PleskFakeApi.php_puts
        assert migration.state['opcache'] == {'104': 'on', str(blog[0]['id']): 'off'}, migration.state['opcache']
        # Final sync: new source rows and files, deleted files; the reviewed path is checked again.
        sql("INSERT INTO shop_wp.items VALUES (2, 'new');")
        (PLESK_HOME / 'httpdocs/delete-on-sync.txt').unlink()
        (PLESK_HOME / 'httpdocs/new.txt').write_text('new file')
        subprocess.run(['chown', 'shopuser:psacln', str(PLESK_HOME / 'httpdocs/new.txt')], check=True)
        crontab = subprocess.run(['crontab', '-l', '-u', 'shopuser'], check=True, capture_output=True).stdout
        subprocess.run(['crontab', '-u', 'shopuser', '-'], input=crontab + b'5 5 * * * /opt/alt/php81/usr/bin/php -f httpdocs/new.php\n', check=True)
        posts = FakeApi.posts
        try:
            migration.run(sync=True, source_quiesced=True, target_quiesced=True)
        except m.MigrationError as exc:
            assert 'Edit configs in the staged tree' in str(exc), str(exc)
        assert (Path(state) / 'round-001/tree/web/wordfence-waf.php').read_text() == (
            "<?php define('WFWAF_LOG_PATH', '%s/web/wp-content/wflogs/');\n" % target_root)
        (Path(state) / 'round-001/tree/web/.htaccess').write_text('AuthUserFile %s/private/.htpasswd\n' % target_root)
        migration.publish(config_reviewed=True)
        assert sql('SELECT COUNT(*) FROM `%s`.items' % wp['name']) == '2'
        assert not (target_root / 'web/delete-on-sync.txt').exists() and (target_root / 'web/new.txt').read_text() == 'new file'
        assert FakeApi.posts == posts, 'sync must not create objects again'
        assert len(PleskFakeApi.php_puts) == 1, 'a change made in the panel between rounds stays'
        assert [job['source'] for job in migration.state['cron_jobs']] == ["/opt/alt/php81/usr/bin/php -f 'httpdocs/feed.php'"]
        assert 'old secret' not in (Path(state) / 'state.json').read_text()
    public.close()
    # Nothing was written on the Plesk side: no option files, sources unchanged.
    assert not set(os.listdir('/tmp')) - temporary, set(os.listdir('/tmp')) - temporary
    assert (PLESK_HOME / 'httpdocs/.user.ini').read_text().startswith("auto_prepend_file = '%s/httpdocs" % PLESK_HOME)
    print('PASS (plesk): --sites, inventory, plan, reads as the subscription user, dumps as the Plesk admin, wildcard, alias redirect, '
          'subdomain folder, inactive cron, old paths rewritten and reviewed, WordPress config, symlinks, DNS zones, final sync')


def main():
    assert Path('/.dockerenv').exists(), 'Never run fixture setup on a real host'
    if os.environ.get('ISPCP_TEST_SOURCE_MODE') == 'plesk':
        return plesk_main()
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
    check_sites(config, mode)
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
        # Read-only source measurement over real SSH (du) and MySQL (information_schema).
        sizes = migration.state['source_size']
        assert sizes['web_bytes'] > 0 and sizes['databases']['old_db'] > 0, sizes
        assert migration.state['quotas'] == {'disk_mb': 5120, 'traffic_mb': -1, 'databases_mb': {'old_db': 1024}}
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
