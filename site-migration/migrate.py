#!/usr/bin/env python3
"""Copy one old ISPConfig vhost into a client already provisioned by WHMCS.

No third-party Python modules. See README.md before using production credentials.
"""
import argparse
import base64
import concurrent.futures
import contextlib
import fcntl
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
INSTALLED_CODE = Path('/usr/local/lib/ispconfig-rest-migration')
DEFAULT_CONFIG = '/etc/ispconfig-rest-migration/config.json'
DEFAULT_STATE = Path('/var/lib/ispconfig-rest-migration')
SSH = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
       '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
       '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
       '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3']
RSYNC_BASE = ['rsync', '-rlpt', '--links', '--no-devices', '--no-specials', '--checksum', '--protect-args']
RSYNC = RSYNC_BASE + ['-e', shlex.join(SSH)]


class MigrationError(Exception):
    pass


class ApiError(MigrationError):
    def __init__(self, message, status):
        super().__init__(message)
        self.status = status


def problem_summary(body):
    """Expose known problem identifiers/numeric limits, never reflected secrets."""
    try:
        problem = json.loads(body)
    except (ValueError, UnicodeError):
        return ''
    if not isinstance(problem, dict):
        return ''
    prefix = 'https://github.com/FELDSAM-INC/ispconfig-rest/blob/main/docs/problems.md#'
    kind = problem.get('type', '')
    known = ('account-locked', 'limit-reached', 'quota-exceeded', 'feature-not-allowed',
             'server-not-assigned', 'validation-failed', 'resource-in-use')
    if kind not in [prefix + name for name in known]:
        return ''
    result = kind[len(prefix):]
    limit = problem.get('limit')
    names = ('limit_web_quota', 'limit_traffic_quota', 'limit_web_domain', 'limit_web_aliasdomain',
             'limit_web_subdomain', 'limit_database', 'limit_database_user', 'limit_database_quota')
    if isinstance(limit, dict) and limit.get('name') in names:
        result += ': ' + limit['name']
        if limit.get('scope') in ('client', 'reseller'):
            result += ' (' + limit['scope'] + ')'
        for name in ('max', 'used', 'requested'):
            value = limit.get(name)
            if type(value) is int:
                result += '; %s=%d' % (name, value)
            elif name == 'requested' and name in limit and value is None:
                result += '; requested=unlimited'
    return result


def require(condition, message):
    if not condition:
        raise MigrationError(message)


def domain_name(value):
    value = value.encode('idna').decode('ascii').lower()
    require(re.fullmatch(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value)
            and '.' in value and '..' not in value, 'Invalid domain')
    return value


def read_json(path):
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)


def atomic_json(path, value):
    path = Path(path)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False, encoding='utf-8') as handle:
        temporary = handle.name
        os.fchmod(handle.fileno(), 0o600)
        json.dump(value, handle, indent=2, ensure_ascii=True)
        handle.write('\n')
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# Website trees; ISPConfig's /var/www/DOMAIN symlinks resolve into /var/www/clients.
WEB_ROOTS = (Path('/var/www/clients'), Path('/var/www/html'), Path('/srv/www'))


def private_directory(path):
    path = Path(path).absolute()
    require(not path.is_symlink(), 'State directory cannot be a symlink')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'State directory must belong to this user and have mode 0700')
    resolved = path.resolve()
    # A dedicated root-only directory on the /var/www file system is fine; website roots are not.
    require(resolved != Path('/var/www') and not any(resolved == root or root in resolved.parents for root in WEB_ROOTS),
            'Keep migration state and database credentials outside website roots (e.g. /var/www/ispcp-migration)')
    parent = resolved.parent.stat()
    require(parent.st_uid in (0, os.getuid()) and (not parent.st_mode & 0o022 or parent.st_mode & stat.S_ISVTX),
            'The parent of the state directory must not be writable by other users')
    return resolved


def state_root(config):
    """Directory holding one private state directory per domain (config "state_dir")."""
    value = config.get('state_dir', str(DEFAULT_STATE))
    require(isinstance(value, str) and value.startswith('/') and not any(c in value for c in '\x00\r\n'),
            'state_dir must be an absolute path')
    return Path(value)


def directory_bytes(path):
    total = 0
    for directory, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            with contextlib.suppress(OSError):
                total += os.lstat(os.path.join(directory, name)).st_blocks * 512
    return total


def ssh_host(host):
    require(isinstance(host, str) and re.fullmatch(r'(?:root@)?[a-zA-Z0-9][a-zA-Z0-9._-]*', host),
            'Use a root SSH hostname or a simple SSH alias (ports/keys belong in ~/.ssh/config)')
    return host


def remote(host, argv):
    return SSH + [ssh_host(host), shlex.join([str(arg) for arg in argv])]


def php_remote(host, helper):
    code = (HERE / helper).read_bytes()
    # Helper is trusted repository code, never customer PHP. Payload is sent on stdin.
    expression = 'eval(base64_decode("' + base64.b64encode(code.removeprefix(b'<?php')).decode() + '"));'
    return remote(host, ['php', '-d', 'display_errors=stderr', '-r', expression])


def execute(argv, *, data=None, output=None, error_path=None):
    with contextlib.ExitStack() as stack:
        stderr = stack.enter_context(open(error_path, 'ab')) if error_path else subprocess.PIPE
        result = subprocess.run(argv, input=data, stdout=output or subprocess.PIPE, stderr=stderr)
    if result.returncode:
        # SQL stderr can include customer data. It stays in the private job directory.
        detail = ' See ' + str(error_path) if error_path else ''
        raise MigrationError('Command failed (exit %d): %s.%s' % (result.returncode, Path(argv[0]).name, detail))
    return result.stdout


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not forward an administrative API credential to a redirect destination.
        return None


class Api:
    def __init__(self, url, key_file=None, *, key=None):
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == 'https' and parsed.hostname and not parsed.username
                and not parsed.query and not parsed.fragment and parsed.path.rstrip('/') == '/api/v1',
                'api_url must be https://panel:8090/api/v1 (TLS verification stays enabled)')
        self.url = url.rstrip('/')
        if key is None:
            path = Path(key_file)
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077,
                    'API key file must be a regular private file (0600)')
            key = path.read_text().strip()
        self.key = key
        require(self.key and '\n' not in self.key and '\r' not in self.key, 'Invalid API key file')
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(self.url + path, data=data, method=method,
                                         headers={'X-API-Key': self.key, 'Accept': 'application/json',
                                                  'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=90) as response:
                body = response.read()
                return json.loads(body) if body else {}, response.headers.get('X-Change-Set-Id')
        except urllib.error.HTTPError as exc:
            # Raw response bodies/details may contain reflected credentials.
            # Only known problem names and numeric limit metadata reach the terminal.
            try:
                summary = problem_summary(exc.read(16384))
            except (OSError, ValueError):
                summary = ''
            message = 'REST %s %s returned HTTP %s' % (method, path, exc.code)
            raise ApiError(message + (': ' + summary if summary else '; inspect API logs.'), exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise MigrationError('REST request failed: %s %s; a POST may already have committed.' % (method, path)) from None

    def get(self, path):
        return self.request('GET', path)[0]

    def all(self, path, **query):
        rows = []
        while True:
            page = self.get(path + '?' + urllib.parse.urlencode(dict(query, limit=100, offset=len(rows))))
            rows.extend(page['data'])
            if len(rows) >= page['meta']['total']:
                return rows
            require(page['data'], 'API pagination stopped unexpectedly')

    def wait(self, change, timeout=600):
        if not change:
            return
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.get('/changes/' + change)['status']
            if status == 'applied':
                return
            require(status not in ('failed', 'stalled'), 'ISPConfig provisioning is ' + status + ': ' + change)
            time.sleep(5)
        raise MigrationError('ISPConfig provisioning timed out; rerun to continue: ' + change)


def validate_inventory(inventory, domain):
    site = inventory['site']
    require(site['domain'] == domain and site['type'] == 'vhost', 'Source domain does not match')
    require(site['active'] == 'y', 'Source website is inactive; do not activate it implicitly')
    require(re.fullmatch(r'/var/www/clients/client[0-9]+/web[0-9]+', site['document_root']),
            'Only canonical /var/www/clients/clientN/webN source roots are supported')
    names = set()
    for db in inventory['databases']:
        require(db['type'] == 'mysql' and re.fullmatch(r'[a-zA-Z0-9_]{1,64}', db['database_name']),
                'Unsupported source database type/name')
        require(db['database_name'] not in names, 'Duplicate source database names are ambiguous')
        require(db['database_user'], 'Source database has no assigned read/write user')
        require(db['active'] == 'y', 'Source database is inactive; review it before migrating')
        names.add(db['database_name'])
    # Vhost children have separate roots/configuration and must be migrated deliberately.
    require(all(child['type'] in ('alias', 'subdomain') for child in inventory['children']),
            'Source has child vhosts with their own settings. Migrate these separately; see inventory.json.')


MB = 1024 * 1024


def remaining_mb(summary, client_id, metric_name, label):
    """Unallocated MB of one client quota (-1 = unlimited).

    Uses the API's allocated quotas, the same sums the API enforces on create,
    not measured usage.
    """
    require(isinstance(summary, dict) and summary.get('client_id') == client_id,
            'Quota summary belongs to a different ISPConfig client')
    metric = summary.get(metric_name)
    require(isinstance(metric, dict) and 'limit_bytes' in metric, 'API did not return the %s limit' % label)
    limit = metric['limit_bytes']
    if limit is None:
        return -1
    allocated = metric.get('allocated_bytes')
    require(type(limit) is int and limit >= 0 and type(allocated) is int and allocated >= 0,
            'API did not return a valid %s allocation' % label)
    return max((limit - allocated) // MB, 0)


def available_disk_mb(summary, client_id):
    remaining = remaining_mb(summary, client_id, 'web_disk', 'website disk quota')
    require(remaining != 0, 'No unallocated website disk quota remains for this client; review its product and existing websites')
    return remaining


def available_traffic_mb(summary, client_id):
    remaining = remaining_mb(summary, client_id, 'web_traffic_this_month', 'website traffic quota')
    require(remaining != 0, 'No unallocated website traffic quota remains for this client; review its product and existing websites')
    return remaining


def database_quotas(summary, client_id, sizes):
    """Split the client's unallocated database quota across databases still to create.

    sizes maps database name -> measured source bytes. Shares are proportional
    to the source sizes, so every database receives at least its current size.
    """
    if not sizes:
        return {}
    remaining = remaining_mb(summary, client_id, 'database_size', 'database quota')
    if remaining == -1:
        return {name: -1 for name in sizes}
    needs = {name: max(-(-size // MB), 1) for name, size in sizes.items()}
    total = sum(needs.values())
    require(remaining >= total,
            'Database quota is too small: %d MB unallocated, the source database(s) need %d MB (%s). '
            'Raise the client database quota, then repeat the command.'
            % (remaining, total, ', '.join('%s %d MB' % item for item in sorted(needs.items()))))
    return {name: remaining * need // total for name, need in needs.items()}


def php_configuration(rows, version, client_id):
    """ID of the active PHP-FPM configuration of VERSION (e.g. 5.6) on the destination web server."""
    require(isinstance(version, str) and re.fullmatch(r'[0-9]+\.[0-9]+', version), '--php takes a version such as 5.6 or 8.3')
    pattern = re.compile(r'(?<![0-9.])' + re.escape(version) + r'(?![0-9])')
    usable = [row for row in rows if row.get('active') in (True, 'y') and row.get('php_fpm_ini_dir')
              and int(row.get('client_id') or 0) in (0, client_id)]
    found = [row for row in usable
             if any(pattern.search(str(row.get(field) or '')) for field in ('name', 'php_fpm_ini_dir', 'php_cli_binary'))]
    names = sorted({str(row.get('name')) for row in usable})
    require(found, 'PHP %s is not an active PHP-FPM version of the destination web server for this client (available: %s)'
            % (version, ', '.join(names) or 'none'))
    require(len(found) == 1, 'PHP %s matches several PHP configurations (IDs %s); remove the duplicate in ISPConfig'
            % (version, ', '.join(str(row['id']) for row in found)))
    return int(found[0]['id'])


# Usage-summary count -> what the migration creates there.
COUNT_LIMITS = {
    'web_domains': 'websites', 'web_alias_domains': 'alias domains', 'web_subdomains': 'subdomains',
    'database_users': 'database users', 'databases': 'databases',
}


def check_counts(summary, needed):
    """Refuse before the first write when a client count limit cannot fit the migration."""
    counts = summary.get('counts')
    require(isinstance(counts, dict), 'API did not return the client usage counts')
    for key, need in needed.items():
        if not need:
            continue
        row = counts.get(key)
        require(isinstance(row, dict) and type(row.get('used')) is int, 'API did not return the %s usage count' % key)
        limit = row.get('limit')
        require(limit is None or type(limit) is int, 'API returned an invalid %s limit' % key)
        require(limit is None or row['used'] + need <= limit,
                'Client limit for %s is too small: limit %d, used %d, migration needs %d more. '
                'Raise the limit, then repeat the command.' % (COUNT_LIMITS[key], limit or 0, row['used'], need))


def normalize_links(tree, old_root):
    """Make absolute in-site links relative; reject links outside web/private."""
    tree = Path(tree).resolve()
    for directory, dirs, files in os.walk(tree, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            mode = path.lstat().st_mode
            require(stat.S_ISDIR(mode) or stat.S_ISREG(mode) or stat.S_ISLNK(mode),
                    'Special source file is not supported: ' + str(path.relative_to(tree)))
            if not path.is_symlink():
                continue
            link = os.readlink(path)
            if os.path.isabs(link):
                require(link.startswith(old_root + '/'), 'External absolute symlink: ' + str(path.relative_to(tree)))
                target = tree / link[len(old_root) + 1:]
                link = os.path.relpath(target, path.parent)
                path.unlink()
                path.symlink_to(link)
    for directory, dirs, files in os.walk(tree, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            if path.is_symlink():
                try:
                    resolved = path.resolve(strict=True)
                except (OSError, RuntimeError):
                    raise MigrationError('Broken/cyclic symlink: ' + str(path.relative_to(tree))) from None
                require(any(resolved == tree / folder or tree / folder in resolved.parents for folder in ('web', 'private')),
                        'Symlink leaves the migrated web/private folders: ' + str(path.relative_to(tree)))


class Migration:
    def __init__(self, config, state_dir, domain, client_id):
        self.config = config
        self.source = config['source']
        self.target = config['target']
        # server-tools installs this CLI on the destination web server. Keep
        # existing config/state unchanged while removing the self-SSH dependency.
        transport = self.target.get('web_transport', 'local' if HERE == INSTALLED_CODE else 'ssh')
        require(transport in ('local', 'ssh'), 'target.web_transport must be local or ssh')
        self.local_web = transport == 'local'
        self.php_version = None  # --php VERSION of this migration
        self.directory = private_directory(state_dir)
        self.file = self.directory / 'state.json'
        self.domain = domain_name(domain)
        self.client_id = int(client_id)
        require(self.client_id > 0, 'client-id is the new ISPConfig client ID, not the WHMCS customer ID')
        via_web = self.source.get('db_via_web')
        require(('db_via_web' in self.source) != ('db_ssh' in self.source),
                'Configure exactly one of source.db_via_web or source.db_ssh')
        if 'db_via_web' in self.source:
            require(isinstance(via_web, dict), 'source.db_via_web must be an object')
            require(isinstance(via_web.get('host'), str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]*', via_web['host']),
                    'source.db_via_web.host must be a MySQL hostname or IPv4 address')
            require(isinstance(via_web.get('port', 3306), int) and 1 <= via_web.get('port', 3306) <= 65535,
                    'Invalid source MySQL port')
            require(set(via_web) <= {'host', 'port', 'defaults_file'}, 'Unknown source.db_via_web option')
            if 'defaults_file' in via_web:
                value = via_web['defaults_file']
                require(isinstance(value, str) and value.startswith('/') and not any(c in value for c in '\x00\r\n'),
                        'source.db_via_web.defaults_file must be an absolute path on the old web server')
        for host in [self.source['panel_ssh'], self.source['web_ssh'], self.target['web_ssh'], self.target['db_ssh']] + list(self.source.get('db_ssh', {}).values()):
            ssh_host(host)
        for field in ('web_server_id', 'db_server_id'):
            require(isinstance(self.target[field], int) and self.target[field] > 0, 'Invalid target ' + field)
        require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]*(?::[0-9]{1,5})?', self.target['db_host']), 'Invalid target db_host')
        # state_dir only locates the state; moving it must not invalidate the migration.
        settings = {key: value for key, value in config.items() if key != 'state_dir'}
        fingerprint = hashlib.sha256(json.dumps([settings, self.domain, self.client_id], sort_keys=True).encode()).hexdigest()
        self.state = read_json(self.file) if self.file.exists() else {
            'version': 1, 'fingerprint': fingerprint, 'domain': self.domain,
            'client_id': self.client_id, 'objects': {}, 'round': 0, 'phase': 'planned',
            'nonce': secrets.token_hex(4), 'databases': {},
        }
        require(self.state['fingerprint'] == fingerprint, 'Configuration/domain/client changed; use the original configuration and state')
        self.api = Api(self.target['api_url'], self.target['api_key_file'])
        self.admin = self.api

    def save(self):
        atomic_json(self.file, self.state)

    def web_command(self, argv):
        return argv if self.local_web else remote(self.target['web_ssh'], argv)

    def check_web_server(self):
        argv = ['php', '-d', 'display_errors=stderr', str(HERE / 'server-check.php')] if self.local_web else \
            php_remote(self.target['web_ssh'], 'server-check.php')
        execute(argv, data=(json.dumps({'server_id': self.target['web_server_id']}) + '\n').encode(),
                error_path=self.directory / 'server-check.log')

    def select_php(self):
        """PHP of the new website: --php VERSION, the version chosen by an earlier run, or target.server_php_id."""
        site = self.state['objects'].get('site', {}).get('record')
        if self.php_version:
            rows = self.admin.all('/servers/%d/php-versions' % self.target['web_server_id'])
            chosen = {'version': self.php_version, 'server_php_id': php_configuration(rows, self.php_version, self.client_id)}
            if site is not None:
                require(int(site.get('server_php_id') or 0) == chosen['server_php_id'],
                        'The website was already created with PHP configuration ID %s; change its PHP version in '
                        'ISPConfig or WHMCS, then repeat the command without --php.' % site.get('server_php_id'))
            self.state['php'] = chosen
        if site is not None:
            return {'version': self.state.get('php', {}).get('version'), 'server_php_id': int(site.get('server_php_id') or 0)}
        return self.state.get('php', {'version': None, 'server_php_id': self.target.get('server_php_id', 0)})

    def usage_summary(self):
        return self.admin.get('/usage/summary?client_id=' + str(self.client_id))

    def needed_counts(self):
        """Objects this migration still has to create, per client count limit."""
        objects = self.state['objects']
        inventory = self.state['inventory']
        children = [child for child in inventory['children'] if 'child:' + str(child['domain_id']) not in objects]
        databases = [db['database_name'] for db in inventory['databases']]
        return {
            'web_domains': 0 if 'site' in objects else 1,
            'web_alias_domains': sum(child['type'] == 'alias' for child in children),
            'web_subdomains': sum(child['type'] == 'subdomain' for child in children),
            'database_users': sum('user:' + name not in objects for name in databases),
            'databases': sum('db:' + name not in objects for name in databases),
        }

    def allocation(self, summary):
        """Quotas of the migrated objects, checked against the measured source sizes.

        Objects already created keep their quota on resume/sync, even when
        their allocation now consumes the account's whole limit. New objects
        receive the client's unallocated quota (product limits, not static
        configuration). The API still enforces client/reseller caps on create.
        """
        objects = self.state['objects']
        sizes = self.state['source_size']

        def unlimited(value):
            value = int(value)
            return value if value > 0 else -1

        site = objects.get('site', {}).get('record')
        if site is not None:
            disk, traffic = unlimited(site['hd_quota']), unlimited(site.get('traffic_quota', -1))
        else:
            disk, traffic = available_disk_mb(summary, self.client_id), available_traffic_mb(summary, self.client_id)
        databases, new = {}, {}
        for db in self.state['inventory']['databases']:
            name = db['database_name']
            record = objects.get('db:' + name, {}).get('record')
            if record is not None:
                databases[name] = unlimited(record.get('database_quota', -1))
            else:
                new[name] = sizes['databases'][name]
        databases.update(database_quotas(summary, self.client_id, new))
        require(disk == -1 or sizes['web_bytes'] <= disk * MB,
                'Source files (%d MB) exceed the website disk quota (%d MB). Raise the client disk quota, then repeat the command; stopped before copying.'
                % (-(-sizes['web_bytes'] // MB), disk))
        for name, quota in databases.items():
            require(quota == -1 or sizes['databases'][name] <= quota * MB,
                    'Source database %s (%d MB) exceeds its database quota (%d MB). Raise the quota, then repeat the command; stopped before copying.'
                    % (name, -(-sizes['databases'][name] // MB), quota))
        return {'disk_mb': disk, 'traffic_mb': traffic, 'databases_mb': databases}

    def preflight(self):
        """Validate every count limit and quota before the first write, so a
        product limit never stops the migration between created objects."""
        summary = self.usage_summary()
        check_counts(summary, self.needed_counts())
        self.state['quotas'] = self.allocation(summary)
        self.state['website_disk_quota_mb'] = self.state['quotas']['disk_mb']
        self.save()

    def check_free_space(self):
        """The private staging copy, target backup and SQL snapshots of a round live in the state directory."""
        sizes = self.state['source_size']
        copied = self.state['phase'] == 'copied'  # a final sync starts the next round and backs up the target
        round_dir = self.directory / ('round-%03d' % (self.state['round'] + (1 if copied else 0)))
        needed = sizes['web_bytes'] * (2 if copied else 1) + 2 * sum(sizes['databases'].values()) + 256 * MB
        if round_dir.exists():
            needed = max(needed - directory_bytes(round_dir), 0)  # partly staged by an interrupted run
        free = shutil.disk_usage(self.directory).free
        require(free >= needed,
                'Not enough free space for the private staging copy: about %d MB needed, %d MB free in %s. '
                'Set "state_dir" in the configuration to a larger file system (see README); nothing was written.'
                % (-(-needed // MB), free // MB, self.directory))
        return needed, free

    def refresh_allocation(self):
        self.state['quotas'] = self.allocation(self.usage_summary())
        self.state['website_disk_quota_mb'] = self.state['quotas']['disk_mb']
        self.save()
        return self.state['quotas']

    def measure_source(self, inventory):
        """Read-only size check, so quota problems stop before any write."""
        root = inventory['site']['document_root']
        output = execute(remote(self.source['web_ssh'], ['du', '-sk', '--', root + '/web', root + '/private']),
                         error_path=self.directory / 'source-size.log').decode()
        lines = output.splitlines()
        require(len(lines) == 2 and all(re.fullmatch(r'[0-9]+\t\S.*', line) for line in lines),
                'Could not measure the source website size')
        sizes = {'web_bytes': sum(int(line.split('\t', 1)[0]) for line in lines) * 1024, 'databases': {}}
        for db in inventory['databases']:
            host, connection = self.source_database_route(db, inventory)
            with tempfile.TemporaryFile(dir=self.directory) as handle:
                self.db_io({'action': 'size', 'source': True, 'database': db['database_name'], **connection},
                           output=handle, host=host)
                handle.seek(0)
                value = handle.read().decode().strip()
            require(re.fullmatch(r'[0-9]+', value), 'Could not measure source database size: ' + db['database_name'])
            sizes['databases'][db['database_name']] = int(value)
        return sizes

    def source_database_route(self, database, inventory=None):
        inventory = inventory or self.state['inventory']
        if 'db_via_web' in self.source:
            # Check the SSH execution host's identity, not the remote SQL server's ID.
            # No SSH connection to the source DB host is made in this mode.
            require(len({str(db['server_id']) for db in inventory['databases']}) <= 1,
                    'db_via_web selects one source MySQL host; the site spans multiple old DB server IDs')
            return self.source['web_ssh'], {
                'server_id': inventory['site']['server_id'],
                'source_connection': self.source['db_via_web'],
            }
        server_id = str(database['server_id'])
        require(server_id in self.source['db_ssh'], 'Add source.db_ssh mapping for old DB server ID ' + server_id)
        return self.source['db_ssh'][server_id], {'server_id': database['server_id']}

    def plan(self):
        self.api = self.admin
        inventory = json.loads(execute(php_remote(self.source['panel_ssh'], 'source-inventory.php'),
                                      data=(json.dumps({'domain': self.domain}) + '\n').encode(),
                                      error_path=self.directory / 'source-inventory.log'))
        atomic_json(self.directory / 'inventory.json', inventory)
        validate_inventory(inventory, self.domain)
        routes = [self.source_database_route(db, inventory) for db in inventory['databases']]
        self.check_web_server()
        for host, server_id in [(self.source['web_ssh'], inventory['site']['server_id']),
                                (self.target['db_ssh'], self.target['db_server_id'])] + [
                                    (host, request['server_id']) for host, request in routes]:
            execute(php_remote(host, 'server-check.php'), data=(json.dumps({'server_id': server_id}) + '\n').encode(),
                    error_path=self.directory / 'server-check.log')
        client = self.api.get('/clients/' + str(self.client_id))
        require(int(client['id']) == self.client_id, 'Target client identity mismatch')
        for field, selected in [('web_servers', self.target['web_server_id']), ('db_servers', self.target['db_server_id'])]:
            if field in client:
                assigned = client[field] if isinstance(client[field], list) else str(client[field]).split(',')
                require(str(selected) in [str(value) for value in assigned], 'Target server is not assigned to this ISPConfig client: ' + field)
        existing = [site for site in self.api.all('/sites/web-domains', search=self.domain) if site['domain'] == self.domain]
        own = self.state['objects'].get('site', {}).get('record', {}).get('id')
        require(not existing or (len(existing) == 1 and existing[0]['id'] == own),
                'Target domain already exists outside this migration; refusing to adopt/overwrite it')
        if 'inventory' in self.state:
            require(inventory == self.state['inventory'], 'Source inventory changed; review it before continuing this migration')
        for name, entry in self.state['objects'].items():
            require('record' in entry, 'Uncertain previous POST for %s. Reconcile the API receipt in state.json before retrying; never delete state blindly.' % name)
        self.state['inventory'] = inventory
        self.state['client_label'] = client.get('username', '')
        self.state['source_size'] = self.measure_source(inventory)
        php = self.select_php()
        self.preflight()
        staging, free = self.check_free_space()
        quotas, sizes = self.state['quotas'], self.state['source_size']

        def mb(value):
            return 'unlimited' if value == -1 else '%d MB' % value

        print('PLAN: %s → ISPConfig client %s (%s)' % (self.domain, self.client_id, self.state['client_label']))
        print('Web: %s:%s → %s' % (self.source['web_ssh'], inventory['site']['document_root'], self.target['web_ssh']))
        print('PHP: ' + ('%s (configuration ID %d)' % (php['version'], php['server_php_id']) if php['version'] else
                         'configuration ID %d' % php['server_php_id'] if php['server_php_id'] else 'server default'))
        print('Destination web access: ' + ('local (no SSH)' if self.local_web else 'SSH'))
        print('Website disk quota: %s (source files %d MB)' % (mb(quotas['disk_mb']), -(-sizes['web_bytes'] // MB)))
        print('Website traffic quota: ' + mb(quotas['traffic_mb']))
        print('Staging space: about %d MB needed, %d MB free in %s' % (-(-staging // MB), free // MB, self.directory))
        print('Databases: ' + (', '.join('%s (quota %s, source %d MB)' % (
            db['database_name'], mb(quotas['databases_mb'][db['database_name']]),
            -(-sizes['databases'][db['database_name']] // MB)) for db in inventory['databases']) or '(none)'))
        if 'db_via_web' in self.source:
            connection = self.source['db_via_web']
            print('Source MySQL: %s:%s via %s' % (connection['host'], connection.get('port', 3306), self.source['web_ssh']))
        if inventory['children']:
            print('Shared-root aliases/subdomains: ' + ', '.join(child['domain'] for child in inventory['children']))
        print('WHMCS product/Create, mail, DNS, certificates and cron jobs remain operator steps.')
        print('Plan only: no writes to source or target servers. State: ' + str(self.directory))

    def create(self, name, endpoint, payload):
        objects = self.state['objects']
        if name in objects:
            entry = objects[name]
            require('record' in entry, 'Uncertain previous POST for %s. Reconcile the API receipt in state.json before retrying; never delete state blindly.' % name)
            current = self.api.get(endpoint + '/' + str(entry['record']['id']))
            require(current['id'] == entry['record']['id'], 'Provisioned object changed')
            self.api.wait(entry.get('change'))
            return current
        objects[name] = {'endpoint': endpoint, 'pending': True}
        self.save()  # A lost HTTP response must never result in a duplicate POST.
        try:
            record, change = self.api.request('POST', endpoint, payload)
        except ApiError as exc:
            if exc.status in (400, 401, 403, 404, 405, 409, 413, 415, 422, 429):
                del objects[name]  # Confirmed rejected write, safe to retry after fixing the cause.
                self.save()
            raise
        objects[name] = {'endpoint': endpoint, 'record': record, 'change': change}
        self.save()  # Persist receipt before waiting for asynchronous ISPConfig provisioning.
        self.api.wait(change)
        return record

    def provision(self):
        # Use the customer's own permissions and quotas, just like the WHMCS
        # client area. Admin authentication is limited to account/key management.
        if 'client_key' not in self.state:
            self.state['client_key'] = {'pending': True, 'name': 'migration-' + self.state['nonce']}
            self.save()
            record, _ = self.admin.request('POST', '/system/api-keys', {
                'name': self.state['client_key']['name'], 'client_id': self.client_id,
            })
            self.state['client_key'] = record
            self.save()
        key = self.state['client_key']
        require('key' in key, 'Uncertain migration-key creation; find and revoke migration-' + self.state['nonce'] + ' before clearing only client_key in state.json')
        self.admin.request('PUT', '/system/api-keys/' + str(key['id']), {'active': True})
        self.api = Api(self.target['api_url'], key=key['key'])
        # Refresh immediately before creating a new website. The API still
        # enforces the client/reseller caps if allocations change concurrently.
        quotas = self.refresh_allocation()
        source = self.state['inventory']['site']
        # Legacy target.hd_quota_mb/traffic_quota_mb settings are ignored (kept
        # only in the configuration fingerprint): quotas follow the client.
        payload = {
            'domain': self.domain, 'type': 'vhost', 'client_id': self.client_id,
            'server_id': self.target['web_server_id'], 'ip_address': '*',
            'php': 'php-fpm',
            'active': True, 'subdomain': source['subdomain'], 'ssl': False,
            'ssl_letsencrypt': False, 'rewrite_to_https': False,
            'hd_quota': quotas['disk_mb'], 'traffic_quota': quotas['traffic_mb'],
        }
        # Omitting a version permits the API's first allowed version when the
        # built-in default is hidden; explicitly submitting zero is rejected there.
        php_id = self.state.get('php', {}).get('server_php_id', self.target.get('server_php_id', 0))
        if php_id:
            payload['server_php_id'] = php_id
        site = self.create('site', '/sites/web-domains', payload)
        require(site['domain'] == self.domain and site['server_id'] == self.target['web_server_id']
                and site['system_group'] == 'client' + str(self.client_id), 'Target website identity changed')
        self.site = site
        self.check_target()
        for child in self.state['inventory']['children']:
            name = child['domain']
            if child['type'] == 'subdomain':
                require(name.endswith('.' + self.domain), 'Source subdomain does not match parent')
                name = name[:-len(self.domain) - 1]
            alias = self.create('child:' + str(child['domain_id']), '/sites/web-child-domains', {
                'parent_domain_id': site['id'], 'domain': name, 'type': child['type'],
                'subdomain': child['subdomain'], 'redirect_type': child['redirect_type'],
                'redirect_path': child['redirect_path'], 'active': child['active'] == 'y',
                'ssl_letsencrypt_exclude': True,
            })
            require(alias['parent_domain_id'] == site['id'] and alias['sys_groupid'] == site['sys_groupid']
                    and alias['domain'] == child['domain'], 'Target alias identity changed')
        for source_db in self.state['inventory']['databases']:
            key = source_db['database_name']
            if key not in self.state['databases']:
                self.state['databases'][key] = {'password': 'Aa1!' + secrets.token_urlsafe(27)}
                self.save()
            target_db = self.state['databases'][key]
            short = 'm' + self.state['nonce'] + '_' + str(source_db['database_id'])
            user = self.create('user:' + key, '/sites/database-users', {
                'client_id': self.client_id, 'database_user': short,
                'database_password': target_db['password'],
            })
            require(user['sys_groupid'] == site['sys_groupid'], 'Database user ownership changed')
            if 'db:' + key not in self.state['objects']:
                # Omitting the quota means unlimited, which a finite client
                # database quota rejects. Refresh after earlier databases.
                quotas = self.refresh_allocation()
            database = self.create('db:' + key, '/sites/databases', {
                'parent_domain_id': site['id'], 'server_id': self.target['db_server_id'],
                'database_name': short, 'database_user_id': user['id'], 'type': 'mysql',
                'database_charset': source_db['database_charset'] or '', 'active': True,
                'database_quota': quotas['databases_mb'][key],
                'remote_access': True, 'remote_ips': self.target['db_remote_ips'],
            })
            require(database['parent_domain_id'] == site['id'] and database['server_id'] == self.target['db_server_id']
                    and database['database_user_id'] == user['id'] and database['sys_groupid'] == site['sys_groupid'],
                    'Target database identity changed')
            target_db.update({'id': database['id'], 'name': database['database_name_full'],
                              'user': user['database_user_prefix'] + user['database_user'],
                              'host': self.target['db_host'], 'old_user': source_db['database_user']})
            self.save()
            self.db_io({'action': 'probe', **self.credentials(target_db)})
        atomic_json(self.directory / 'database-map.json', self.state['databases'])

    def files_command(self):
        identity = json.dumps({field: self.site[field] for field in ('document_root', 'system_user', 'system_group')})
        if self.local_web:
            return ['python3', str(HERE / 'target-files.py'), identity]
        code = base64.b64encode((HERE / 'target-files.py').read_bytes()).decode()
        # Source is administrator-controlled and encoded before passing through ssh/rsync shells.
        return ['python3', '-c', 'import base64;exec(base64.b64decode("' + code + '"))', identity]

    def target_rsync(self):
        if self.local_web:
            # Keep rsync's separate sender/receiver processes so the website side
            # drops privilege while the administrator side can read private state.
            # The transport executes our local helper directly, with no SSH/socket.
            return RSYNC_BASE + ['-e', shlex.join(self.files_command() + ['--local-rsync'])], 'local:'
        return RSYNC + ['--rsync-path=' + shlex.join(self.files_command())], self.target['web_ssh'] + ':'

    def check_target(self):
        self.check_web_server()
        execute(self.web_command(self.files_command()), error_path=self.directory / 'target-files.log')

    @staticmethod
    def credentials(db):
        return {'database': db['name'], 'user': db['user'], 'password': db['password']}

    def db_io(self, request, output=None, input_file=None, host=None):
        request = dict(request)
        if 'server_id' not in request:
            request['server_id'] = self.target['db_server_id']
        argv = php_remote(host or self.target['db_ssh'], 'db-io.php')
        with open(self.directory / 'database.log', 'ab') as errors:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=output or subprocess.DEVNULL, stderr=errors)
            try:
                process.stdin.write((json.dumps(request) + '\n').encode())
                if input_file:
                    shutil.copyfileobj(input_file, process.stdin, 1024 * 1024)
                process.stdin.close()
                code = process.wait()
            except BaseException:
                process.kill()
                process.wait()
                raise
        require(code == 0, 'Database %s failed; see private database.log. Source data is unchanged.' % request['action'])

    def pull(self):
        tree = self.directory / ('round-%03d' % self.state['round']) / 'tree'
        if (tree.parent / 'files-staged.json').exists():
            return tree
        tree.mkdir(parents=True, exist_ok=True, mode=0o700)
        root = self.state['inventory']['site']['document_root']
        for folder in ('web', 'private'):
            destination = tree / folder
            destination.mkdir(exist_ok=True)
            execute(RSYNC + ['--delete-delay', self.source['web_ssh'] + ':' + root + '/' + folder + '/', str(destination) + '/'],
                    error_path=self.directory / 'rsync.log')
        normalize_links(tree, root)
        atomic_json(tree.parent / 'files-staged.json', {'complete': True})
        return tree

    def backup(self, round_dir):
        marker = round_dir / 'backup-complete.json'
        if marker.exists():
            return
        backup = round_dir / 'before'
        backup.mkdir(mode=0o700, exist_ok=True)
        transfer, target = self.target_rsync()
        for folder in ('web', 'private'):
            (backup / folder).mkdir(exist_ok=True)
            execute(transfer + [target + self.site['document_root'] + '/' + folder + '/',
                            str(backup / folder) + '/'], error_path=self.directory / 'rsync.log')
        for key, db in self.state['databases'].items():
            # Binary stdout goes to a file, never the terminal. Compress after successful dump.
            sql = backup / (key + '.sql')
            with open(sql, 'wb') as output:
                self.db_io({'action': 'dump', **self.credentials(db)}, output=output)
            with open(sql, 'rb') as source, gzip.open(str(sql) + '.gz', 'wb') as target:
                shutil.copyfileobj(source, target, 1024 * 1024)
            sql.unlink()
        atomic_json(marker, {'complete': True})

    def transfer_databases(self, round_dir):
        # Finish ALL source dumps before importing any database. Retain the same
        # snapshot on retry, including after a partially completed import.
        for source in self.state['inventory']['databases']:
            key = source['database_name']
            if (round_dir / (key + '.dumped.json')).exists():
                continue
            host, connection = self.source_database_route(source)
            with open(round_dir / (key + '.source.sql'), 'wb') as output:
                self.db_io({'action': 'dump', 'source': True, 'database': key, **connection}, output=output, host=host)
            atomic_json(round_dir / (key + '.dumped.json'), {'complete': True})
        for source in self.state['inventory']['databases']:
            key = source['database_name']
            marker = round_dir / (key + '.imported.json')
            if marker.exists():
                continue
            db = self.state['databases'][key]
            raw = round_dir / (key + '.source.sql')
            print('Database: ' + key + ' → ' + db['name'], flush=True)
            normalized = round_dir / (key + '.target.sql')
            with open(raw, 'rb') as source_file, open(normalized, 'wb') as target_file, open(self.directory / 'database.log', 'ab') as errors:
                result = subprocess.run(['php', str(HERE / 'normalize-sql.php'), key, db['name']],
                                        stdin=source_file, stdout=target_file, stderr=errors)
            require(result.returncode == 0, 'SQL normalization failed; source dump retained')
            with open(normalized, 'rb') as source_file:
                self.db_io({'action': 'import', **self.credentials(db)}, input_file=source_file)
            atomic_json(marker, {'complete': True})
            # Keep an immutable source snapshot for recovery. Delete normalized plaintext copy.
            with open(raw, 'rb') as source_file, gzip.open(str(raw) + '.gz', 'wb') as target_file:
                shutil.copyfileobj(source_file, target_file, 1024 * 1024)
            raw.unlink()
            normalized.unlink()

    def configure(self, tree):
        if (tree.parent / 'configuration-report.json').exists():
            report = read_json(tree.parent / 'configuration-report.json')
            self.state['manual_configuration'] = bool(report['manual_files'] or report['databases_needing_manual_config'])
            self.save()
            return
        updated, manual, covered = [], [], set()
        for directory, dirs, files in os.walk(tree, followlinks=False):
            if 'wp-config.php' not in files:
                continue
            path = Path(directory) / 'wp-config.php'
            if path.is_symlink():
                manual.append(str(path.relative_to(tree)))
                continue
            request = {'content': base64.b64encode(path.read_bytes()).decode(), 'databases': self.state['databases']}
            result = subprocess.run(['php', str(HERE / 'wordpress-config.php')], input=json.dumps(request).encode(),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode:
                manual.append(str(path.relative_to(tree)))
                continue
            response = json.loads(result.stdout)
            path.write_bytes(base64.b64decode(response['content']))
            covered.add(response['database'])
            updated.append(str(path.relative_to(tree)))
        missing = sorted(set(self.state['databases']) - covered)
        report = {'wordpress_updated': updated, 'manual_files': manual, 'databases_needing_manual_config': missing}
        atomic_json(tree.parent / 'configuration-report.json', report)
        self.state['manual_configuration'] = bool(manual or missing)
        self.save()

    def publish(self, *, config_reviewed=False):
        require(self.state['phase'] == 'prepared', 'Run the migration first; no prepared files available')
        require(not self.state.get('manual_configuration') or config_reviewed,
                'Edit configs in the staged tree using database-map.json, then repeat ispcp-migrate %s %s (or use publish --config-reviewed). No files were published.' % (self.domain, self.client_id))
        self.site = self.state['objects']['site']['record']
        current = self.api.get('/sites/web-domains/' + str(self.site['id']))
        for field in ('id', 'domain', 'server_id', 'sys_groupid', 'document_root', 'system_user', 'system_group'):
            require(current[field] == self.site[field], 'Website identity changed since preparation')
        self.check_target()
        tree = self.directory / ('round-%03d' % self.state['round']) / 'tree'
        normalize_links(tree, self.state['inventory']['site']['document_root'])
        # Credential configurations MUST have been patched in the private staging tree first.
        transfer, target = self.target_rsync()
        for folder in ('private', 'web'):
            mode = 'Du=rwx,Dgo=,Fu=rw,Fgo=' if folder == 'private' else 'Du=rwx,Dgo=rx,Fu=rw,Fgo=r'
            execute(transfer + ['--chmod=' + mode, '--delete-delay', '--exclude=/.well-known/acme-challenge/',
                            str(tree / folder) + '/', target + self.site['document_root'] + '/' + folder + '/'],
                    error_path=self.directory / 'rsync.log')
        self.state['phase'] = 'copied'
        self.save()
        print('COPY COMPLETE: ' + self.domain + ' (website ID ' + str(self.site['id']) + ')')
        print('Verify the application on the new host before switching DNS. Migration state: ' + str(self.directory))

    def run(self, *, sync=False, source_quiesced=False, target_quiesced=False, plan_ready=False):
        try:
            self._run(sync=sync, source_quiesced=source_quiesced, target_quiesced=target_quiesced, plan_ready=plan_ready)
        finally:
            key = self.state.get('client_key', {})
            if 'id' in key:
                self.admin.request('PUT', '/system/api-keys/' + str(key['id']), {'active': False})

    def _run(self, *, sync=False, source_quiesced=False, target_quiesced=False, plan_ready=False):
        require(source_quiesced, 'Stop source application writes/cron first, then pass --source-quiesced. The script never stops the old website automatically.')
        if sync:
            require(target_quiesced, 'Stop target application writes/cron too, then pass --target-quiesced for sync')
            require(self.state['phase'] == 'copied', 'Finish the current migration before starting a final sync')
            self.state['round'] += 1
            self.state['phase'] = 'planned'
            self.save()
        elif self.state['phase'] == 'copied':
            print('Already copied. Use sync --source-quiesced for a new source snapshot; DNS remains manual.')
            return
        if self.state['phase'] == 'prepared':
            self.publish()
            return
        if not plan_ready:
            self.plan()
        print('Provisioning target website and databases…', flush=True)
        self.provision()
        print('Copying source files into the private staging directory…', flush=True)
        tree = self.pull()
        self.backup(tree.parent)
        self.transfer_databases(tree.parent)
        self.configure(tree)
        self.state['phase'] = 'prepared'
        self.save()
        self.publish()


# --- ispcp-migrate --sites: which old websites are live --------------------------------------
# Public DNS decides, not /etc/hosts or a server's own authoritative copy of a zone, so the
# hostnames are asked directly from recursive resolvers (public ones unless --resolver is given).
DNS_RESOLVERS = ('1.1.1.1', '8.8.8.8')
DNS_A, DNS_AAAA, DNS_CNAME = 1, 28, 5
DNS_RCODES = {1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}
# Website status, strongest first: one hostname on the old server keeps the website "old".
SITE_STATES = ('old', 'new', 'other', 'none')
SITE_STATE_HELP = {'old': 'DNS points to the old server: live, migrate',
                   'new': 'DNS points to the new web server: migrated',
                   'other': 'DNS points elsewhere (or a proxy/CDN, compare traffic)',
                   'none': 'no DNS address'}


class DnsError(Exception):
    pass


def ascii_hostname(name):
    name = str(name).strip().rstrip('.').lower()
    try:
        name = name.encode('idna').decode('ascii')
    except UnicodeError:
        raise DnsError('invalid name') from None
    if not name or len(name) > 253 or any(not 0 < len(label) < 64 for label in name.split('.')):
        raise DnsError('invalid name')
    return name


def dns_read_name(message, offset):
    """Name at offset (with compression pointers) and the offset after it."""
    labels, end, jumps = [], None, 0
    while True:
        if offset >= len(message):
            raise DnsError('malformed response')
        length = message[offset]
        if length >= 0xC0:
            jumps += 1
            if offset + 1 >= len(message) or jumps > 32:
                raise DnsError('malformed response')
            end = offset + 2 if end is None else end
            offset = (length & 0x3F) << 8 | message[offset + 1]
        elif length >= 0x40 or offset + 1 + length > len(message):
            raise DnsError('malformed response')
        elif length == 0:
            return '.'.join(labels).lower(), offset + 1 if end is None else end
        else:
            labels.append(message[offset + 1:offset + 1 + length].decode('ascii', 'replace'))
            offset += 1 + length


def dns_parse(message, ident, question):
    """(truncated, rcode, [(owner, type, value)]) or None for a reply to another query."""
    if len(message) < 12:
        return None
    rid, flags, questions, answers = struct.unpack('!HHHH', message[:8])
    if rid != ident or not flags & 0x8000 or questions != 1 or message[12:12 + len(question)].lower() != question.lower():
        return None
    offset, records = 12 + len(question), []
    for _ in range(answers):
        owner, offset = dns_read_name(message, offset)
        if offset + 10 > len(message):
            raise DnsError('malformed response')
        rtype, rclass, _, length = struct.unpack('!HHIH', message[offset:offset + 10])
        offset += 10
        if offset + length > len(message):
            raise DnsError('malformed response')
        data = message[offset:offset + length]
        if rclass == 1 and rtype == DNS_A and length == 4:
            records.append((owner, rtype, str(ipaddress.IPv4Address(data))))
        elif rclass == 1 and rtype == DNS_AAAA and length == 16:
            records.append((owner, rtype, ipaddress.IPv6Address(data).compressed))
        elif rclass == 1 and rtype == DNS_CNAME:
            records.append((owner, rtype, dns_read_name(message, offset)[0]))
        offset += length
    return bool(flags & 0x0200), flags & 0x000F, records


def recv_exact(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise DnsError('malformed response')
        data += chunk
    return data


def dns_query(resolver, name, qtype, timeout=3.0):
    """One recursive query over UDP (TCP when truncated): (rcode, records)."""
    host, port = resolver
    question = b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.')) + b'\0' + struct.pack('!HH', qtype, 1)
    ident = secrets.randbits(16)
    packet = struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + question
    deadline = time.monotonic() + timeout
    try:
        with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.connect((host, port))
            udp.send(packet)
            parsed = None
            while parsed is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DnsError('timeout')
                udp.settimeout(remaining)
                parsed = dns_parse(udp.recv(65535), ident, question)
        if parsed[0]:
            with socket.create_connection((host, port), timeout=timeout) as tcp:
                tcp.sendall(struct.pack('!H', len(packet)) + packet)
                parsed = dns_parse(recv_exact(tcp, struct.unpack('!H', recv_exact(tcp, 2))[0]), ident, question)
                if parsed is None:
                    raise DnsError('malformed response')
    except socket.timeout:
        raise DnsError('timeout') from None
    except OSError:
        raise DnsError('resolver unreachable') from None
    return parsed[1], parsed[2]


def dns_ask(resolvers, name, qtype, timeout):
    """Ask the resolvers in order; the next one only after a timeout or server failure."""
    failure = 'timeout'
    for resolver in resolvers:
        try:
            rcode, records = dns_query(resolver, name, qtype, timeout)
        except DnsError as exc:
            failure = str(exc)
            continue
        if rcode in (0, 3):
            return rcode, records
        failure = DNS_RCODES.get(rcode, 'RCODE %d' % rcode)
    raise DnsError(failure)


def resolve(name, resolvers, timeout=3.0):
    """Public IPv4/IPv6 addresses of a hostname, following CNAMEs."""
    addresses, chain, failures, nxdomain = [], [], [], False
    try:
        name = ascii_hostname(name)
    except DnsError as exc:
        return {'addresses': [], 'cname': [], 'error': str(exc)}
    for qtype in (DNS_A, DNS_AAAA):
        current, asked = name, set()
        while current not in asked and len(asked) < 8:
            asked.add(current)
            try:
                rcode, records = dns_ask(resolvers, current, qtype, timeout)
            except DnsError as exc:
                failures.append(str(exc))
                break
            if rcode == 3:
                nxdomain = True
                break
            aliases = {owner: value for owner, rtype, value in records if rtype == DNS_CNAME}
            target = current
            for _ in range(8):
                if target not in aliases:
                    break
                target = aliases[target]
                if target not in chain:
                    chain.append(target)
            found = [value for owner, rtype, value in records if rtype == qtype and owner == target]
            addresses += [value for value in found if value not in addresses]
            if found or target == current:
                break
            current = target  # only the CNAME came back: ask for its target
    error = None if addresses else 'NXDOMAIN' if nxdomain else failures[0] if failures else 'no address'
    return {'addresses': addresses, 'cname': chain, 'error': error}


def ip_text(value):
    try:
        return ipaddress.ip_address(str(value).strip()).compressed
    except ValueError:
        return None


def resolver_address(value):
    address = ip_text(value)
    require(address, '--resolver takes an IP address: ' + str(value))
    return address, 53


def source_sites(config):
    """Every website of the old ISPConfig, read on the old panel (no state, no writes)."""
    host = ssh_host(config['source']['panel_ssh'])
    result = subprocess.run(php_remote(host, 'source-sites.php'), stdin=subprocess.DEVNULL, capture_output=True)
    if result.returncode:
        # Only the helper's own messages and SSH errors; no credentials reach stderr.
        lines = result.stderr.decode('utf-8', 'replace').strip().splitlines()
        raise MigrationError('Reading the old websites on %s failed (exit %d)%s' % (
            host, result.returncode, ': ' + lines[-1][:300] if lines else ''))
    return json.loads(result.stdout)


def site_hostnames(row):
    domain = str(row['domain']).strip().lower().rstrip('.')
    return [domain] + (['www.' + domain] if row.get('subdomain') in ('www', '*') else [])


def site_list(inventory):
    """Websites (vhosts, child vhosts) with the hostnames they serve: active aliases/subdomains included."""
    children = {}
    for row in inventory['websites']:
        if row['type'] in ('alias', 'subdomain') and row.get('active') == 'y':
            children.setdefault(str(row['parent_domain_id']), []).append(row)
    servers = {str(server['server_id']): server['server_name'] for server in inventory['servers']}
    domains = {str(row['domain_id']): row['domain'] for row in inventory['websites']}
    traffic = inventory.get('traffic')
    sites = []
    for row in inventory['websites']:
        if row['type'] in ('alias', 'subdomain'):
            continue
        names = site_hostnames(row)
        for child in children.get(str(row['domain_id']), []):
            names += [name for name in site_hostnames(child) if name not in names]
        label = ' '.join(str(value) for value in (row.get('client_username'), row.get('client_company') or row.get('client_contact')) if value)
        sites.append({
            'domain': row['domain'], 'type': row['type'], 'id': int(row['domain_id']),
            'parent': domains.get(str(row['parent_domain_id'])) if row['type'] != 'vhost' else None,
            'server': servers.get(str(row['server_id']), str(row['server_id'])), 'server_id': int(row['server_id']),
            'active': row.get('active') == 'y', 'document_root': row['document_root'],
            'redirect': row.get('redirect_path') or None, 'client': label,
            'databases': int(inventory.get('databases', {}).get(str(row['domain_id']), 0)),
            'traffic_30d_bytes': None if traffic is None else int(sum(traffic.get(name, 0) for name in names)),
            'hostnames': names,
        })
    return sites


def server_addresses(inventory, config, extra_old, extra_new, lookup):
    """Address → label for the old web servers and the new web server."""
    old, new, warnings = {}, {}, []

    def add(table, value, label):
        address = ip_text(value)
        if address and address not in table:
            table[address] = label

    names = {str(server['server_id']): server['server_name'] for server in inventory['servers']}
    web_servers = sorted({str(row['server_id']) for row in inventory['websites']})
    for row in inventory['ips']:
        if str(row['server_id']) in web_servers:
            add(old, row['ip_address'], names.get(str(row['server_id']), 'server ' + str(row['server_id'])))
    for row in inventory['websites']:
        for field in ('ip_address', 'ipv6_address'):
            add(old, row.get(field), names.get(str(row['server_id']), 'server ' + str(row['server_id'])))
    for server_id in web_servers:
        if names.get(server_id):
            for address in lookup(names[server_id])['addresses']:
                add(old, address, 'DNS ' + names[server_id])
    for address in extra_old:
        add(old, address, '--old-ip')
    target = config['target']
    try:
        api = Api(target['api_url'], target['api_key_file'])
        for row in api.all('/servers/%d/ip-addresses' % int(target['web_server_id'])):
            add(new, row.get('ip_address'), 'API server %s' % target['web_server_id'])
    except (MigrationError, OSError, KeyError, TypeError, ValueError) as exc:
        warnings.append('New web server addresses from the API are unavailable (%s); add them with --new-ip.' % exc)
    host = str(target.get('web_ssh', '')).split('@')[-1]
    if ip_text(host):
        add(new, host, 'target.web_ssh')
    elif '.' in host:
        for address in lookup(host)['addresses']:
            add(new, address, 'DNS ' + host)
    for address in extra_new:
        add(new, address, '--new-ip')
    for address in set(old) & set(new):
        warnings.append('%s is listed for both the old and the new server; counted as old.' % address)
    return old, new, warnings


def classify_sites(sites, resolved, old, new):
    for site in sites:
        site['dns'] = []
        for name in site['hostnames']:
            result = resolved[name]
            addresses = result['addresses']
            state = 'old' if any(a in old for a in addresses) else 'new' if any(a in new for a in addresses) \
                else 'other' if addresses else 'none'
            site['dns'].append(dict(result, name=name, state=state))
        site['status'] = next(state for state in SITE_STATES if state == 'none' or any(entry['state'] == state for entry in site['dns']))
    return sites


def site_inventory(config, *, resolvers, extra_old=(), extra_new=(), workers=16, inventory=None):
    inventory = source_sites(config) if inventory is None else inventory
    sites = site_list(inventory)
    cache = {}

    def lookup(name):
        if name not in cache:
            cache[name] = resolve(name, resolvers)
        return cache[name]

    old, new, warnings = server_addresses(inventory, config, extra_old, extra_new, lookup)
    names = sorted({name for site in sites for name in site['hostnames']} - set(cache))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        cache.update(zip(names, pool.map(lambda name: resolve(name, resolvers), names)))
    return {'resolvers': [host for host, _ in resolvers], 'old_addresses': old, 'new_addresses': new,
            'warnings': warnings, 'traffic': inventory.get('traffic') is not None,
            'websites': classify_sites(sites, cache, old, new)}


def human_bytes(value):
    if value is None:
        return '-'
    if value >= 1024 ** 3:
        return '%.1f GB' % (value / 1024 ** 3)
    return '%d MB' % -(-value // MB)


def print_sites(report, states=SITE_STATES, *, as_json=False, out=None):
    out = out or sys.stdout
    shown = sorted((site for site in report['websites'] if site['status'] in states),
                   key=lambda site: (SITE_STATES.index(site['status']), site['domain']))
    if as_json:
        json.dump(dict(report, websites=shown), out, indent=2, ensure_ascii=False)
        out.write('\n')
        return

    def addresses(table):
        return ', '.join('%s (%s)' % item for item in table.items()) or '(none found)'

    out.write('Old web server addresses: %s\n' % addresses(report['old_addresses']))
    out.write('New web server addresses: %s\n' % addresses(report['new_addresses']))
    out.write('DNS resolvers: %s\n' % ', '.join(report['resolvers']))
    for warning in report['warnings']:
        out.write('WARNING: %s\n' % warning)
    rows = [('STATUS', 'WEBSITE', 'ACT', 'SERVER', 'CLIENT', 'DB', 'TRAFFIC 30D', 'DNS')]
    for site in shown:
        detail = []
        for entry in site['dns']:
            name = 'www' if entry['name'] == 'www.' + site['domain'] else entry['name']
            value = entry['state'] if entry['state'] in ('old', 'new') else \
                ','.join(entry['addresses'][:3]) + (',…' if len(entry['addresses']) > 3 else '') if entry['addresses'] else entry['error']
            detail.append('%s=%s' % (name, value))
        domain = site['domain'] + (' (in %s)' % site['parent'] if site['parent'] else '')
        rows.append((site['status'], domain, 'y' if site['active'] else 'n', site['server'], site['client'][:28],
                     str(site['databases']), human_bytes(site['traffic_30d_bytes']), ' '.join(detail)))
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]) - 1)]
    for row in rows:
        out.write('  '.join(value.ljust(width) for value, width in zip(row, widths)) + '  ' + row[-1] + '\n')
    counts = {state: sum(site['status'] == state for site in report['websites']) for state in SITE_STATES}
    out.write('\n' + '\n'.join('%-5s %4d  %s' % (state, counts[state], SITE_STATE_HELP[state]) for state in SITE_STATES) + '\n')
    inactive = sum(not site['active'] for site in report['websites'])
    if inactive:
        out.write('Inactive old websites (ACT n): %d; ISPConfig does not serve them.\n' % inactive)
    if not report['traffic']:
        out.write('Traffic statistics (web_traffic) are not available on the old panel.\n')


def sites_options(parser):
    parser.add_argument('--status', metavar='STATES', help='Only show these states, comma separated: old,new,other,none')
    parser.add_argument('--json', action='store_true', help='Print JSON instead of the table')
    parser.add_argument('--resolver', action='append', metavar='IP',
                        help='Recursive DNS resolver to ask (repeatable; default %s)' % ' and '.join(DNS_RESOLVERS))
    parser.add_argument('--old-ip', action='append', default=[], metavar='IP',
                        help='Another public address of the old web server, e.g. behind NAT (repeatable)')
    parser.add_argument('--new-ip', action='append', default=[], metavar='IP',
                        help='Another public address of the new web server (repeatable)')


def check_sites_options(args):
    args.states = tuple(SITE_STATES if not args.status else [value.strip() for value in args.status.split(',')])
    require(set(args.states) <= set(SITE_STATES), '--status takes old, new, other and/or none')
    args.resolvers = [resolver_address(value) for value in (args.resolver or DNS_RESOLVERS)]
    for value in args.old_ip + args.new_ip:
        require(ip_text(value), 'Not an IP address: ' + value)


def run_sites(args):
    config = read_json(args.config)
    report = site_inventory(config, resolvers=args.resolvers, extra_old=args.old_ip, extra_new=args.new_ip)
    print_sites(report, args.states, as_json=args.json)


def confirm(message):
    require(sys.stdin.isatty(), 'Interactive migration requires a terminal. Use --plan for a read-only check or the documented batch interface.')
    try:
        answer = input(message + ' [y/N] ').strip().lower()
    except EOFError:
        answer = ''
    require(answer in ('y', 'yes', 'ano', 'áno'), 'Not started.')


def interactive(migration, *, sync=False):
    phase = migration.state['phase']
    if not sync and phase == 'copied':
        print('Already copied. For a new source snapshot use: ispcp-migrate %s %s --sync' % (migration.domain, migration.client_id))
        return
    if not sync and phase == 'prepared':
        if migration.state.get('manual_configuration'):
            tree = migration.directory / ('round-%03d' % migration.state['round']) / 'tree'
            print('Prepared files: ' + str(tree))
            print('Database credentials: ' + str(migration.directory / 'database-map.json'))
            confirm('Have you updated and reviewed the application database configuration in the prepared files? Publish this copy?')
        migration.publish(config_reviewed=True)
        return
    require(not sync or phase == 'copied', 'Resume the unfinished migration by running the same command without --sync.')
    migration.plan()
    if sync:
        confirm('The source snapshot will overwrite the target. Are writes and scheduled jobs stopped on BOTH sites? Start sync?')
    else:
        confirm('Are writes and scheduled jobs stopped on the OLD site? Start migration?')
    migration.run(sync=sync, source_quiesced=True, target_quiesced=sync, plan_ready=True)


def parse_args(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:2] == ['--simple', '--sites'] or argv[:1] == ['sites']:
        simple = argv[0] == '--simple'
        parser = argparse.ArgumentParser(
            prog='ispcp-migrate --sites' if simple else 'migrate.py sites',
            description='List the old ISPConfig websites and where their public DNS points.')
        parser.add_argument('--config', default=DEFAULT_CONFIG, help='Connection settings (normally configured once)')
        sites_options(parser)
        args = parser.parse_args(argv[2:] if simple else argv[1:])
        try:
            check_sites_options(args)
        except MigrationError as exc:
            parser.error(str(exc))
        args.command = 'sites'
        return args
    if argv and argv[0] == '--simple':
        parser = argparse.ArgumentParser(prog='ispcp-migrate', description='Migrate a website to an existing new ISPConfig client.',
                                         epilog='Which old websites are live (DNS): ispcp-migrate --sites')
        parser.add_argument('domain', help='Domain on the old ISPConfig')
        parser.add_argument('client_id', type=int, help='Client ID in the NEW ISPConfig (not WHMCS)')
        actions = parser.add_mutually_exclusive_group()
        actions.add_argument('--plan', dest='command', action='store_const', const='plan', help='Only show the migration plan')
        actions.add_argument('--sync', dest='command', action='store_const', const='interactive_sync', help='Take a new source snapshot after the first migration')
        actions.add_argument('--status', dest='command', action='store_const', const='status', help='Show saved progress')
        parser.add_argument('--config', default=DEFAULT_CONFIG, help='Connection settings (normally configured once)')
        parser.add_argument('--state', help='Existing state directory from a manual migration; normally state_dir/DOMAIN')
        parser.add_argument('--php', metavar='VERSION', help='PHP version of the new website, e.g. 5.6 (default: target.server_php_id)')
        parser.set_defaults(command='interactive', source_quiesced=False, target_quiesced=False, config_reviewed=False)
        args = parser.parse_args(argv[1:])
        try:
            args.domain = domain_name(args.domain)
            require(args.client_id > 0, 'client ID must be positive')
            require(args.php is None or re.fullmatch(r'[0-9]+\.[0-9]+', args.php), '--php takes a version such as 5.6 or 8.3')
        except (MigrationError, ValueError) as exc:
            parser.error(str(exc))
        return args
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['plan', 'run', 'sync', 'publish', 'status'])
    parser.add_argument('--config', required=True, help='Connection settings JSON (see config.example.json)')
    parser.add_argument('--domain', required=True)
    parser.add_argument('--client-id', required=True, type=int, help='Existing NEW ISPConfig client ID')
    parser.add_argument('--state', required=True, help='Private directory outside every document root; retain for resume')
    parser.add_argument('--source-quiesced', action='store_true', help='Confirm source application writes/cron are stopped')
    parser.add_argument('--target-quiesced', action='store_true', help='With sync: confirm target writes/cron are also stopped')
    parser.add_argument('--config-reviewed', action='store_true', help='With publish: manually patched staged non-WordPress configs')
    parser.add_argument('--php', metavar='VERSION', help='With plan/run: PHP version of the new website, e.g. 5.6')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    os.umask(0o077)
    try:
        if args.command == 'sites':
            require(shutil.which('ssh'), 'Install required local command: ssh')
            run_sites(args)
            return 0
        for command in ('ssh', 'rsync', 'php'):
            require(shutil.which(command), 'Install required local command: ' + command)
        config = read_json(args.config)
        if args.state is None:
            args.state = str(state_root(config) / args.domain)
            legacy = DEFAULT_STATE / args.domain
            require(Path(args.state) == legacy or (Path(args.state) / 'state.json').exists()
                    or not (legacy / 'state.json').exists(),
                    'The migration state of %s is still in %s. Move it first: mv %s %s/'
                    % (args.domain, legacy, legacy, state_root(config)))
        state_dir = private_directory(args.state)
        lock = os.open(state_dir / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(lock, 'w') as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MigrationError('Another process is using this migration state') from None
            migration = Migration(config, state_dir, args.domain, args.client_id)
            migration.php_version = args.php
            if args.command == 'plan':
                migration.plan()
            elif args.command == 'status':
                print('Domain: %s; phase: %s; round: %s' % (migration.domain, migration.state['phase'], migration.state['round']))
            elif args.command == 'publish':
                migration.publish(config_reviewed=args.config_reviewed)
            elif args.command in ('interactive', 'interactive_sync'):
                interactive(migration, sync=args.command == 'interactive_sync')
            else:
                migration.run(sync=args.command == 'sync', source_quiesced=args.source_quiesced, target_quiesced=args.target_quiesced)
    except (MigrationError, OSError, ValueError, KeyError) as exc:
        print('STOP: ' + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Interrupted. Retain the state directory and rerun the same command to resume.', file=sys.stderr)
        return 130
    return 0


if __name__ == '__main__':
    sys.exit(main())
