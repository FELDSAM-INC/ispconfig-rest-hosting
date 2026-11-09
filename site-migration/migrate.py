#!/usr/bin/env python3
"""Copy one old ISPConfig vhost or Plesk website into a client already provisioned by WHMCS.

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
             'limit_web_subdomain', 'limit_database', 'limit_database_user', 'limit_database_quota',
             'limit_cron', 'limit_cron_frequency')
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
    'database_users': 'database users', 'databases': 'databases', 'cron_jobs': 'cron jobs',
    'dns_zones': 'DNS zones', 'dns_records': 'DNS records',
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
    """Make absolute in-site links relative; reject links outside web/private.

    old_root is the old website root (mirrored by the tree) or a list of (old directory, tree folder) pairs.
    """
    tree = Path(tree).resolve()
    roots = [(old_root, '')] if isinstance(old_root, str) else list(old_root)
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
                root = next(((old, folder) for old, folder in roots if link.startswith(old + '/')), None)
                require(root is not None, 'External absolute symlink: ' + str(path.relative_to(tree)))
                target = tree / root[1] / link[len(root[0]) + 1:]
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


# --- Plesk source ----------------------------------------------------------------------------
# plesk-source.py runs on the Plesk server (Python 3.6+) and only reads: `plesk db` SELECTs, the owner's
# account and crontab, sizes and files as the subscription's system user, dumps as the Plesk administrator.
SOURCE_TYPES = ('ispconfig', 'plesk')
# Webspace entries Plesk, CloudLinux and the chroot shell create; anything else outside the document root is reported.
PLESK_SYSTEM_ENTRIES = frozenset((
    'bin', 'dev', 'etc', 'lib', 'lib64', 'usr', 'var', 'tmp', 'logs', 'error_docs', 'cgi-bin', '.cagefs', '.cl.selector',
    '.imunify_patch_id', '.myimunify_id', '.bash_history', '.bash_logout', '.bash_profile', '.bashrc', '.profile',
    '.ssh', '.cache', '.config', '.local', '.composer', '.nodenv', '.npm', '.wp-cli', '.mysql_history', '.lesshst',
    '.viminfo', '.wget-hsts', '.python_history', '.gnupg', '.trash', '.wp-toolkit', '.secure_site_id'))
FOLDER_PART = re.compile(r'[A-Za-z0-9_][A-Za-z0-9._-]*')
CRON_FIELDS = (('run_min', 0, 59, 1), ('run_hour', 0, 23, 60), ('run_mday', 1, 31, 1440),
               ('run_month', 1, 12, 40320), ('run_wday', 0, 7, 1440))
CRON_ENTRY = re.compile(r'(?:([0-9]+)(?:-([0-9]+))?|\*)(?:/([1-9][0-9]*))?\Z')
CRON_MACROS = {'@hourly': '0 * * * *', '@daily': '0 0 * * *', '@midnight': '0 0 * * *', '@weekly': '0 0 * * 0',
               '@monthly': '0 0 1 * *', '@yearly': '0 0 1 1 *', '@annually': '0 0 1 1 *'}
# Output discarded to /dev/null at the end of a command is kept as written; other shell syntax is reviewed by hand.
CRON_REDIRECT = re.compile(r'\s+(?:(?:1?>|>>)\s*/dev/null(?:\s+2>&1)?|2>&1\s+(?:1?>|>>)\s*/dev/null|&>\s*/dev/null)\s*\Z')
# WordPress cron of WP Toolkit (php -f httpdocs/wp-cron.php, or a fetch of /wp-cron.php): not migrated, the website's
# WordPress cron is turned on in the panel instead.
WORDPRESS_CRON = re.compile(r'(?:\A|[\s/\'"=])wp-cron\.php(?:[\s\'"?#]|\Z)')
CRON_PHP = re.compile(r'(?:/opt/alt/php[0-9]+/usr/bin/php|/opt/plesk/php/[0-9]+\.[0-9]+/bin/php|/usr/(?:local/)?bin/php[0-9.]*|php[0-9.]*)\Z')


def plesk_command(host):
    """Run plesk-source.py with the Plesk server's own Python; the request goes to its stdin."""
    code = base64.b64encode((HERE / 'plesk-source.py').read_bytes()).decode()
    script = 'p=$(command -v python3 || echo /usr/libexec/platform-python); exec "$p" -I -c "$0"'
    return remote(host, ['sh', '-c', script, 'import base64;exec(base64.b64decode("' + code + '"))'])


def plesk_php_version(handler):
    """alt-php74-fpm / plesk-php82-fastcgi → 7.4 / 8.2; None for other handlers."""
    match = re.fullmatch(r'(?:alt|plesk)-php([0-9])([0-9]+)-[a-z-]+', str(handler or ''))
    return '%s.%s' % match.groups() if match else None


def cron_field_valid(minimum, maximum, value):
    """ISPConfig's validate_cron run_time_format (the API rejects anything else)."""
    if not re.fullmatch(r'[0-9,/*-]+', value) or re.search(r'[-,/][-,/]', value):
        return False
    for entry in value.split(','):
        match = CRON_ENTRY.match(entry)
        if not match:
            return False
        start, end, step = match.groups()
        if start is not None and (not minimum <= int(start) <= maximum
                                  or end is not None and (not minimum <= int(end) <= maximum or int(end) <= int(start))):
            return False
        if step is not None and not 2 <= int(step) <= maximum - 1:
            return False
    return True


def cron_interval(fields):
    """Shortest interval between runs in minutes, as ISPConfig computes it for limit_cron_frequency."""
    interval = None
    for (_, minimum, maximum, weight), value in zip(CRON_FIELDS, fields):
        used = set()
        for entry in value.split(','):
            start, end, step = CRON_ENTRY.match(entry).groups()
            low, high = (minimum, maximum) if start is None else (int(start), int(end or start))
            used.update(range(low, high + 1, int(step or 1)))
        used = sorted(used)
        gap = min([b - a for a, b in zip(used, used[1:])] + [used[0] - minimum + maximum - used[-1] + 1])
        if 0 < gap <= maximum:
            interval = gap * weight if interval is None else min(interval, gap * weight)
    return interval


def parse_crontab(text):
    """Jobs of a crontab with the SHELL in effect and Plesk's '#@desc:' description."""
    shell, description, jobs = '/bin/sh', None, []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith('#'):
            if line.startswith('#@desc:'):
                description = line[len('#@desc:'):].strip()
            continue
        variable = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)', line)
        if variable:
            if variable.group(1) == 'SHELL':
                shell = variable.group(2).strip().strip('"\'')
            continue
        if line.startswith('@'):
            parts = re.split(r'\s+', line, maxsplit=1)
            fields = CRON_MACROS.get(parts[0].lower(), '').split() or None
            command = parts[1] if len(parts) == 2 else ''
        else:
            parts = re.split(r'\s+', line, maxsplit=5)
            fields, command = (parts[:5], parts[5]) if len(parts) == 6 else (None, '')
        jobs.append({'schedule': fields, 'command': command.strip(), 'shell': shell, 'description': description})
        description = None
    return jobs


def shell_syntax(command):
    """True when sh would treat part of the command as more than plain words (or crontab as stdin: %)."""
    quote = None
    for char in command:
        if char == '%':
            return True
        if quote == "'":
            quote = None if char == "'" else quote
        elif quote == '"':
            if char == '"':
                quote = None
            elif char in '$`\\':
                return True
        elif char in '\'"':
            quote = char
        elif char in ';&|<>()$`*?[]{}~\\#!':
            return True
    return quote is not None


def webspace_path(value, *, home, chroot, entries):
    """Webspace-relative path of a command word ('.' = webspace root), or None when it is no webspace path.

    Plesk runs jobs in the webspace (relative paths) or, with the chroot shell, sees the webspace as /.
    """
    if value == home or value.startswith(home + '/'):
        relative = value[len(home):].strip('/')
    elif chroot and value.startswith('/') and value[1:].split('/', 1)[0] in entries:
        relative = value[1:]
    elif not value.startswith('/') and value.split('/', 1)[0] in entries:
        relative = value
    else:
        return None
    relative = os.path.normpath(relative) if relative else '.'
    return None if relative == '..' or relative.startswith('../') else relative


def plesk_cron_job(job, *, home, entries, folders):
    """A source cron job as reusable command words, its URL, or the reason it needs manual review.

    folders maps webspace-relative source folders to website folders ('httpdocs' → 'web'). The result
    has 'owner': 'site' (refers to this website), 'any' (no webspace path) or 'other' (another domain).
    """
    result = {'schedule': job['schedule'], 'source': job['command'], 'description': job['description']}
    if job['schedule'] is None:
        return dict(result, owner='any', reason='schedule ISPConfig cannot store (@reboot or malformed)')
    if not all(cron_field_valid(minimum, maximum, value) for (_, minimum, maximum, _), value in zip(CRON_FIELDS, job['schedule'])):
        return dict(result, owner='any', reason='schedule ISPConfig cannot store (names, */1 or unusual steps)')
    command, suffix = job['command'], ''
    match = CRON_REDIRECT.search(command)
    if match:
        command, suffix = command[:match.start()], match.group(0).strip()
    if not command.strip() or shell_syntax(command):
        return dict(result, owner='any', reason='shell syntax (pipes, variables, globs, quotes or %)')
    words = shlex.split(command)
    if os.path.basename(words[0]) in ('curl', 'wget'):
        urls = [word for word in words if re.match(r'https?://', word)]
        if len(urls) == 1:
            return dict(result, owner='url', url=urls[0])
        return dict(result, owner='any', reason='URL fetch with several or no URLs')
    chroot = job['shell'].endswith('chrootsh')
    mapped, unmapped = [], []
    for index, word in enumerate(words):
        if index == 0 and CRON_PHP.match(word):
            mapped.append({'php': word})
            continue
        option = re.match(r'(-{1,2}[A-Za-z][A-Za-z0-9_-]*=)(.+)\Z', word)
        prefix, value = option.groups() if option else ('', word)
        relative = webspace_path(value, home=home, chroot=chroot, entries=entries)
        if relative is None:
            mapped.append(word)
            continue
        target = next((folder + relative[len(source):] for source, folder in folders
                       if relative == source or relative.startswith(source + '/')), None)
        if target is None:
            unmapped.append(relative)
        mapped.append({'prefix': prefix, 'path': target} if target is not None else word)
    paths = [word for word in mapped if isinstance(word, dict) and 'path' in word]
    if unmapped and paths:
        return dict(result, owner='site', reason='refers to files that are not migrated: ' + ', '.join(unmapped))
    if unmapped:
        return dict(result, owner='other')
    return dict(result, owner='site' if paths else 'any', words=mapped, suffix=suffix)


def render_cron(job, *, document_root, cron_type, php_cli):
    """Command of an ISPConfig cron job: absolute paths for 'full', website-relative (/web/...) in the jail."""
    if 'url' in job:
        return job['url']
    words = []
    for word in job['words']:
        if isinstance(word, str):
            words.append(word)
        elif 'php' in word:
            words.append(php_cli)
        else:
            words.append(word['prefix'] + (document_root if cron_type == 'full' else '') + '/' + word['path'])
    return shlex.join(words) + (' ' + job['suffix'] if job['suffix'] else '')


def cron_decision(job, client):
    """None when the client's plan accepts the job, otherwise why it is left for manual review."""
    if 'reason' in job:
        return job['reason']
    limit = client.get('limit_cron_type') or 'url'
    if 'url' not in job and limit == 'url':
        return "the client's plan permits only URL cron jobs"
    frequency = int(client.get('limit_cron_frequency') or 0)
    interval = cron_interval(job['schedule'])
    if frequency > 1 and interval is not None and interval < frequency:
        return 'runs every %d minutes; the plan allows every %d minutes or less often' % (interval, frequency)
    return None


def plesk_rows(rows):
    grouped = {}
    for row in rows:
        grouped.setdefault(row['t'], []).append(row)
    return grouped


def plesk_site(rows, domain):
    """The Plesk domain to migrate, with website hosting in its webspace."""
    found = [row for row in plesk_rows(rows).get('domain', []) if str(row['name']).lower() == domain]
    require(len(found) == 1, 'The domain is not on the Plesk server: ' + domain)
    site = found[0]
    require(site['htype'] == 'vrt_hst' and site['www_root'] and site['home'] and site['login'],
            'The Plesk domain has no website hosting (forwarding or DNS/mail only)')
    require(not site['name'].startswith('_.'), 'This is the wildcard subdomain of a website; migrate its website')
    require(site['status'] == 0, 'The Plesk domain is suspended or disabled (status %s); do not activate it implicitly' % site['status'])
    home, root = site['home'].rstrip('/'), site['www_root'].rstrip('/')
    require(home.startswith('/') and os.path.normpath(home) == home and root.startswith(home + '/') and os.path.normpath(root) == root,
            'The document root is outside the webspace')
    relative = root[len(home) + 1:]
    require(FOLDER_PART.fullmatch(relative),
            'The document root %s is a subfolder of the webspace folder; such layouts are not supported yet' % root)
    return site


def plesk_inventory(rows, account, domain, databases=None):
    """Plesk metadata in the migration's inventory format: the website, its databases, aliases, subdomains and cron.

    databases names exactly which databases of the subscription to migrate; by default, those Plesk assigns to the domain.
    """
    site = plesk_site(rows, domain)
    grouped = plesk_rows(rows)
    domains = grouped.get('domain', [])
    home, root = site['home'].rstrip('/'), site['www_root'].rstrip('/')
    subscription_id = site['webspace_id'] or site['id']
    notes, children, wildcard = [], [], False
    # Plesk DNS zones of the website, its aliases (also those for mail/DNS only) and the subdomains migrated with it.
    zones = [{'id': site.get('dns_zone_id'), 'domain': domain, 'role': 'website'}]
    for child in sorted((row for row in domains if row['parent_id'] == site['id']), key=lambda row: row['name']):
        name = str(child['name']).lower()
        if child['htype'] != 'vrt_hst' or not child['www_root']:
            notes.append('Subdomain %s has no website hosting (forwarding); configure it by hand' % name)
            continue
        child_root = child['www_root'].rstrip('/')
        if child['status'] != 0:
            notes.append('Subdomain %s is disabled in Plesk and is not migrated' % name)
        elif name == '_.' + domain and child_root == root:
            wildcard = True
        elif name.startswith('_.'):
            notes.append('The wildcard subdomain *.%s has its own folder; configure it by hand' % domain)
        elif not name.endswith('.' + domain):
            notes.append('Subdomain %s does not end with %s; migrate it separately' % (name, domain))
        elif child_root == root:
            children.append({'domain_id': 's%d' % child['id'], 'domain': name, 'type': 'subdomain', 'subdomain': 'none',
                             'redirect_type': '', 'redirect_path': '', 'active': 'y'})
            zones.append({'id': child.get('dns_zone_id'), 'domain': name, 'role': 'subdomain'})
        elif child_root.startswith(root + '/') and all(FOLDER_PART.fullmatch(part) for part in child_root[len(root) + 1:].split('/')):
            children.append({'domain_id': 's%d' % child['id'], 'domain': name, 'type': 'vhostsubdomain', 'subdomain': 'www',
                             'web_folder': 'web/' + child_root[len(root) + 1:], 'php_version': plesk_php_version(child['php_handler']),
                             'redirect_type': '', 'redirect_path': '', 'active': 'y'})
            zones.append({'id': child.get('dns_zone_id'), 'domain': name, 'role': 'subdomain'})
        else:
            notes.append('Subdomain %s has its own folder outside the document root; migrate it separately '
                         '(ispcp-migrate --from plesk %s CLIENT_ID)' % (name, name))
    for alias in sorted((row for row in grouped.get('alias', []) if row['dom_id'] == site['id']), key=lambda row: row['name']):
        name = str(alias['name']).lower()
        zones.append({'id': alias.get('dns_zone_id'), 'domain': name, 'role': 'alias'})
        if alias['web'] != 'true':
            notes.append('Alias %s is not used for the website (mail/DNS only) and is not migrated' % name)
            continue
        redirect = alias['seo_redirect'] == 'true'
        children.append({'domain_id': 'a%d' % alias['id'], 'domain': name, 'type': 'alias', 'subdomain': 'www',
                         'redirect_type': 'R=301,L' if redirect else '', 'redirect_path': '[scheme]://%s/' % domain if redirect else '',
                         'active': 'y' if alias['status'] == 0 else 'n'})
    by_id = {row['id']: row for row in domains}

    def with_parent(row):
        """A subdomain that is migrated together with its parent website (same folder or inside its document root)."""
        parent = by_id.get(row['parent_id'])
        if not parent or parent['htype'] != 'vrt_hst' or not parent['www_root'] or not row['www_root']:
            return False
        parent_root, child_root = parent['www_root'].rstrip('/'), row['www_root'].rstrip('/')
        return child_root == parent_root or child_root.startswith(parent_root + '/')

    others = sorted(str(row['name']).lower() for row in domains if row['id'] != site['id'] and row['htype'] == 'vrt_hst'
                    and (row['webspace_id'] or row['id']) == subscription_id and not str(row['name']).startswith('_.')
                    and row['parent_id'] != site['id'] and not with_parent(row))
    if others:
        notes.append('Other websites of this Plesk subscription, migrated separately: ' + ', '.join(others))
    servers = {row['id']: row for row in grouped.get('dbserver', [])}
    charsets = {row['name']: row['charset'] for row in grouped.get('charset', [])}
    users = grouped.get('dbuser', [])
    subscription = {row['id'] for row in domains if (row['webspace_id'] or row['id']) == subscription_id}
    if databases is None:
        selected = [row for row in grouped.get('database', []) if row['dom_id'] == site['id']]
    else:
        available = {row['name']: row for row in grouped.get('database', []) if row['dom_id'] in subscription}
        missing = sorted(set(databases) - set(available))
        require(not missing, 'Not a database of this Plesk subscription: %s (available: %s)' % (
            ', '.join(missing), ', '.join(sorted(available)) or 'none'))
        selected = [available[name] for name in sorted(set(databases))]
    assigned = sorted(row['name'] for row in grouped.get('database', []) if row['dom_id'] in subscription
                      and row['dom_id'] != site['id'] and row not in selected)
    if assigned:
        notes.append('Databases of other websites of the subscription, not migrated (select with --database): ' + ', '.join(assigned))
    databases = []
    for db in sorted(selected, key=lambda row: row['name']):
        server = servers.get(db['server_id'], {})
        require(db['type'] == 'mysql' and server.get('type') == 'mysql' and server.get('host') in ('localhost', '127.0.0.1'),
                'Database %s is not on the local MySQL server of Plesk; only local MySQL/MariaDB databases are supported' % db['name'])
        require(re.fullmatch(r'[A-Za-z0-9_-]{1,64}', db['name']), 'Unsupported Plesk database name: ' + str(db['name']))
        own = [user for user in users if user['db_id'] == db['id']]
        shared = [user for user in users if user['db_id'] == 0 and user['dom_id'] == subscription_id]
        default = [user['login'] for user in own + shared if user['id'] == db['default_user_id']]
        logins = sorted({user['login'] for user in own + shared})
        if not logins:
            notes.append('Database %s has no Plesk user; applications must use the new database user' % db['name'])
        databases.append({'database_id': db['id'], 'server_id': db['server_id'], 'database_name': db['name'],
                          'database_charset': charsets.get(db['name']) or '', 'type': 'mysql', 'active': 'y',
                          'database_user': (default or [user['login'] for user in own] or logins or [''])[0], 'database_users': logins})
    folder = root[len(home) + 1:]
    other_folders = {str(row['www_root']).rstrip('/')[len(home) + 1:].split('/', 1)[0] for row in domains
                     if row['id'] != site['id'] and str(row['www_root'] or '').startswith(home + '/')}
    entries = sorted(set(account['entries']))
    cron, seen = [], set()
    skipped_cron = wordpress_cron = 0
    for job in parse_crontab(account['crontab']):
        result = plesk_cron_job(job, home=home, entries=entries, folders=[(folder, 'web')])
        owner = result.pop('owner')
        if owner == 'url':
            host = urllib.parse.urlsplit(result['url']).hostname or ''
            names = {domain} | {child['domain'] for child in children}
            owner = 'site' if host.lower() in names | {'www.' + name for name in names} else 'any'
        # Jobs of the whole subscription (no paths) belong to its main website.
        if not (owner == 'site' or owner == 'any' and not site['webspace_id'] and not site['parent_id']):
            skipped_cron += 1
            continue
        if WORDPRESS_CRON.search(job['command']):
            wordpress_cron += 1
            continue
        # The same job twice (often with two PHP versions) would run twice on the new website.
        key = json.dumps([result['schedule'], result.get('url'), result.get('suffix'), result.get('reason') and result['source'],
                          [word if isinstance(word, str) or 'path' in word else 'php' for word in result.get('words', [])]])
        if key in seen:
            notes.append('Duplicate cron job skipped: ' + result['source'])
            continue
        seen.add(key)
        cron.append(result)
    if skipped_cron:
        notes.append('%d cron job(s) of other websites of the subscription are left to their own migration' % skipped_cron)
    if wordpress_cron:
        notes.append('WordPress cron (WP Toolkit, %d job(s) running wp-cron.php) is not migrated: turn on the WordPress cron '
                     "in the panel's WordPress tools after the DNS switch. WP Toolkit usually disables WordPress's own cron "
                     '(DISABLE_WP_CRON), so scheduled WordPress tasks wait until then.' % wordpress_cron)
    return {
        'source': 'plesk',
        'site': {'domain_id': site['id'], 'server_id': 'plesk', 'domain': domain, 'type': 'vhost', 'document_root': home,
                 'www_root': root, 'system_user': site['login'], 'system_group': account['group'], 'uid': account['uid'],
                 'gid': account['gid'], 'php': 'php-fpm', 'php_handler': site['php_handler'],
                 'php_version': plesk_php_version(site['php_handler']), 'server_php_id': 0,
                 'subdomain': '*' if wildcard else 'www', 'active': 'y',
                 'subscription': next(str(row['name']) for row in domains if row['id'] == subscription_id)},
        'databases': databases, 'children': children, 'cron': cron, 'notes': notes,
        'not_copied': [entry for entry in entries if entry != folder and entry not in PLESK_SYSTEM_ENTRIES and entry not in other_folders],
        'servers': [], 'dns_zones': [zone for zone in zones if zone['id']],
    }


def plesk_sites_inventory(rows, host):
    """`plesk db` rows in the --sites inventory format of the old ISPConfig panel."""
    grouped = plesk_rows(rows)
    domains = {row['id']: row for row in grouped.get('domain', [])}
    websites = []
    for row in sorted(domains.values(), key=lambda row: row['id']):
        if row['htype'] == 'none' or str(row['name']).startswith('_.'):
            continue
        parent = domains.get(row['parent_id'])
        shared = parent is not None and parent['htype'] == 'vrt_hst' and row['www_root'] and row['www_root'] == parent['www_root']
        kind = 'subdomain' if shared else 'vhostsubdomain' if row['parent_id'] else 'vhostalias' if row['webspace_id'] else 'vhost'
        websites.append({
            'domain_id': row['id'], 'server_id': 1, 'domain': str(row['name']).lower(), 'type': kind,
            'parent_domain_id': row['parent_id'] or row['webspace_id'] or 0, 'subdomain': 'www',
            'active': 'y' if row['status'] == 0 else 'n', 'document_root': row['www_root'] or '',
            'redirect_path': None if row['htype'] == 'vrt_hst' else 'forwarding',
            'client_username': row['client'], 'client_company': row['company'], 'client_contact': row['contact']})
    for alias in grouped.get('alias', []):
        if alias['web'] == 'true' and alias['dom_id'] in domains:
            websites.append({'domain_id': 'a%d' % alias['id'], 'server_id': 1, 'domain': str(alias['name']).lower(), 'type': 'alias',
                             'parent_domain_id': alias['dom_id'], 'subdomain': 'www', 'active': 'y' if alias['status'] == 0 else 'n',
                             'document_root': ''})
    databases = {}
    for db in grouped.get('database', []):
        databases[str(db['dom_id'])] = databases.get(str(db['dom_id']), 0) + 1
    traffic = {str(domains[row['dom_id']]['name']).lower(): int(row['bytes'] or 0)
               for row in grouped.get('traffic', []) if row['dom_id'] in domains}
    return {'websites': websites, 'databases': databases, 'servers': [{'server_id': 1, 'server_name': host}],
            'ips': [{'server_id': 1, 'ip_address': row['address']} for row in grouped.get('ip', [])], 'traffic': traffic}


def select_source(config, name):
    """The configuration of one migration: "source" or the named entry of "sources" (never part of the state fingerprint)."""
    selected = {key: value for key, value in config.items() if key != 'sources'}
    if name:
        sources = config.get('sources')
        require(isinstance(sources, dict) and isinstance(sources.get(name), dict),
                'The configuration has no source "%s" under "sources"' % name)
        selected['source'] = sources[name]
    return selected


# Configuration files that commonly hold absolute paths; PHP files only directly in the document root.
PATH_FILES = frozenset(('.htaccess', '.user.ini', 'php.ini', '.env', 'wp-config.php', 'wordfence-waf.php'))


def old_path_references(tree, old_root, limit=200):
    """Staged configuration files that still name the old webspace (reported, never changed)."""
    needle = (old_root.rstrip('/') + '/').encode()
    found = []
    for directory, dirs, files in os.walk(tree, followlinks=False):
        dirs.sort()
        for name in sorted(files):
            path = Path(directory) / name
            top = path.parent == Path(tree) / 'web'
            if name not in PATH_FILES and not (top and name.endswith(('.php', '.ini'))):
                continue
            with contextlib.suppress(OSError):
                if path.is_file() and not path.is_symlink() and path.stat().st_size <= MB and needle in path.read_bytes():
                    found.append(str(path.relative_to(tree)))
            if len(found) >= limit:
                return found
    return found


# --- DNS zones of a Plesk website ------------------------------------------------------------
# Plesk's transfer ACL and secondary-zone rows are no zone data.
PLESK_DNS_SKIP = frozenset(('AXFR', 'master', 'none'))
# Longest record name ISPConfig accepts per type (legacy dns_a/dns_aaaa forms); others take 255.
DNS_NAME_LIMIT = {'A': 64, 'AAAA': 64}


def dns_record_name(host, origin, kind):
    """The record name for the API: absolute like Plesk's, relative when that is too long for the type, or None."""
    limit = DNS_NAME_LIMIT.get(kind, 255)
    if len(host) + 1 <= limit:
        return host + '.'
    relative = host[:-len(origin) - 1] if host != origin else ''
    return relative if relative and len(relative) <= limit else None


# ISPConfig keeps SPF, DMARC and DKIM in TXT rows but accepts them only as those record types (the API refuses TXT
# data containing these markers, like ISPConfig's forms); SPF and DMARC are composed from fields.
SPF_ALL = {'-all': 'fail', '~all': 'softfail', '?all': 'neutral'}
DMARC_POLICIES = ('none', 'quarantine', 'reject')


def spf_fields(text):
    """API fields of an SPF record that ISPConfig's SPF record can hold: pass mechanisms a, mx, ip4, ip6, a:HOST and
    include:DOMAIN, ended by -all, ~all or ?all. None for anything else (ptr, exists, redirect=, +all, other qualifiers)."""
    tokens = text.split()
    if len(tokens) < 2 or tokens[0] != 'v=spf1':
        return None
    fields, lists, policy = {'allow_mx': False, 'allow_a': False}, {'ipv4_address': [], 'ipv6_address': [], 'hostname': [], 'include': []}, None
    for token in tokens[1:]:
        if policy is not None:
            return None  # nothing may follow "all"
        if token.lower() in SPF_ALL:
            policy = SPF_ALL[token.lower()]
            continue
        bare = token[1:] if token.startswith('+') else token
        kind, _, value = bare.partition(':')
        kind = kind.lower()
        if kind in ('mx', 'a') and not value:
            fields['allow_' + kind] = True
        elif kind in ('ip4', 'ip6') and value:
            try:
                network = ipaddress.ip_interface(value)
            except ValueError:
                return None
            if network.version != (4 if kind == 'ip4' else 6):
                return None
            lists['ipv4_address' if kind == 'ip4' else 'ipv6_address'].append(value)
        elif kind == 'a' and re.fullmatch(r'[a-zA-Z0-9.*-]{1,64}', value):
            lists['hostname'].append(value)
        elif kind == 'include' and re.fullmatch(r'[_a-zA-Z0-9.*-]{1,64}', value):
            lists['include'].append(value)
        else:
            return None
    if policy is None:
        return None
    fields.update({key: ' '.join(values) for key, values in lists.items() if values})
    fields['policy'] = policy
    return fields


def spf_text(fields):
    """The SPF text ISPConfig composes from the fields (DnsRecordMetaService::composeSpf)."""
    tokens = (['mx'] if fields['allow_mx'] else []) + (['a'] if fields['allow_a'] else [])
    for key, prefix in (('ipv4_address', 'ip4:'), ('ipv6_address', 'ip6:'), ('hostname', 'a:'), ('include', 'include:')):
        tokens += [prefix + value for value in fields.get(key, '').split()]
    return 'v=spf1 ' + ' '.join(tokens + [{'fail': '-', 'softfail': '~', 'neutral': '?'}[fields['policy']] + 'all'])


def dmarc_fields(text):
    """API fields of a DMARC record with only the tags ISPConfig's DMARC record holds (p, sp, rua, ruf, adkim, aspf, pct)."""
    tags = [part.strip() for part in text.split(';')]
    if tags[0].replace(' ', '') != 'v=DMARC1':
        return None
    found = {}
    for tag in filter(None, tags[1:]):
        name, equals, value = (part.strip() for part in tag.partition('='))
        name = name.lower()
        if not equals or name in found or name not in ('p', 'sp', 'rua', 'ruf', 'adkim', 'aspf', 'pct'):
            return None
        found[name] = value
    fields = {'policy': found.pop('p', '').lower()}
    if fields['policy'] not in DMARC_POLICIES:
        return None
    for name, value in found.items():
        lower = value.lower()
        if name == 'sp' and lower in DMARC_POLICIES or name in ('adkim', 'aspf') and lower in ('r', 's'):
            fields[name] = lower
        elif name == 'pct' and value.isdigit() and int(value) <= 100:
            fields[name] = int(value)
        elif name in ('rua', 'ruf') and all(re.fullmatch(r'mailto:[^\s,;!@]+@[a-zA-Z0-9.-]+', address.strip())
                                              for address in value.split(',')):
            fields[name] = ','.join(address.strip() for address in value.split(','))
        else:
            return None
    return fields


def dmarc_text(fields):
    """The DMARC text ISPConfig composes from the fields (DnsRecordMetaService::composeDmarc)."""
    tags = ['p=' + fields['policy']]
    tags += ['%s=%s' % (name, fields[name]) for name in ('rua', 'ruf') if fields.get(name)]
    tags += ['%s=%s' % (name, fields[name]) for name in ('adkim', 'aspf') if fields.get(name, 'r') != 'r']
    tags += ['pct=%d' % fields['pct']] if fields.get('pct', 100) != 100 else []
    tags += ['sp=' + fields['sp']] if fields.get('sp') else []
    return 'v=DMARC1; ' + '; '.join(tags)


def record_value(record):
    """The value of a record body for messages, as in a zone file."""
    kind = record['type']
    if kind == 'SPF':
        return spf_text(record)
    if kind == 'DMARC':
        return dmarc_text(record)
    if kind == 'MX':
        return '%d %s' % (record['priority'], record['hostname'])
    if kind == 'SRV':
        return '%d %d %d %s' % (record['priority'], record['weight'], record['port'], record['hostname'])
    return record.get('data', '')


def nova_zone(zone, records, *, plesk_addresses, ipv4, ipv6, nameservers):
    """The new ISPConfig zone of one Plesk zone: everything is copied, except that the new DNS server's name servers
    replace Plesk's (NS and SOA) and A/AAAA records with an address of the Plesk server get the new web server's.

    zone/records are `plesk db` rows (settings in seconds, record ttl NULL = zone default). The result has the
    zone body (created inactive), the record bodies, the remapped names, SPF/DMARC texts ISPConfig writes differently
    (same meaning, its own order) and the records left for the operator.
    """
    origin = str(zone['name']).strip().lower().rstrip('.')

    def host_of(row):
        return str(row['host']).strip().lower().rstrip('.')

    default_ttl = max(int(zone['ttl'] or 3600), 60)
    plesk_ns = {str(row['val']).strip().lower().rstrip('.') for row in records if row['type'] == 'NS' and host_of(row) == origin}
    created, remapped, rewritten, manual, dmarc, seen = [], [], [], [], [], set()

    def add(record):
        key = json.dumps(record, sort_keys=True)
        if key not in seen:
            seen.add(key)
            created.append(record)

    for server in nameservers:
        add({'type': 'NS', 'name': origin + '.', 'data': server + '.', 'ttl': default_ttl, 'active': True})
    for row in sorted(records, key=lambda row: (host_of(row), str(row['type']), str(row['val']), row['id'])):
        kind, host, value = str(row['type']), host_of(row), str(row['val']).strip()
        option = str(row.get('opt') or '').strip()
        shown = '%s %s %s' % (host, kind, value if len(value) <= 60 else value[:57] + '...')
        if kind in PLESK_DNS_SKIP:
            continue
        if host != origin and not host.endswith('.' + origin):
            manual.append(shown + ' (outside the zone)')
            continue
        name = dns_record_name(host, origin, kind)
        if name is None:
            manual.append(shown + ' (name too long for ISPConfig)')
            continue
        ttl = default_ttl if row.get('ttl') in (None, '') else max(int(row['ttl']), 60)
        base = {'name': name, 'ttl': ttl, 'active': True}
        target = value.lower().rstrip('.')
        if kind == 'NS':
            if host == origin:
                continue  # the zone's own name servers: the new DNS server's, added above
            # A subzone delegated to the Plesk name servers moves to the new DNS server too.
            for server in nameservers if target in plesk_ns else [target]:
                add(dict(base, type='NS', data=server + '.'))
        elif kind in ('A', 'AAAA'):
            address = ip_text(value)
            if address is None or (':' in address) != (kind == 'AAAA'):
                manual.append(shown + ' (not an %s address)' % ('IPv6' if kind == 'AAAA' else 'IPv4'))
                continue
            # The addresses of the Plesk name servers themselves stay (glue of ns.* in the provider's zone).
            if address in plesk_addresses and host not in plesk_ns:
                new = ipv6 if kind == 'AAAA' else ipv4
                if new is None:
                    manual.append(shown + ' (the new web server has no %s address)' % ('IPv6' if kind == 'AAAA' else 'IPv4'))
                    continue
                remapped.append({'name': host, 'type': kind, 'old': address, 'new': new})
                address = new
            add(dict(base, type=kind, data=address))
        elif kind == 'CNAME' and target:
            add(dict(base, type='CNAME', data=target + '.'))
        elif kind == 'MX' and target and option.isdigit():
            add(dict(base, type='MX', hostname=target + '.', priority=int(option)))
        elif kind == 'SRV' and target and len(option.split()) == 3 and all(part.isdigit() for part in option.split()):
            priority, weight, port = (int(part) for part in option.split())
            add(dict(base, type='SRV', priority=priority, weight=weight, port=port, hostname=target + '.'))
        elif kind == 'TXT' and value and not any(char in value for char in '"\\\r\n'):
            if 'v=DKIM' in value:
                add(dict(base, type='DKIM', data=value))  # stored verbatim
            elif 'v=spf' in value or 'v=DMARC1; ' in value:
                spf = 'v=spf' in value
                fields = spf_fields(value) if spf else dmarc_fields(value) if host == '_dmarc.' + origin else None
                if fields is None:
                    manual.append(shown + (' (SPF that ISPConfig cannot hold as is)' if spf else
                                           ' (DMARC that ISPConfig cannot hold as is)'))
                    continue
                text = spf_text(fields) if spf else dmarc_text(fields)
                change = {'name': host, 'old': value, 'new': text} if text != value else None
                if spf:
                    add(dict(base, type='SPF', **fields))
                    rewritten += [change] if change else []
                else:
                    dmarc.append((dict(base, type='DMARC', **fields), shown, change))
            else:
                add(dict(base, type='TXT', data=value))
        else:
            manual.append(shown + (' (%s records are not copied)' % kind if kind not in ('CNAME', 'MX', 'SRV', 'TXT')
                                   else ' (value ISPConfig does not accept as is)'))
    # ISPConfig creates a DMARC record only next to an active DKIM record and the domain's one SPF record (legacy
    # dns_dmarc_edit.php), so it comes last, or is left to the operator when the zone cannot have it.
    dkim = any(record['type'] == 'DKIM' and '._domainkey' in record['name'] or
               record['type'] == 'CNAME' and '._domainkey' in record['name'] for record in created)
    spf = sum(record['type'] == 'SPF' and record['name'] == origin + '.' for record in created)
    for record, shown, change in dmarc:
        if dkim and spf == 1:
            add(record)
            rewritten += [change] if change else []
        else:
            manual.append(shown + (' (ISPConfig accepts DMARC only in a zone with a DKIM record)' if not dkim else
                                   ' (ISPConfig accepts DMARC only next to exactly one SPF record of the domain)'))
    email = str(zone.get('email') or '').strip().lower()
    mailbox = email if re.fullmatch(r'[a-z0-9_+-]+(?:\.[a-z0-9_+-]+)*@[a-z0-9-]+(?:\.[a-z0-9-]+)+', email) else 'hostmaster@' + origin
    soa = {'origin': origin + '.', 'ns': nameservers[0] + '.', 'mbox': mailbox.replace('@', '.') + '.', 'ttl': default_ttl,
           'refresh': max(int(zone['refresh']), 60), 'retry': max(int(zone['retry']), 60), 'expire': max(int(zone['expire']), 60),
           'minimum': max(int(zone['minimum']), 60), 'active': False}
    return {'origin': origin, 'soa': soa, 'records': created, 'remapped': remapped, 'rewritten': rewritten, 'manual': manual}


class Migration:
    kind = 'ispconfig'
    dns = True  # Plesk: recreate the website's DNS zones on the new DNS server (--no-dns: not)
    key_active = False  # the client-bound key is switched on

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
        self.databases = None  # --database NAME (Plesk): exactly these databases of the subscription
        self.resolvers = [(address, 53) for address in DNS_RESOLVERS]
        self.directory = private_directory(state_dir)
        self.file = self.directory / 'state.json'
        self.domain = domain_name(domain)
        self.client_id = int(client_id)
        require(self.client_id > 0, 'client-id is the new ISPConfig client ID, not the WHMCS customer ID')
        self.kind = self.source.get('type', 'ispconfig')
        require(self.kind in SOURCE_TYPES, 'source.type must be ispconfig or plesk')
        if self.kind == 'plesk':
            require(set(self.source) == {'type', 'ssh'}, 'A Plesk source has exactly "type": "plesk" and "ssh": "root@PLESK-HOST"')
            hosts = [self.source['ssh']]
        else:
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
            hosts = [self.source['panel_ssh'], self.source['web_ssh']] + list(self.source.get('db_ssh', {}).values())
        for host in hosts + [self.target['web_ssh'], self.target['db_ssh']]:
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

    def plesk(self, request, *, output=None, log='plesk-source.log'):
        """One read-only plesk-source.py action over root SSH; its messages stay in the private log."""
        return execute(plesk_command(self.source['ssh']), data=(json.dumps(request) + '\n').encode(),
                       output=output, error_path=self.directory / log)

    def source_inventory(self):
        require(self.databases is None or self.kind == 'plesk', '--database selects databases of a Plesk subscription (--from plesk)')
        if self.kind == 'plesk':
            self.state['plesk'] = json.loads(self.plesk({'action': 'check'}))
            rows = json.loads(self.plesk({'action': 'inventory'}))['rows']
            site = plesk_site(rows, self.domain)
            account = json.loads(self.plesk({'action': 'account', 'login': site['login'], 'home': site['home'].rstrip('/')}))
            return plesk_inventory(rows, account, self.domain, self.databases)
        inventory = json.loads(execute(php_remote(self.source['panel_ssh'], 'source-inventory.php'),
                                       data=(json.dumps({'domain': self.domain}) + '\n').encode(),
                                       error_path=self.directory / 'source-inventory.log'))
        atomic_json(self.directory / 'inventory.json', inventory)
        validate_inventory(inventory, self.domain)
        return inventory

    def link_roots(self):
        """Old absolute paths and the staged folder that holds them, for normalize_links."""
        site = self.state['inventory']['site']
        return [(site['www_root'], 'web')] if self.kind == 'plesk' else [(site['document_root'], '')]

    def php_cli(self, php):
        """PHP CLI of the new website's PHP version for its cron jobs (server default: php)."""
        if not php['server_php_id']:
            return '/usr/bin/php'
        rows = self.admin.all('/servers/%d/php-versions' % self.target['web_server_id'])
        found = [row.get('php_cli_binary') for row in rows if int(row.get('id') or 0) == php['server_php_id']]
        return found[0] if found and found[0] else '/usr/bin/php'

    def cron_plan(self, inventory, client, php):
        """Source cron jobs the client's plan accepts, created inactive; the others are listed for review."""
        cli = self.php_cli(php) if inventory.get('cron') else '/usr/bin/php'
        cron_type = 'full' if client.get('limit_cron_type') == 'full' else 'chrooted'
        plan = []
        for job in inventory.get('cron', []):
            reason = cron_decision(job, client)
            plan.append(dict(job, create=reason is None, reason=reason, type='url' if 'url' in job else cron_type, php_cli=cli))
        return plan

    def web_command(self, argv):
        return argv if self.local_web else remote(self.target['web_ssh'], argv)

    def check_web_server(self):
        argv = ['php', '-d', 'display_errors=stderr', str(HERE / 'server-check.php')] if self.local_web else \
            php_remote(self.target['web_ssh'], 'server-check.php')
        execute(argv, data=(json.dumps({'server_id': self.target['web_server_id']}) + '\n').encode(),
                error_path=self.directory / 'server-check.log')

    def select_php(self):
        """PHP of the new website: --php VERSION, the version chosen by an earlier run, the Plesk website's own version,
        or target.server_php_id. A Plesk subdomain with its own folder keeps its own version (--php sets all)."""
        site = self.state['objects'].get('site', {}).get('record')
        rows = None
        if self.kind == 'plesk' and site is None:
            inventory = self.state['inventory']
            if not self.php_version and 'php' not in self.state and inventory['site'].get('php_version'):
                # The same PHP as on Plesk, e.g. alt-php74-fpm -> 7.4.
                rows = self.admin.all('/servers/%d/php-versions' % self.target['web_server_id'])
                version = inventory['site']['php_version']
                try:
                    php_id = php_configuration(rows, version, self.client_id)
                except MigrationError as exc:
                    raise MigrationError('The Plesk website runs PHP %s (%s), which the new web server does not offer: %s. Choose '
                                         'another version with --php VERSION.' % (version, inventory['site']['php_handler'], exc)) from None
                self.state['php'] = {'version': version, 'server_php_id': php_id, 'source': 'plesk'}
        if self.php_version:
            rows = rows or self.admin.all('/servers/%d/php-versions' % self.target['web_server_id'])
            chosen = {'version': self.php_version, 'server_php_id': php_configuration(rows, self.php_version, self.client_id)}
            if site is not None:
                require(int(site.get('server_php_id') or 0) == chosen['server_php_id'],
                        'The website was already created with PHP configuration ID %s; change its PHP version in '
                        'ISPConfig or WHMCS, then repeat the command without --php.' % site.get('server_php_id'))
            self.state['php'] = chosen
        if self.kind == 'plesk' and site is None:
            self.state['php_children'] = self.child_php(rows)
        if site is not None:
            return {'version': self.state.get('php', {}).get('version'), 'server_php_id': int(site.get('server_php_id') or 0)}
        return self.state.get('php', {'version': None, 'server_php_id': self.target.get('server_php_id', 0)})

    def child_php(self, rows=None):
        """PHP of the Plesk subdomains with their own folder whose Plesk version differs from the website's.

        Without --php each keeps its Plesk version; one the new web server does not offer gets the website's PHP
        (server_php_id None, listed in the plan).
        """
        website = (self.state.get('php') or {}).get('version')
        result = {}
        for child in self.state['inventory']['children']:
            version = child.get('php_version')
            if self.php_version or child['type'] != 'vhostsubdomain' or not version or version == website:
                continue
            rows = rows or self.admin.all('/servers/%d/php-versions' % self.target['web_server_id'])
            try:
                php_id = php_configuration(rows, version, self.client_id)
            except MigrationError:
                php_id = None
            result[str(child['domain_id'])] = {'version': version, 'server_php_id': php_id}
        return result

    def usage_summary(self):
        return self.admin.get('/usage/summary?client_id=' + str(self.client_id))

    def needed_counts(self):
        """Objects this migration still has to create, per client count limit."""
        objects = self.state['objects']
        inventory = self.state['inventory']
        children = [child for child in inventory['children'] if 'child:' + str(child['domain_id']) not in objects]
        databases = [db['database_name'] for db in inventory['databases']]
        counts = {
            'web_domains': 0 if 'site' in objects else 1,
            'web_alias_domains': sum(child['type'] == 'alias' for child in children),
            'web_subdomains': sum(child['type'] in ('subdomain', 'vhostsubdomain') for child in children),
            'database_users': sum('user:' + name not in objects for name in databases),
            'databases': sum('db:' + name not in objects for name in databases),
        }
        if self.state.get('cron_jobs'):
            counts['cron_jobs'] = sum(job['create'] and 'cron:%d' % index not in objects
                                      for index, job in enumerate(self.state['cron_jobs']))
        counts.update(self.dns_counts())
        return counts

    def dns_counts(self):
        """DNS zones and records this migration still has to create."""
        plan = self.state.get('dns') if self.dns else None
        if not plan or plan.get('done'):
            return {}
        objects = self.state['objects']
        return {'dns_zones': sum('zone:' + zone['origin'] not in objects for zone in plan['zones']),
                'dns_records': sum('rr:%s:%d' % (zone['origin'], index) not in objects and index not in zone.get('rejected', [])
                                   for zone in plan['zones'] for index in range(len(zone['records'])))}

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
        if self.state['inventory']['site'].get('subdomain') == '*' and 'site' not in self.state['objects']:
            client = self.admin.get('/clients/' + str(self.client_id))
            require(client.get('limit_wildcard') in (True, 'y'),
                    'The old website also serves *.%s (wildcard subdomain), which the client\'s plan does not allow. '
                    'Enable wildcard subdomains for the client (limit_wildcard), then repeat the command.' % self.domain)
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
        if self.kind == 'plesk':
            site = inventory['site']
            names = [db['database_name'] for db in inventory['databases']]
            result = json.loads(self.plesk({'action': 'size', 'login': site['system_user'], 'paths': [site['www_root']],
                                            'databases': names}, log='source-size.log'))
            require(set(result['databases']) == set(names), 'Could not measure the source databases')
            return {'web_bytes': int(result['paths'][site['www_root']]),
                    'databases': {name: int(result['databases'][name]) for name in names}}
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
        inventory = self.source_inventory()
        if self.kind == 'plesk':
            atomic_json(self.directory / 'inventory.json', inventory)
            checks = [(self.target['db_ssh'], self.target['db_server_id'])]
        else:
            routes = [self.source_database_route(db, inventory) for db in inventory['databases']]
            checks = [(self.source['web_ssh'], inventory['site']['server_id']), (self.target['db_ssh'], self.target['db_server_id'])] + [
                (host, request['server_id']) for host, request in routes]
        self.check_web_server()
        for host, server_id in checks:
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
            previous = self.state['inventory']
            # Plesk changes crontabs and notes by itself (WP Toolkit); only what identifies created objects must stay.
            fixed = ('source', 'site', 'databases', 'children') if self.kind == 'plesk' else tuple(set(previous) | set(inventory))
            require({key: inventory.get(key) for key in fixed} == {key: previous.get(key) for key in fixed},
                    'Source inventory changed; review it before continuing this migration')
            if self.kind == 'plesk' and inventory['cron'] != previous['cron'] \
                    and any(name.startswith('cron:') for name in self.state['objects']):
                print('WARNING: the Plesk cron jobs changed after they were created on the new website; '
                      'the created jobs are kept, compare them with Plesk.')
                inventory = dict(inventory, cron=previous['cron'])
        for name, entry in self.state['objects'].items():
            require('record' in entry, 'Uncertain previous POST for %s. Reconcile the API receipt in state.json before retrying; never delete state blindly.' % name)
        self.state['inventory'] = inventory
        self.state['client_label'] = client.get('username', '')
        self.state['source_size'] = self.measure_source(inventory)
        php = self.select_php()
        self.state['cron_jobs'] = self.cron_plan(inventory, client, php) if self.kind == 'plesk' else []
        if self.kind == 'plesk' and self.dns:
            self.prepare_dns()
        self.preflight()
        staging, free = self.check_free_space()
        quotas, sizes = self.state['quotas'], self.state['source_size']

        def mb(value):
            return 'unlimited' if value == -1 else '%d MB' % value

        print('PLAN: %s → ISPConfig client %s (%s)' % (self.domain, self.client_id, self.state['client_label']))
        site = inventory['site']
        if self.kind == 'plesk':
            print('Source: Plesk %s on %s, subscription %s, read as its system user %s' % (
                self.state['plesk']['version'].split()[0], self.source['ssh'], site['subscription'], site['system_user']))
            print('Web: %s → web/ on %s' % (site['www_root'], self.target['web_ssh']))
        else:
            print('Web: %s:%s → %s' % (self.source['web_ssh'], site['document_root'], self.target['web_ssh']))
        print('PHP: ' + ('%s (configuration ID %d)' % (php['version'], php['server_php_id']) if php['version'] else
                         'configuration ID %d' % php['server_php_id'] if php['server_php_id'] else 'server default'))
        if self.kind == 'plesk':
            hint = '' if php['version'] == site['php_version'] or not site['php_version'] else '; keep it with --php ' + site['php_version']
            print('Source PHP: %s (%s)%s' % (site['php_version'] or 'unknown', site['php_handler'],
                                             '; the same on the new website' if site['php_version'] and php['version'] == site['php_version']
                                             else hint))
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
        if self.kind == 'plesk':
            self.print_plesk_plan(inventory)
        else:
            if inventory['children']:
                print('Shared-root aliases/subdomains: ' + ', '.join(child['domain'] for child in inventory['children']))
            print('WHMCS product/Create, mail, DNS, certificates and cron jobs remain operator steps.')
        print('Plan only: no writes to source or target servers. State: ' + str(self.directory))

    def print_plesk_plan(self, inventory):
        site = inventory['site']
        if site['subdomain'] == '*':
            print('Wildcard: *.%s is served by the website (ISPConfig subdomain *)' % self.domain)
        aliases = [child for child in inventory['children'] if child['type'] == 'alias']
        if aliases:
            print('Aliases: ' + ', '.join(child['domain'] + (' (301 to %s)' % self.domain if child['redirect_type'] else '')
                                          + ('' if child['active'] == 'y' else ' (inactive)') for child in aliases))
        subdomains = [child for child in inventory['children'] if child['type'] != 'alias']
        php = self.state.get('php_children', {})

        def folder(child):
            own = php.get(str(child['domain_id']))
            if own is None:
                return ' (%s)' % child['web_folder']
            if own['server_php_id'] is None:
                return " (%s; PHP %s of Plesk is not on the new web server: the website's PHP)" % (child['web_folder'], own['version'])
            return ' (%s, PHP %s)' % (child['web_folder'], own['version'])
        if subdomains:
            print('Subdomains: ' + ', '.join(child['domain'] + (folder(child) if child['type'] == 'vhostsubdomain' else ' (same folder)')
                                             for child in subdomains))
        jobs = self.state['cron_jobs']
        if jobs:
            print('Cron jobs (%d created INACTIVE: enable them after the DNS switch):' % sum(job['create'] for job in jobs))
            for job in jobs:
                schedule = ' '.join(job['schedule'] or ['?'])
                if job['create']:
                    command = render_cron(job, document_root='<website root>', cron_type=job['type'], php_cli=job['php_cli'])
                    print('  %s  %s' % (schedule, command))
                else:
                    print('  MANUAL %s  %s (%s)' % (schedule, job['source'], job['reason']))
        if inventory['not_copied']:
            print('Not copied from the Plesk webspace (outside the document root): ' + ', '.join(inventory['not_copied']))
        for note in inventory['notes']:
            print('Note: ' + note)
        if self.dns:
            self.print_dns_plan(self.state['dns'], when='when the copy is complete')
        else:
            print('DNS zones: not created (--no-dns)')
        print('WHMCS product/Create, mail, the DNS switch and certificates remain operator steps; '
              'PHP settings of the Plesk domain are not copied.')

    # --- DNS zones (Plesk) ----------------------------------------------------------------------
    def hosting_addresses(self):
        """The client's DNS server with its name servers and the new web server's addresses (GET /me/hosting-addresses)."""
        result = self.admin.get('/me/hosting-addresses?client_id=%d' % self.client_id)
        dns = [row for row in result.get('dns') or [] if row.get('is_default')]
        require(dns and dns[0].get('nameservers'),
                'The client has no DNS server in the new ISPConfig, so the website\'s DNS zones cannot be created there. '
                'Assign a DNS server to the client, or migrate without the DNS zones (--no-dns).')
        web = [row for row in result.get('web') or [] if row.get('server_id') == self.target['web_server_id']]
        require(web, 'The new web server (server ID %d) is not a web server of this client' % self.target['web_server_id'])
        servers = [{'name': str(row['name']).strip().lower().rstrip('.'), 'ipv4': list(row.get('ipv4') or [])}
                   for row in dns[0]['nameservers']]
        return {'server_id': int(dns[0]['server_id']), 'nameservers': servers,
                'ipv4': (web[0].get('ipv4') or [None])[0], 'ipv6': (web[0].get('ipv6') or [None])[0]}

    def dns_plan(self, rows=None, lookup=None):
        """Read-only: the website's Plesk zones that public DNS really delegates to Plesk, as zones of the new DNS server.

        rows: `plesk db` rows of the zones (read on the Plesk server when None);
        lookup: zone name -> (its name servers in public DNS, error).
        """
        inventory = self.state.get('inventory') or {}
        if 'dns_zones' not in inventory:
            inventory = self.source_inventory()  # migration state written before the DNS zones were planned
        zones = inventory['dns_zones']
        if rows is None:
            rows = json.loads(self.plesk({'action': 'dns', 'zones': [zone['id'] for zone in zones]},
                                         log='plesk-dns.log'))['rows'] if zones else []
        lookup = lookup or (lambda name: public_nameservers(name, self.resolvers))
        grouped = plesk_rows(rows)
        found = {row['id']: row for row in grouped.get('zone', [])}
        records = {}
        for row in grouped.get('record', []):
            records.setdefault(row['zone_id'], []).append(row)
        addresses = {ip_text(row['address']) for row in grouped.get('ip', [])} - {None}
        hosting = self.hosting_addresses()
        names = [server['name'] for server in hosting['nameservers']]
        plan = dict(hosting, zones=[], skipped=[])
        for entry in zones:
            zone = found.get(entry['id'])
            if zone is None:
                plan['skipped'].append('%s: no DNS zone in Plesk' % entry['domain'])
                continue
            origin = str(zone['name']).strip().lower().rstrip('.')
            if zone['type'] != 'master' or zone['status'] != 0:
                plan['skipped'].append('%s: %s in Plesk' % (origin, 'DNS is switched off' if zone['type'] == 'master' else 'secondary zone'))
                continue
            own = {str(row['val']).strip().lower().rstrip('.') for row in records.get(zone['id'], [])
                   if row['type'] == 'NS' and str(row['host']).strip().lower().rstrip('.') == origin}
            public, error = lookup(origin)
            if not own & set(public):
                plan['skipped'].append('%s: public DNS does not use the Plesk name servers (%s)' % (origin, ', '.join(public) or error))
                continue
            existing = [row for row in self.admin.all('/dns/soa', origin=origin + '.') if str(row.get('origin', '')).lower() == origin + '.']
            mine = self.state['objects'].get('zone:' + origin, {}).get('record', {}).get('id')
            if existing and existing[0]['id'] != mine:
                plan['skipped'].append('%s: the zone already exists in the new ISPConfig (zone ID %s) and is left unchanged'
                                       % (origin, existing[0]['id']))
                continue
            copy = nova_zone(zone, records.get(zone['id'], []), plesk_addresses=addresses, ipv4=hosting['ipv4'],
                             ipv6=hosting['ipv6'], nameservers=names)
            copy['soa']['server_id'] = hosting['server_id']
            plan['zones'].append(copy)
        return plan

    def prepare_dns(self, **source):
        """The DNS plan of this migration: kept once a zone was created, otherwise read again (Plesk may have changed)."""
        plan = self.state.get('dns')
        objects = self.state['objects']
        if plan and (plan.get('done') or any('zone:' + zone['origin'] in objects for zone in plan['zones'])):
            return plan
        self.state['dns'] = self.dns_plan(**source)
        self.save()
        return self.state['dns']

    def print_dns_plan(self, plan, *, when):
        if plan.get('done'):
            print('DNS zones: created in the new ISPConfig: ' + ', '.join(zone['origin'] for zone in plan['zones']))
            return
        servers = ', '.join(server['name'] for server in plan['nameservers'])
        if plan['zones']:
            print('DNS zones (created %s; name servers %s):' % (when, servers))
        for zone in plan['zones']:
            changes = sorted({'%s -> %s' % (item['old'], item['new']) for item in zone['remapped']})
            names = sorted({item['name'] for item in zone['remapped']})
            print('  %s: %d records%s' % (zone['origin'], len(zone['records']), '; A/AAAA of the Plesk server (%s) become the new '
                                          'web server\'s for: %s' % (', '.join(changes), ', '.join(names)) if names else ''))
            for item in zone.get('rewritten', []):
                print('  %s: ISPConfig writes "%s" as "%s"' % (item['name'], item['old'], item['new']))
            for record in zone['manual']:
                print('  MANUAL %s' % record)
        for note in plan['skipped']:
            print('DNS zone not created: ' + note)
        if plan['zones']:
            print('DNS switch: once the website and the zones are checked, change the domains\' name servers at the registrar to %s.'
                  % servers)
        else:
            print('DNS zones: none to create')

    def create_dns(self, plan):
        """Create the planned zones with the client's key: each one inactive, then its records, then switched on.

        ISPConfig's DNS server rewrites and checks an active zone after every journal entry; a zone switched on
        only when it is complete is loaded once, with all its records.
        """
        if plan.get('done') or not plan['zones']:
            return
        self.use_client_key()
        for zone in plan['zones']:
            name = 'zone:' + zone['origin']
            record = self.create(name, '/dns/soa', zone['soa'], wait=False)
            require(str(record['origin']).lower() == zone['soa']['origin'], 'DNS zone identity changed')
            rejected = zone.setdefault('rejected', [])
            for index, rr in enumerate(zone['records']):
                if index in rejected:
                    continue
                try:
                    created = self.create('rr:%s:%d' % (zone['origin'], index), '/dns/records', dict(rr, zone=record['id']), wait=False)
                except ApiError as exc:
                    if exc.status != 422:
                        raise
                    # Data ISPConfig refuses (e.g. other data next to a CNAME) must not keep the rest of the zone off.
                    rejected.append(index)
                    value = record_value(rr)
                    value = value if len(value) <= 60 else value[:57] + '...'
                    zone['manual'].append('%s %s %s (rejected by the new ISPConfig: %s)' % (rr['name'], rr['type'], value, exc))
                    self.save()
                    continue
                require(int(created['zone']) == int(record['id']), 'DNS record identity changed')
            entry = self.state['objects'][name]
            if 'activated' not in entry:
                _, change = self.api.request('PUT', '/dns/soa/%d' % record['id'], {'active': True})
                entry['activated'] = change
                self.save()
            self.api.wait(entry['activated'])
            print('DNS zone created: %s (zone ID %d, %d records)' % (zone['origin'], record['id'], len(zone['records']) - len(rejected)),
                  flush=True)
            for line in zone['manual']:
                print('  MANUAL %s' % line)
        plan['done'] = True
        self.save()
        self.verify_dns(plan)

    def verify_dns(self, plan, attempts=12):
        """Ask the new DNS server itself whether it answers for every created zone."""
        address = next(((server['name'], value) for server in plan['nameservers'] for value in server['ipv4']), None)
        if address is None:
            return
        expected = {server['name'] for server in plan['nameservers']}
        for zone in plan['zones']:
            for attempt in range(attempts):
                if zone_served(address[1], zone['origin'], expected):
                    print('DNS: %s (%s) answers for %s' % (address[0], address[1], zone['origin']))
                    break
                time.sleep(5)
            else:
                print('WARNING: %s (%s) does not answer for %s with its name servers yet; check the zone in ISPConfig '
                      'before the DNS switch.' % (address[0], address[1], zone['origin']))

    def dns_after_copy(self):
        """Plesk: the website's DNS zones once its copy is complete (nothing changes for visitors before the DNS switch)."""
        if self.kind != 'plesk' or not self.dns:
            return
        try:
            plan = self.prepare_dns()
            if not plan.get('done'):
                self.print_dns_plan(plan, when='now')
                check_counts(self.usage_summary(), self.dns_counts())
                self.create_dns(plan)
        except MigrationError as exc:
            raise MigrationError('The website copy is complete, but its DNS zones were not created: %s Fix the cause, then '
                                 'repeat the command with --dns.' % exc) from None
        finally:
            self.release_client_key()

    def dns_only(self, *, plan_only=False, interactive=False):
        """--dns: only the website's DNS zones, e.g. for a website copied before the migration created them."""
        require(self.kind == 'plesk', '--dns creates the DNS zones of a Plesk website (--from plesk)')
        try:
            plan = self.prepare_dns()
            print('DNS: %s → ISPConfig client %s' % (self.domain, self.client_id))
            self.print_dns_plan(plan, when='now' if not plan_only else 'by --dns without --plan')
            if plan_only or plan.get('done') or not plan['zones']:
                return
            check_counts(self.usage_summary(), self.dns_counts())
            if interactive:
                confirm('Create these DNS zones in the new ISPConfig? Public DNS keeps using Plesk until the switch.')
            self.create_dns(plan)
        finally:
            self.release_client_key()

    def create(self, name, endpoint, payload, *, wait=True):
        """POST once per state entry. wait=False leaves waiting for ISPConfig to a later change (DNS records:
        ISPConfig applies changes in order, so waiting for the zone's activation covers its records)."""
        objects = self.state['objects']
        if name in objects:
            entry = objects[name]
            require('record' in entry, 'Uncertain previous POST for %s. Reconcile the API receipt in state.json before retrying; never delete state blindly.' % name)
            current = self.api.get(endpoint + '/' + str(entry['record']['id']))
            require(current['id'] == entry['record']['id'], 'Provisioned object changed')
            if wait:
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
        if wait:
            self.api.wait(change)
        return record

    def use_client_key(self):
        """Act with the customer's own permissions and quotas, just like the WHMCS client area.

        Admin authentication is limited to account/key management and reads. The key is switched off again
        by release_client_key() or at the end of run().
        """
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
        self.key_active = True
        self.api = Api(self.target['api_url'], key=key['key'])

    def release_client_key(self):
        if self.key_active:
            self.admin.request('PUT', '/system/api-keys/' + str(self.state['client_key']['id']), {'active': False})
            self.key_active = False
        self.api = self.admin

    def provision(self):
        self.use_client_key()
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
            if child['type'] == 'vhostsubdomain':
                payload = {'domain': name, 'type': 'vhostsubdomain', 'parent_domain_id': site['id'], 'web_folder': child['web_folder'],
                           'php': 'php-fpm', 'active': True, 'subdomain': child['subdomain'], 'ssl': False,
                           'ssl_letsencrypt': False, 'rewrite_to_https': False}
                own = self.state.get('php_children', {}).get(str(child['domain_id']), {}).get('server_php_id')
                if own or php_id:
                    payload['server_php_id'] = own or php_id
                record = self.create('child:' + str(child['domain_id']), '/sites/web-domains', payload)
                require(record['parent_domain_id'] == site['id'] and record['domain'] == name and record['web_folder'] == child['web_folder']
                        and record['document_root'] == site['document_root'], 'Target subdomain identity changed')
                continue
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
            if 'database_users' in source_db:
                target_db['old_users'] = source_db['database_users']
            self.save()
            self.db_io({'action': 'probe', **self.credentials(target_db)})
        for index, job in enumerate(self.state.get('cron_jobs', [])):
            if not job['create']:
                continue
            command = render_cron(job, document_root=site['document_root'], cron_type=job['type'], php_cli=job['php_cli'])
            run_min, run_hour, run_mday, run_month, run_wday = job['schedule']
            # Inactive: the old server keeps running the same jobs until the DNS switch.
            record = self.create('cron:%d' % index, '/sites/cron-jobs', {
                'parent_domain_id': site['id'], 'run_min': run_min, 'run_hour': run_hour, 'run_mday': run_mday,
                'run_month': run_month, 'run_wday': run_wday, 'command': command, 'active': False,
            })
            require(record['parent_domain_id'] == site['id'] and record['command'] == command, 'Target cron job changed')
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
        site = self.state['inventory']['site']
        if self.kind == 'plesk':
            (tree / 'private').mkdir(exist_ok=True)
            (tree / 'web').mkdir(exist_ok=True)
            # Read as the subscription's system user: a customer symlink cannot make root read other files.
            reader = ['setpriv', '--reuid=%d' % site['uid'], '--regid=%d' % site['gid'], '--clear-groups', '--no-new-privs', '--', 'rsync']
            execute(RSYNC + ['--delete-delay', '--rsync-path=' + shlex.join(reader),
                             self.source['ssh'] + ':' + site['www_root'] + '/', str(tree / 'web') + '/'],
                    error_path=self.directory / 'rsync.log')
        else:
            root = site['document_root']
            for folder in ('web', 'private'):
                destination = tree / folder
                destination.mkdir(exist_ok=True)
                execute(RSYNC + ['--delete-delay', self.source['web_ssh'] + ':' + root + '/' + folder + '/', str(destination) + '/'],
                        error_path=self.directory / 'rsync.log')
        normalize_links(tree, self.link_roots())
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
            with open(round_dir / (key + '.source.sql'), 'wb') as output:
                if self.kind == 'plesk':
                    self.plesk({'action': 'dump', 'database': key}, output=output, log='database.log')
                else:
                    host, connection = self.source_database_route(source)
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
        if self.kind == 'plesk':
            # e.g. Wordfence's .user.ini auto_prepend_file: PHP stops on the new server until the path is changed.
            report['old_path_references'] = old_path_references(tree, self.state['inventory']['site']['document_root'])
            manual = manual + report['old_path_references']
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
        normalize_links(tree, self.link_roots())
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
        created = sum(job['create'] for job in self.state.get('cron_jobs', []))
        if created:
            print('%d cron job(s) were created INACTIVE; enable them after the DNS switch and stop them on the old server.' % created)
        self.dns_after_copy()

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
DNS_A, DNS_AAAA, DNS_CNAME, DNS_NS = 1, 28, 5, 2
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
        elif rclass == 1 and rtype in (DNS_CNAME, DNS_NS):
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


def public_nameservers(name, resolvers, timeout=3.0):
    """Name servers of a zone in public DNS (lowercase, without the dot) and why there are none."""
    try:
        name = ascii_hostname(name)
        rcode, records = dns_ask(resolvers, name, DNS_NS, timeout)
    except DnsError as exc:
        return [], str(exc)
    if rcode == 3:
        return [], 'NXDOMAIN'
    found = sorted({value for owner, rtype, value in records if rtype == DNS_NS and owner == name})
    return found, None if found else 'no NS records'


def zone_served(address, origin, nameservers, timeout=3.0):
    """True when the DNS server at address answers for the zone with exactly these name servers."""
    try:
        rcode, records = dns_query((address, 53), ascii_hostname(origin), DNS_NS, timeout)
    except DnsError:
        return False
    return rcode == 0 and {value for owner, rtype, value in records if rtype == DNS_NS and owner == origin} == set(nameservers)


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
    """Every website of the old ISPConfig (or Plesk) server, read on the old panel (no state, no writes)."""
    source = config['source']
    if source.get('type') == 'plesk':
        host = ssh_host(source['ssh'])
        result = subprocess.run(plesk_command(host), input=b'{"action": "inventory", "traffic": true}\n', capture_output=True)
        if result.returncode:
            lines = result.stderr.decode('utf-8', 'replace').strip().splitlines()
            raise MigrationError('Reading the Plesk websites on %s failed (exit %d)%s' % (
                host, result.returncode, ': ' + lines[-1][:300] if lines else ''))
        return plesk_sites_inventory(json.loads(result.stdout)['rows'], host.split('@')[-1])
    host = ssh_host(source['panel_ssh'])
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
        out.write('Inactive old websites (ACT n): %d; the old server does not serve them.\n' % inactive)
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
    config = select_source(read_json(args.config), args.source_name)
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
            report_file = tree.parent / 'configuration-report.json'
            if report_file.exists():
                report = read_json(report_file)
                for label, key in (('Review by hand', 'manual_files'), ('Still names the old Plesk webspace', 'old_path_references'),
                                   ('No configuration found for database', 'databases_needing_manual_config')):
                    if report.get(key):
                        print('%s: %s' % (label, ', '.join(report[key][:20]) + (' …' if len(report[key]) > 20 else '')))
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
        parser.add_argument('--from', dest='source_name', metavar='NAME', help='Old server from "sources" in the configuration, e.g. plesk')
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
                                         epilog='Which old websites are live (DNS): ispcp-migrate --sites [--from plesk]')
        parser.add_argument('domain', help='Domain on the old ISPConfig (or the --from server)')
        parser.add_argument('client_id', type=int, help='Client ID in the NEW ISPConfig (not WHMCS)')
        actions = parser.add_mutually_exclusive_group()
        actions.add_argument('--plan', dest='command', action='store_const', const='plan', help='Only show the migration plan')
        actions.add_argument('--sync', dest='command', action='store_const', const='interactive_sync', help='Take a new source snapshot after the first migration')
        actions.add_argument('--status', dest='command', action='store_const', const='status', help='Show saved progress')
        parser.add_argument('--config', default=DEFAULT_CONFIG, help='Connection settings (normally configured once)')
        parser.add_argument('--from', dest='source_name', metavar='NAME', help='Old server from "sources" in the configuration, e.g. plesk')
        parser.add_argument('--state', help='Existing state directory from a manual migration; normally state_dir/DOMAIN')
        parser.add_argument('--php', metavar='VERSION', help='PHP version of the new website, e.g. 5.6 (default: target.server_php_id)')
        parser.add_argument('--database', action='append', metavar='NAME',
                            help='Plesk: migrate exactly this database of the subscription (repeatable; default: those of the domain)')
        parser.add_argument('--dns', action='store_true',
                            help='Plesk: only create the DNS zones of the website, e.g. one copied earlier (with --plan: show them)')
        parser.add_argument('--no-dns', action='store_true', help='Plesk: do not create the DNS zones of the website')
        parser.set_defaults(command='interactive', source_quiesced=False, target_quiesced=False, config_reviewed=False)
        args = parser.parse_args(argv[1:])
        try:
            args.domain = domain_name(args.domain)
            require(args.client_id > 0, 'client ID must be positive')
            require(args.php is None or re.fullmatch(r'[0-9]+\.[0-9]+', args.php), '--php takes a version such as 5.6 or 8.3')
            require(not (args.dns and args.no_dns), '--dns and --no-dns exclude each other')
            require(not args.dns or args.command in ('interactive', 'plan'), '--dns goes alone or with --plan')
        except (MigrationError, ValueError) as exc:
            parser.error(str(exc))
        return args
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['plan', 'run', 'sync', 'publish', 'status', 'dns'])
    parser.add_argument('--config', required=True, help='Connection settings JSON (see config.example.json)')
    parser.add_argument('--domain', required=True)
    parser.add_argument('--client-id', required=True, type=int, help='Existing NEW ISPConfig client ID')
    parser.add_argument('--state', required=True, help='Private directory outside every document root; retain for resume')
    parser.add_argument('--source-quiesced', action='store_true', help='Confirm source application writes/cron are stopped')
    parser.add_argument('--target-quiesced', action='store_true', help='With sync: confirm target writes/cron are also stopped')
    parser.add_argument('--config-reviewed', action='store_true', help='With publish: manually patched staged non-WordPress configs')
    parser.add_argument('--php', metavar='VERSION', help='With plan/run: PHP version of the new website, e.g. 5.6')
    parser.add_argument('--database', action='append', metavar='NAME', help='Plesk: migrate exactly this database (repeatable)')
    parser.add_argument('--from', dest='source_name', metavar='NAME', help='Old server from "sources" in the configuration, e.g. plesk')
    parser.add_argument('--no-dns', action='store_true', help='Plesk: do not create the DNS zones of the website')
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
        config = select_source(read_json(args.config), args.source_name)
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
            migration.databases = args.database
            migration.dns = not args.no_dns
            if getattr(args, 'dns', False):
                migration.dns_only(plan_only=args.command == 'plan', interactive=True)
            elif args.command == 'dns':
                migration.dns_only()
            elif args.command == 'plan':
                migration.plan()
            elif args.command == 'status':
                print('Domain: %s; phase: %s; round: %s' % (migration.domain, migration.state['phase'], migration.state['round']))
                dns = migration.state.get('dns')
                if dns:
                    print('DNS zones: %s %s' % ('created' if dns.get('done') else 'planned',
                                                ', '.join(zone['origin'] for zone in dns['zones']) or '(none)'))
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
