"""Runs as root on a Plesk (Linux) server through root SSH; Python 3.6 compatible (CloudLinux/RHEL 8 python3).

Read-only. Plesk metadata comes from `plesk db` SELECT statements, the website owner's account from the
system databases. Files are measured as the subscription's system user, never as root, so a customer
symlink cannot point root at other files. Database dumps run as the Plesk administrator with the password
passed through a pipe: nothing is written on the Plesk server. The request is one JSON line on stdin.
"""
import grp
import json
import os
import pwd
import re
import stat
import subprocess
import sys

QUERIES = [
    "SELECT JSON_OBJECT('t','domain','id',d.id,'name',d.name,'htype',d.htype,'status',d.status,"
    "'webspace_id',d.webspace_id,'parent_id',d.parentDomainId,'www_root',h.www_root,'login',s.login,"
    "'home',s.home,'shell',s.shell,'php_handler',h.php_handler_id,'client',c.login,'company',c.cname,"
    "'contact',c.pname,'dns_zone_id',d.dns_zone_id) FROM domains d LEFT JOIN hosting h ON h.dom_id=d.id "
    "LEFT JOIN sys_users s ON s.id=h.sys_user_id LEFT JOIN clients c ON c.id=d.cl_id",
    "SELECT JSON_OBJECT('t','alias','id',a.id,'dom_id',a.dom_id,'name',a.name,'status',a.status,"
    "'web',a.web,'seo_redirect',a.seoRedirect,'dns_zone_id',a.dns_zone_id) FROM domain_aliases a",
    "SELECT JSON_OBJECT('t','database','id',b.id,'name',b.name,'type',b.type,'dom_id',b.dom_id,"
    "'server_id',b.db_server_id,'default_user_id',b.default_user_id) FROM data_bases b",
    "SELECT JSON_OBJECT('t','dbuser','id',u.id,'login',u.login,'db_id',u.db_id,'dom_id',u.dom_id) FROM db_users u",
    "SELECT JSON_OBJECT('t','dbserver','id',v.id,'host',v.host,'port',v.port,'type',v.type) FROM DatabaseServers v",
    "SELECT JSON_OBJECT('t','ip','address',i.ip_address) FROM IP_Addresses i",
    "SELECT JSON_OBJECT('t','charset','name',SCHEMA_NAME,'charset',DEFAULT_CHARACTER_SET_NAME) FROM information_schema.SCHEMATA",
]
TRAFFIC = ("SELECT JSON_OBJECT('t','traffic','dom_id',dom_id,'bytes',SUM(http_in+http_out)) FROM DomainsTraffic "
           "WHERE date >= CURDATE() - INTERVAL 30 DAY GROUP BY dom_id")
# DNS zones (zone settings in seconds), their records and the server's addresses, for the zones the migration
# recreates on the new DNS server.
DNS = ("SELECT JSON_OBJECT('t','zone','id',z.id,'name',z.name,'status',z.status,'type',z.type,'email',z.email,'ttl',z.ttl,"
       "'refresh',z.refresh,'retry',z.retry,'expire',z.expire,'minimum',z.minimum) FROM dns_zone z WHERE z.id IN (%s)",
       "SELECT JSON_OBJECT('t','record','id',r.id,'zone_id',r.dns_zone_id,'type',r.type,'host',r.host,'val',r.val,'opt',r.opt,"
       "'ttl',r.ttl) FROM dns_recs r WHERE r.dns_zone_id IN (%s)")
ADDRESSES = "SELECT JSON_OBJECT('t','ip','address',i.ip_address) FROM IP_Addresses i"
DATABASE = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')
LOGIN = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z')


def fail(message):
    sys.stderr.write(message + '\n')
    sys.exit(1)


def run(argv, **kwargs):
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def select(statements):
    result = run(['plesk', 'db', '-N', '-B', '-r', '-e', ';'.join(statements)])
    if result.returncode:
        lines = result.stderr.decode('utf-8', 'replace').strip().splitlines()
        fail('Reading the Plesk database failed' + (': ' + lines[-1][:300] if lines else ''))
    return [json.loads(line) for line in result.stdout.decode('utf-8').splitlines() if line.strip()]


def safe_directory(path, home):
    """A real directory inside the webspace, reached without symlinks below the root-owned vhosts tree."""
    if not path.startswith(home + '/') or '/../' in path + '/' or '/./' in path + '/' or '//' in path:
        fail('Path is outside the webspace: ' + path)
    current = home
    for part in [''] + path[len(home) + 1:].rstrip('/').split('/'):
        current += '/' + part if part else ''
        if not stat.S_ISDIR(os.lstat(current).st_mode):
            fail('Not a directory (or a symlink): ' + current)


def account(request):
    login, home = request['login'], request['home']
    if not LOGIN.match(login):
        fail('Invalid system user')
    user = pwd.getpwnam(login)
    if user.pw_uid < 500 or user.pw_dir.rstrip('/') != home or not stat.S_ISDIR(os.lstat(home).st_mode):
        fail('The system user does not own this webspace')
    crontab = run(['crontab', '-l', '-u', login])
    text = crontab.stdout.decode('utf-8', 'replace')
    if crontab.returncode:
        message = crontab.stderr.decode('utf-8', 'replace')
        if 'no crontab for' not in message:
            fail('Reading the crontab failed')
        text = ''
    return {'uid': user.pw_uid, 'gid': user.pw_gid, 'group': grp.getgrgid(user.pw_gid).gr_name,
            'entries': sorted(os.listdir(home)), 'crontab': text}


def size(request):
    user = pwd.getpwnam(request['login'])
    home = user.pw_dir.rstrip('/')
    sizes = {}
    for path in request['paths']:
        safe_directory(path, home)
        result = run(['setpriv', '--reuid=%d' % user.pw_uid, '--regid=%d' % user.pw_gid, '--clear-groups',
                      '--no-new-privs', '--', 'du', '-sk', '--', path])
        line = result.stdout.decode('utf-8', 'replace').split('\t', 1)[0]
        if result.returncode or not line.isdigit():
            fail('Could not measure %s as the website user' % path)
        sizes[path] = int(line) * 1024
    names = request['databases']
    if any(not DATABASE.match(name) for name in names):
        fail('Invalid database name')
    databases = dict((name, 0) for name in names)
    if names:
        quoted = ','.join("'" + name + "'" for name in names)
        for row in select(["SELECT JSON_OBJECT('name',table_schema,'bytes',SUM(data_length+index_length)) "
                           "FROM information_schema.TABLES WHERE table_schema IN (%s) GROUP BY table_schema" % quoted]):
            databases[row['name']] = int(row['bytes'] or 0)
    return {'paths': sizes, 'databases': databases}


def dump(request):
    name = request['database']
    if not DATABASE.match(name):
        fail('Invalid database name')
    with open('/etc/psa/.psa.shadow') as handle:
        password = handle.read().strip()
    escaped = password.replace('\\', '\\\\').replace('"', '\\"')
    help_text = run(['mysqldump', '--no-defaults', '--help']).stdout.decode('utf-8', 'replace')
    read, write = os.pipe()
    options = ['--defaults-extra-file=/dev/fd/%d' % read, '--single-transaction', '--quick', '--hex-blob',
               '--routines', '--events', '--triggers']
    for flag, option in (('no-tablespaces', '--no-tablespaces'), ('column-statistics', '--column-statistics=0')):
        if flag in help_text:
            options.append(option)
    process = subprocess.Popen(['mysqldump'] + options + ['--', name], pass_fds=(read,), stdout=sys.stdout.buffer)
    os.close(read)
    # The option file never touches the disk; it is read once from the pipe.
    os.write(write, ('[client]\nuser=admin\npassword="%s"\nhost=localhost\n' % escaped).encode())
    os.close(write)
    sys.exit(process.wait())


def main():
    if os.geteuid() != 0:
        fail('Run through root SSH')
    if not os.path.isfile('/usr/local/psa/version'):
        fail('This is not a Plesk server')
    request = json.loads(sys.stdin.readline())
    action = request.get('action')
    if action == 'check':
        with open('/usr/local/psa/version') as handle:
            result = {'version': handle.read().strip(), 'hostname': os.uname()[1]}
    elif action == 'inventory':
        result = {'rows': select(QUERIES + ([TRAFFIC] if request.get('traffic') else []))}
    elif action == 'account':
        result = account(request)
    elif action == 'size':
        result = size(request)
    elif action == 'dns':
        zones = request['zones']
        if not isinstance(zones, list) or not all(type(zone) is int and zone > 0 for zone in zones):
            fail('Invalid DNS zone IDs')
        ids = ','.join(str(zone) for zone in sorted(set(zones)))
        result = {'rows': select([query % ids for query in DNS] + [ADDRESSES]) if zones else []}
    elif action == 'dump':
        dump(request)
        return
    else:
        fail('Unknown action')
    sys.stdout.write(json.dumps(result) + '\n')


if __name__ == '__main__':
    try:
        main()
    except (KeyError, OSError, ValueError) as error:
        fail('Plesk source helper failed: %s' % type(error).__name__)
