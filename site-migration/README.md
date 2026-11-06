# Migrate an existing ISPConfig website into a WHMCS hosting account

First change the product and click **Create** in the WHMCS administrator area. That step stays manual.
This utility then creates the website and its database users/databases under the resulting **new ISPConfig
client ID**, copies the old site's `web/` and `private/` directories, imports its databases, and updates ordinary
WordPress `wp-config.php` files, including installations in subdirectories. It does not execute customer PHP.

Run it on the new web server or a trusted Linux administration host. The old servers do **not** need Python.
WHMCS itself is not modified. The target domain must not already exist; subsequent runs reuse the private
state directory for the domain to identify resources created by this migration.

## Install once through ispconfig-rest

This is the optional **`migration` server-tools component** of the hosting extension. It is not a scheduled worker
and is never installed by the default worker selection. It requires **hosting v1.2.0+** and **ispconfig-rest v1.4.2+**.

On the REST panel, select the new web server (ID `4` in this deployment):

```bash
sudo ispconfig-rest extension:update hosting --tag v1.2.3
sudo ispconfig-rest server-tools install --components migration --server 4
```

The manager verifies SSH and prerequisites, fetches the exact installed hosting commit from the trusted release
source and runs the installer on that web server. It installs:

| Path on the new web server | Purpose |
| --- | --- |
| `/usr/local/sbin/ispcp-migrate` | Command for the administrator |
| `/usr/local/lib/ispconfig-rest-migration/` | Root-owned program and this guide |
| `/etc/ispconfig-rest-migration/config.json` | Connection settings, configured once |
| `/var/lib/ispconfig-rest-migration/DOMAIN/` | Private progress, staging copy, SQL snapshots and backups for each site (`state_dir` moves it) |

On the new web server, edit `/etc/ispconfig-rest-migration/config.json`: set the new DB server ID,
PHP selection, source/destination SSH addresses and the administrator REST key file. The example already contains
the `web0.feldhost.cz → db0.feldhost.cz` source route. Since v1.2.2 the installed CLI accesses the destination web
server locally, including checks, backups and publication; it does not need SSH access back to itself.
Root SSH to the old servers and the destination DB server must use keys with verified host keys.

Create a dedicated administrator REST key on the panel with `sudo ispconfig-rest key:create "website migrations"`.
Store **only the resulting key** in the configured key file on the new web server, owned by root with mode 0600.
The example key path is `/root/.config/ispcp-migrate/api-key`; create its parent directory with mode 0700.
The installer does not copy API or SSH credentials from the panel.

After updating the hosting extension, update the installed tool from the panel:

```bash
sudo ispconfig-rest server-tools update --components migration --server 4
```

Updates preserve configuration and migration state and refuse to replace code while an installed `ispcp-migrate`
process is running. No cron entry, web endpoint or additional worker-table grant is created for this component.

## Requirements and connection settings

- Local host: Python **3.9+**, PHP **7.4+**, OpenSSH client and a current, security-patched rsync.
- Old panel: root SSH, PHP CLI with mysqli, OpenSSL and POSIX, standard ISPConfig server configuration.
  Use hosting v1.2.1+ for source schemas without `web_domain.server_php_id`; destination PHP selection is configured separately.
- Old web server: root SSH, PHP CLI and rsync **3.0+** (`--protect-args`).
- Source database export: `mysqldump` on the old web server, with MySQL access from that host to the old DB
  server. Direct SSH to the old DB server is **not required** when using `source.db_via_web` (the example default).
  The optional direct mode uses root SSH, PHP CLI and `mysqldump` on each old DB server instead.
- New web server: run the installed command as root; Python 3, PHP CLI, rsync and the standard
  `/var/www/clients/clientN/webN` layout. SSH from the panel is needed for installation/updates, but the
  migration command itself accesses this web server locally.
- New DB server: root SSH, PHP CLI with POSIX, `mysql`, `mysqldump`, `setpriv`, and the `nobody` account.
- New panel: ispconfig-rest **v1.4.2+**, trusted HTTPS certificate and an administrator API key in a **0600** file.
  A temporary client-bound API key is created for provisioning, so client permissions and quotas still apply.
  It is revoked when `run`/`sync` exits normally or with a handled error, and reactivated on a retry.

The installer creates a private configuration from `config.example.json` on first install. The example
deliberately has `db_server_id: 0`: replace that with the real **new ISPConfig DB server ID**. Set the PHP version ID to
the new product's intended setting; quotas follow the client automatically (see below). `server_php_id: 0` lets the API select the server default (or its first
allowed PHP version if the default is hidden); this may differ from the old site. `db_host` is the address
the **new website** uses for MySQL. The example grants remote access
to both the web server (`10.0.10.21`) and phpMyAdmin on the panel (`10.0.10.20`).

### Quotas and limits (automatic)

Every quota follows the client's product allowance in the new ISPConfig, never a static configuration value.
The plan reads `/usage/summary?client_id=ID` and uses the client's limit minus the quotas already allocated
to other objects (allocated quotas, not measured usage):

- website disk quota (`hd_quota`) and monthly traffic quota (`traffic_quota`);
- database quota (`database_quota`): the unallocated database quota is split across the migrated databases in
  proportion to their source size. With one database it receives the whole unallocated quota.

An unlimited allowance produces `-1` (unlimited). Before the first write, the plan also measures the source
(`du -sk` of `web` and `private` on the old web server, and `data_length + index_length` per source database,
read-only) and stops when the website files or any database would not fit its quota, or when a count limit
(websites, alias domains, subdomains, databases, database users) cannot fit the objects still to be created.
A filled website quota would otherwise interrupt publishing, and ISPConfig restricts a database over its quota
to read/delete access. The plan prints every chosen quota with the measured source size; values are refreshed
before each create request. Client and reseller limits remain enforced by the API, including concurrent
allocations. Resume and final sync keep the quotas of objects already created by this migration and repeat
the size checks against them before copying new data.

The old `target.hd_quota_mb` (ignored since v1.2.3) and `target.traffic_quota_mb` (ignored since v1.2.4)
settings remain only for compatibility. Leave existing configuration files unchanged when upgrading so the
saved configuration fingerprint still matches. A disabled direct ISPConfig login (`canceled: true`, as configured
by WHMCS) does not disable a client API key; a locked account remains subject to the API's write restrictions.

Use SSH aliases in `/root/.ssh/config` for custom ports/identity files. Every alias must log in as root with a
key and have a host key verified through a trusted channel. Both SSH host verification and HTTPS verification
are mandatory; the utility does not accept unknown keys or insecure TLS. It verifies the ISPConfig server ID
on each SSH host and on the local destination web server before provisioning.

### Destination web transport

The installed `ispcp-migrate` command defaults to local destination access. Existing configuration files without
`target.web_transport` need no change, even if `target.web_ssh` still names the new web server. The example
explicitly sets `"web_transport": "local"`. Local mode requires root and checks that the local ISPConfig
server ID matches `target.web_server_id`; a mismatch stops the plan before provisioning. File operations run
as the website user, while private snapshots remain accessible only to the administrator.

To run from a separate trusted administration host, set `"web_transport": "ssh"` and configure
`target.web_ssh` with a verified host key. Standalone source-tree runs default to SSH when this setting is
absent. Select the transport before starting a new migration; an existing installed-tool migration can
continue with its original configuration and state after upgrading from v1.2.0/v1.2.1.

### Old database reachable only from the old web server

The supplied example uses this route:

```text
migration runner ──SSH──> web0.feldhost.cz ──MySQL TCP──> db0.feldhost.cz:3306
```

Inventory is read on `web0.feldhost.cz` using its trusted ISPConfig control-database configuration. `mysqldump`
also runs on `web0`; SQL streams back through the SSH session. The runner never opens SSH or MySQL to the old
`db0`. The transport identity check uses the old **web** server's ISPConfig ID, even when the source database
belongs to a different server ID. The configured MySQL hostname selects the DB endpoint; its ISPConfig ID
cannot be checked via SSH in this mode. A website spread over multiple old DB server IDs is refused.

By default the export uses the user/password from
`/usr/local/ispconfig/server/lib/mysql_clientdb.conf` **on web0**, overriding its MySQL host and port with
`source.db_via_web.host` and `port`. Those credentials must actually have export access to `db0`; a web server's
local MySQL root account is not necessarily valid on the remote database server.

If a separate export account is needed, store its MySQL client options in a root-owned **0600** regular file
outside the web roots **on web0**, then add its path:

```json
"db_via_web": {
  "host": "db0.feldhost.cz",
  "port": 3306,
  "defaults_file": "/root/.config/ispcp-migrate/source-db.cnf"
}
```

That file uses the usual `[client]` section with `user` and `password`; it can also carry the installation's
MySQL TLS settings. Host, port and TCP transport are enforced by the migration route. The account needs
permission to export the selected database, including any views, routines, triggers and events. The source
helper only permits dumps, never imports or mutations. Credentials stay on web0 and do not appear in process
arguments or local state; the supplied file is neither changed nor removed. `plan` validates routing and SSH
identities but does not test these database credentials; export reports connection/privilege failures in the
private `database.log`.

For installations allowing direct root SSH to old DB hosts, replace `db_via_web` with
`"db_ssh": {"2": "root@old-db.example.net"}`. Those map keys are old ISPConfig DB server IDs, not WHMCS IDs.
Configure exactly one source database transport. Direct mode reads `mysql_clientdb.conf` on the DB host.

Keep API keys, state, backups and configuration outside all document roots and Git checkouts. State contains
new database passwords, the temporary API key, customer files and SQL dumps. It uses directory mode 0700 and
file mode 0600. Keep the state directory until the migration and any final sync are complete.

## One website: domain and client ID

After changing the product and clicking **Create** in WHMCS, run this on the new web server as root:

```bash
ispcp-migrate example.com 123
```

`123` is the **new ISPConfig client ID**, not a WHMCS customer/service/server ID. Do not create the domain or
DBs manually. The command uses the saved configuration and stores progress automatically under
`/var/lib/ispconfig-rest-migration/example.com/` (or `STATE_DIR/example.com/`, see below).

### Staging space and `state_dir`

Each round copies the source website into a private staging tree, backs up the target and keeps SQL snapshots,
all in the site's state directory. The plan measures the source and stops before any write when that file
system lacks about the website size plus twice the database size and 256 MB (a final sync also needs room for
the target backup). When the root file system is small, put the state on the website file system, outside
every website root, with a top-level `state_dir` in `/etc/ispconfig-rest-migration/config.json`:

```bash
mkdir -m 700 /var/www/ispcp-migration
mv /var/lib/ispconfig-rest-migration/example.com /var/www/ispcp-migration/   # only for a started migration
python3 -c 'import json; p="/etc/ispconfig-rest-migration/config.json"; c=json.load(open(p)); c["state_dir"]="/var/www/ispcp-migration"; open(p, "w").write(json.dumps(c, indent=2) + "\n")'
```

`state_dir` does not change the configuration fingerprint, so a started migration continues from the moved
directory. The command refuses to start over while a migration's state is still in the old location. The state
must stay root-only (mode 0700), not below `/var/www/clients`, `/var/www/html` or a `/var/www/DOMAIN` link.
After the final copy is verified, older `round-NNN` directories can be deleted to recover space.

It shows the source/destination plan first, then asks whether the old application's writes and scheduled jobs
are stopped and the transfer should begin. Put the source in maintenance/read-only mode, stop queues, cron and
external writers, then answer `y` or `ano`. This confirms an operator action; the command does not switch the
source into maintenance itself. Empty input, refusal or noninteractive stdin stops before migration writes.
Ensure there is space for staged files, SQL snapshots and destination backups. Keep writes stopped during
snapshot capture: `--single-transaction` alone does not coordinate files, several DBs, nontransactional tables or DDL.

For a plan without a transfer prompt:

```bash
ispcp-migrate example.com 123 --plan
```

This reads old ISPConfig metadata and validates destination/client/SSH identities. It writes only local inventory
and state files, without creating domains, databases, keys or remote files. It does not test source export credentials.

If custom application configuration needs manual changes, the command stops before publishing files. Edit the
prepared `STATE/round-000/tree/` using `STATE/database-map.json` and `configuration-report.json`, then run the same
two-argument command again. It asks whether those prepared configs have been reviewed, then publishes that copy.
Ordinary WordPress literal DB settings are updated automatically; dynamic PHP, `.env`, YAML and other applications
require review. The staging tree is retained on retries.

Test the copied site through its preview hostname or a hosts-file override before DNS cutover. Check the frontend,
admin, uploads, DB writes, application logs and PHP compatibility. Use the original domain for applications that
redirect to their configured URL. Application URLs and serialized data are not rewritten.

If the source resumed accepting writes while testing, stop writes and scheduled jobs on both copies, then run:

```bash
ispcp-migrate example.com 123 --sync
```

The prompt confirms both sites are quiesced. This overwrites the migration's target from a fresh source snapshot,
keeping the pre-sync target in `STATE/round-NNN/before/`. Custom configurations need review again. Resume an
interrupted round using the ordinary two-argument command, without `--sync`. `--status` displays saved progress.

After testing the final copy, arrange certificates/HTTPS and switch DNS separately. Keep the old copy available
for recovery until verified. Mail, DNS, cron and other services remain separate migration steps.

### Batch and existing manual migrations

The original explicit interface remains available for automation or an existing custom state path:

```bash
python3 /usr/local/lib/ispconfig-rest-migration/migrate.py run \
  --config /etc/ispconfig-rest-migration/config.json --domain example.com --client-id 123 \
  --state /var/lib/ispconfig-rest-migration/example.com --source-quiesced
```

Its actions are `plan`, `run`, `sync`, `publish` and `status`. `sync` also needs `--target-quiesced`; publishing
manually edited configuration needs `--config-reviewed`. These flags assert the same operator checks as the
interactive prompts. Do not run a tool update concurrently with this direct Python interface.
`ispcp-migrate example.com 123 --config /old/config.json --state /old/state` can resume an older manual migration
with its original configuration and state; do not create a new state directory to bypass an existing target.

## Scope, retries and recovery

- All MySQL databases linked to the old website by `parent_domain_id` are migrated. Each gets a new randomly
  named ISPConfig database/user and a new password. Databases used by the application but not linked in the
  old ISPConfig metadata need separate review; inspect application configs before cutover.
- Aliases and subdomains sharing the parent vhost are created through the API. Child vhosts with separate
  settings, PostgreSQL, inactive primary websites/databases, and nonstandard website paths stop at planning.
  Shared-root aliases are excluded from Let's Encrypt initially; review their certificate settings at cutover.
- `web/` and `private/` are copied including dotfiles. Logs, old TLS keys, backups, jail contents, Linux users,
  vhost directives, custom PHP ini, mailboxes and scheduler settings are not copied. Review old rewrite rules,
  PHP compatibility and any document-root override. Old absolute application paths may need configuration edits.
- In-site absolute symlinks are converted to relative links. External, cyclic and broken symlinks stop before
  publishing rather than widening `open_basedir` or copying another site's files. Resolve unsupported links at
  the source and use a new attempt if staging had not completed. Device files and special files are not copied.
- Target files are written after dropping to the **target website UID/GID**, without inherited groups. They are
  normalized to web directories 0755/files 0644 and **private directories 0700/files 0600**, owned by the new
  website user. Review applications requiring
  executable files or more restrictive permissions. Parent ISPConfig directories and immutable flags are untouched.
- The destination's existing files and databases are backed up before the first overwrite in each round.
  `.well-known/acme-challenge/` is preserved during publication. The source is never written to.
- The SQL normalizer is the hosting extension's database-worker implementation (`worker/SqlDump.php`), copied
  from the same release during installation. It streams SQL, rewrites schema qualifiers
  and object DEFINERs, and preserves string/BLOB contents. Import runs as an unprivileged OS account with the
  **new database's scoped SQL user**, binary mode, and local infile disabled. Cross-database objects and unusual
  server-version SQL incompatibilities can require manual adaptation; errors stop the migration.
- The script has no automatic production cutover or application-health claim. `COPY COMPLETE` means files and
  SQL were transferred, not that the application is compatible with the selected PHP/MySQL versions.

The configuration, domain and client ID are bound to the state. Normal retries preserve target IDs, passwords,
source snapshots and completed import receipts. `status` reports the current phase. A failed import may have
partially changed the target database; its pre-import dump is in `round-NNN/before/`. Keep target writes stopped
and rerun `run --source-quiesced` to retry from the saved source snapshot. Restoring `before/` is a manual recovery
operation; no automatic deletion of ISPConfig resources or reversal of a partially completed migration occurs.

If a POST loses its response or the process is killed between the API commit and saving its receipt, the script
stops instead of guessing whether it created an object. Inspect `state.json`'s pending object and the API:
only after verifying its exact domain/name, parent and client ownership, replace that object's pending entry
with `{"endpoint":"...","record":<GET response>,"change":<change-set ID or null>}`. If the server confirms no
object was created, remove only that pending entry and retry. Never delete the whole state to bypass an existing
target conflict. For a lost key-create response, revoke the key named `migration-NONCE` first, then remove only
`client_key`. A SIGKILL or network failure during cleanup may leave that key active; revoke it on the panel.

Errors containing customer SQL remain in private `database.log`. Other connection errors are in
`source-inventory.log`, `server-check.log`, `target-files.log` and `rsync.log`. Do not paste private state,
database mappings, SQL dumps or application configurations into tickets/chat.

REST errors show recognized problem names and numeric limits, for example
`quota-exceeded: limit_web_quota (client); max=5120; used=0; requested=10240`. Raw server response bodies and
free-form error details are not printed because they may contain reflected credentials. The migration's
temporary client key is deactivated after an error and reactivated when the original command is retried.

Since v1.2.1, inventory query errors include their section and MySQL error code/message, for example
`[databases] (MySQL 1054): Unknown column ...`. Missing required columns or tables stop the plan before
destination provisioning. The optional source `server_php_id` column is detected automatically; its absence
does not require changing the old database schema. An SSH post-quantum key-exchange warning is separate
from SQL inventory failures.

## Validation

```bash
python3 -m unittest discover -s tests/Migration -p 'test_*.py'
../../vendor/bin/phpunit --filter MigrationProvisioningTest
bash tests/Migration/integration.sh
```

The integration test installs through the server-tools remote dispatcher, checks updates preserve settings/state,
rejects concurrent updates and destination symlinks, and runs both source transports with real SSH, rsync, PHP and MariaDB.
The web-mediated variant uses local destination file access with an unreachable destination SSH hostname,
checks rejection of a wrong local ISPConfig server ID, and exercises backup, publication, recovery and final sync
under the website user's privileges. The direct-source variant also covers remote destination access.
The web-mediated variant checks TCP export with a limited SQL account, different web/DB server IDs, both credential
sources, rejection of public credential files and rejection of source imports. It also checks source schemas
with and without `server_php_id`, useful diagnostics for missing required columns, inventory,
planning without remote writes, client-scoped provisioning calls, interrupted import recovery, binary data and
views, WordPress edits without executing customer code, link conversion, ownership, backups, repeated runs and
final sync, plus the read-only source size measurement (`du` and `information_schema`). Its REST transport is a
contract-shaped fake. `MigrationProvisioningTest` instead runs the shipped `preflight()`/`provision()` code through
`tests/Migration/api_bridge.py` against the real API controllers, client keys and limit enforcement on a
disposable SQLite schema: it reproduces the omitted database quota refusal of v1.2.3 and its resume, creates
website, alias, database user and databases with every quota derived from the client (including a
size-proportional database split and unlimited plans), and proves that count limits and source sizes that do not
fit stop before any write. The 10 GB website request still fails for a 5 GB account and an existing allocation
reduces the new quota.
These tests are **not a live ISPConfig instance**. A first production migration must
start with `plan` and an application test before DNS changes.
