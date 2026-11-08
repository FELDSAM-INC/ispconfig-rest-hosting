# Migrate an existing ISPConfig or Plesk website into a WHMCS hosting account

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
the `old-web.example.net → old-db.example.net` source route. Since v1.2.2 the installed CLI accesses the destination web
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
the new product's intended setting; quotas follow the client automatically (see below). `server_php_id` is the default when a migration has no `--php` (see below); `0` lets the API select the server default (or its first
allowed PHP version if the default is hidden); this may differ from the old site. `db_host` is the address
the **new website** uses for MySQL. The example grants remote access
to both the web server (`10.20.30.21`) and phpMyAdmin on the panel (`10.20.30.20`).

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
migration runner ──SSH──> old-web.example.net ──MySQL TCP──> old-db.example.net:3306
```

Inventory is read on `old-web.example.net` using its trusted ISPConfig control-database configuration. `mysqldump`
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
  "host": "old-db.example.net",
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

## Which old websites are live

Before choosing what to migrate, list every website of the old ISPConfig with where its public DNS points:

```bash
ispcp-migrate --sites
ispcp-migrate --sites --status old          # only websites still served by the old server
ispcp-migrate --sites --json > sites.json   # all details, e.g. for jq
```

It reads the websites on the old panel (`source.panel_ssh`, read-only: websites, aliases/subdomains, owners,
database counts, server addresses and ISPConfig's traffic statistics) and asks recursive DNS resolvers for the
A/AAAA records of each website, `www.` (for `www`/`*` websites) and every active alias and subdomain, following
CNAMEs. It writes no state and needs no client ID. Each website gets the strongest state of its hostnames:

| Status | Meaning |
| --- | --- |
| `old` | At least one hostname points to an old web server: the website is live there. Migrate it. |
| `new` | Points to the new web server: already migrated. |
| `other` | Points elsewhere: hosted somewhere else, or behind a proxy/CDN such as Cloudflare (compare `TRAFFIC 30D`). |
| `none` | No hostname has an address (NXDOMAIN, no A/AAAA, or the resolver failed; the DNS column shows which). |

Old server addresses are the old ISPConfig IP addresses of the servers hosting websites, website-specific IPs
and the DNS addresses of those servers' names. New server addresses come from `GET /servers/ID/ip-addresses`
(the configured REST key) and the DNS of `target.web_ssh`. The header prints both lists; add missing public
addresses, e.g. behind NAT, with `--old-ip IP` / `--new-ip IP`. The resolvers are `1.1.1.1` and `8.8.8.8` by
default, so `/etc/hosts` overrides and a server's own copy of a zone do not change the result; use
`--resolver IP` for another recursive resolver. `TRAFFIC 30D` sums the old panel's `web_traffic` for the last
30 days. Inactive websites (`ACT n`) are listed too, but ISPConfig does not serve them.

## Migrating from Plesk

The same commands migrate websites of a **Plesk Obsidian (Linux)** server; `--from plesk` selects it. Add the
Plesk server once under `sources` in `/etc/ispconfig-rest-migration/config.json`; the `target` settings and
`state_dir` are shared, and existing ISPConfig migrations are not affected (`sources` is not part of a
migration's configuration fingerprint):

```json
"sources": {"plesk": {"type": "plesk", "ssh": "root@plesk.example.net"}}
```

Root SSH from the new web server to the Plesk server uses a key and a verified host key, as for the old ISPConfig.
The Plesk server needs only its own `python3` (CloudLinux/RHEL 8 `platform-python` 3.6 is enough), `rsync`,
`setpriv`, `crontab` and `mysqldump`. Nothing is installed or written there:

- Plesk's metadata comes from `plesk db` **SELECT** statements (domains, hosting, aliases, databases and their
  users, IP addresses, 30-day traffic). The Plesk REST API would need a key created on the server and lacks the
  PHP handler, the system user and the traffic; the CLI utilities print text only.
- Files and sizes are read **as the subscription's system user** (`setpriv`), so a symlink a customer places in the
  webspace cannot make root read other files. A file that user cannot read stops the copy.
- Databases are dumped as the Plesk administrator (`/etc/psa/.psa.shadow`); the password reaches `mysqldump` through
  a pipe, not a file or the command line.

```bash
ispcp-migrate --sites --from plesk              # which Plesk websites are live (DNS), as above
ispcp-migrate --from plesk example.com 123 --plan
ispcp-migrate --from plesk example.com 123 --php 8.2
```

What is migrated, per Plesk domain with website hosting (a suspended or disabled domain stops the plan):

| Plesk | New ISPConfig website |
| --- | --- |
| Document root (`httpdocs`, or an additional domain's folder) | `web/` (`private/` stays empty) |
| `www.` and the wildcard subdomain `*.example.com` in the same folder | `subdomain` `www` or `*` (`*` needs `limit_wildcard` in the client's plan; checked before any write) |
| Domain alias used for the website | Alias domain; Plesk's SEO-safe 301 becomes a 301 redirect to `[scheme]://example.com/` |
| Subdomain in the same folder | Subdomain |
| Subdomain with its folder inside the document root (`httpdocs/blog`) | Subdomain with its own web folder (`web/blog`) |
| Local MySQL/MariaDB databases Plesk assigns to the domain | New databases and users; WordPress configs using any of the database's Plesk users are updated |
| Cron jobs of the subscription's system user | ISPConfig cron jobs, created **inactive** |

The plan lists everything else: subdomains or additional domains of the subscription with their own folder
(migrate each one separately, `ispcp-migrate --from plesk sub.example.com 123`), aliases used only for mail or DNS,
forwarding subdomains, files of the webspace outside the document root (e.g. `wordpress-backups`), and databases
assigned to another domain of the subscription. Plesk often assigns all databases to the subscription's main
domain: `--database NAME` (repeatable) migrates exactly these databases of the subscription instead, e.g. the one an
additional domain's WordPress uses. The source PHP version comes from the Plesk handler (`alt-php74-fpm` → 7.4);
the plan prints it and suggests `--php` when the new website would differ. Per-domain PHP settings, mail, DNS,
certificates and Plesk extensions (WP Toolkit, Imunify) are not migrated.

**Cron jobs.** Paths in the subscription's webspace are rewritten: relative ones (`httpdocs/wp-cron.php`, Plesk runs
jobs in the webspace), chroot ones (`/httpdocs/…`) and absolute ones (`/var/www/vhosts/example.com/httpdocs/…`)
become `/var/www/clients/clientN/webM/web/…` for `full` cron jobs, or `/web/…` inside the jail for `chrooted` ones (the
client's `limit_cron_type`). The CloudLinux/Plesk PHP binary (`/opt/alt/php74/usr/bin/php`) becomes the CLI of
the new website's PHP version; `curl`/`wget` of one URL becomes an ISPConfig URL job. A trailing `>/dev/null 2>&1`
is kept. Jobs with other shell syntax (pipes, `&&`, variables, globs, `%`), schedules ISPConfig cannot store
(`@reboot`, `*/1`), paths outside the migrated folders, jobs more frequent than `limit_cron_frequency` and command jobs
of a URL-only plan are listed as `MANUAL` and not created. Duplicate jobs are created once. Jobs without webspace
paths belong to the subscription's main domain. All created jobs are **inactive**: the old server keeps running
them until the DNS switch, so enable them in ISPConfig/WHMCS then and stop them in Plesk.

WordPress cron is not migrated: WP Toolkit's jobs (`php -f httpdocs/wp-cron.php`, with or without its description)
and fetches of `wp-cron.php` are left out, and the plan says so in one note. After the DNS switch turn on the
WordPress cron of the website in WHMCS (WordPress tools). WP Toolkit usually disables WordPress's own cron
(`DISABLE_WP_CRON` in `wp-config.php`), so scheduled WordPress tasks wait until then.

**Old paths.** Configuration files in the copy that still name the old webspace (`.htaccess`, `.user.ini`,
`php.ini`, `.env`, `wp-config.php`, `wordfence-waf.php`, PHP/ini files directly in the document root) are listed
in `configuration-report.json` (`old_path_references`) and stop publication for review, like other manual
configuration: for example Wordfence's `auto_prepend_file`, which would stop PHP on the new server. Edit the
staged copy, then repeat the command and confirm.

## One website: domain and client ID

After changing the product and clicking **Create** in WHMCS, run this on the new web server as root:

```bash
ispcp-migrate example.com 123
```

`123` is the **new ISPConfig client ID**, not a WHMCS customer/service/server ID. Do not create the domain or
DBs manually. The command uses the saved configuration and stores progress automatically under
`/var/lib/ispconfig-rest-migration/example.com/` (or `STATE_DIR/example.com/`, see below).

### PHP version per migration

```bash
ispcp-migrate example.com 123 --php 5.6
```

`--php VERSION` selects the new website's PHP: the plan looks up the destination web server's PHP versions
(`GET /servers/ID/php-versions`) and uses the single active PHP-FPM configuration of that version that is public
or limited to this client, matched by its name (`PHP 5.6`) or FPM/CLI path (`/etc/php/5.6/fpm`). An unknown,
inactive or ambiguous version stops the plan before any write and lists the usable versions. The plan prints
the chosen version and configuration ID; the API still checks that the client may use it. The choice is saved, so
resuming without `--php` keeps it. Without `--php`, `target.server_php_id` from the configuration applies. Once
the website exists, change its PHP version in ISPConfig or WHMCS; a different `--php` then stops instead of
silently diverging. Changing it in ISPConfig directly also works with the `php-limits` resource limits.

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
The `plesk` variant of the integration test runs a Plesk source in the container (`plesk db` over a `psa` schema,
the subscription's system user and crontab, the administrator password file): `--sites`, the inventory and plan,
reads as the subscription user (a root-only file stops the copy), dumps as the Plesk administrator including a
database name with a hyphen, the wildcard, the alias redirect, a subdomain folder, an inactive cron job with
rewritten paths, the old-path review, WordPress configuration and a final sync, and that nothing is written on the
Plesk side. `MigrationProvisioningTest` also provisions a Plesk inventory through the real API, including the
wildcard and cron limits that stop before any write.
These tests are **not a live ISPConfig instance**. A first production migration must
start with `plan` and an application test before DNS changes.
