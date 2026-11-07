# Changelog

All notable changes to ispconfig-rest-hosting. The format follows [Keep a Changelog](https://keepachangelog.com/),
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.3.3] - 2026-11-07

### Added

- `ispcp-migrate --sites` lists every website of the old ISPConfig with where its public DNS points: `old`
  (live on the old server, migrate it), `new` (already migrated), `other` (elsewhere or behind a CDN) or `none`
  (no address), per hostname (`www.`, active aliases and subdomains, CNAMEs followed), with owner, database count
  and 30-day traffic. Read-only on the old panel (`source-sites.php`, PHP 5.3+); DNS is asked from public
  recursive resolvers (`--resolver`), so `/etc/hosts` and local zone copies do not skew it. `--status`, `--json`,
  `--old-ip`/`--new-ip` for addresses behind NAT.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.3.3 && ispconfig-rest server-tools update --components migration --server 4`
  installs the new helper. Configuration and migration state are unchanged.

## [1.3.2] - 2026-11-07

### Fixed

- Apache websites no longer get a copy of every WAF finding in their web server error log, which customers read
  in WHMCS (`[security2:error] ModSecurity: Warning ...`). `base.conf` sets `LogLevel security2:crit` for the WAF
  vhosts; ModSecurity 2 still records every finding and execution error in the JSON audit log behind the WAF tab.
  nginx cannot separate them and is unchanged.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.3.2 && ispconfig-rest server-tools update --components waf --yes`
  rewrites `base.conf` and reloads Apache. No migrations.

## [1.3.1] - 2026-11-07

### Security

- OWASP CRS 4.25.2 (LTS) instead of 4.25.1, with its security backports: command injection in the URL path (RCE
  rules 932125–932390 also inspect `REQUEST_FILENAME`), upper-case `charset` in `Content-Type` (920480, the
  malformed-charset scans of 2026-11-06), shadowed multipart `_charset_` (922100), a bypassable SQL `(X)OR` length
  bound (942390) and upload filenames ending in `/` (933110, 944140); see the
  [release notes](https://github.com/coreruleset/coreruleset/releases/tag/v4.25.2). Verified like every pin: release
  key signature and SHA-256, native Apache and nginx checks.

### Added

- Weekly `crs-update` workflow and `tools/crs-update.php`: a newer release of the pinned CRS LTS line is verified
  with the pinned release key, checked on the native engines, committed to `develop` and reported in an issue.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.3.1`, then
  `ispconfig-rest server-tools update --components waf --yes`. RCE rules now also inspect URL paths, so review new
  events of websites in detection mode for false positives. No migrations.

## [1.3.0] - 2026-11-07

### Added

- WAF bans (spec 048). The root WAF worker bans a client on HTTP and HTTPS of its web server through fail2ban when,
  within 10 minutes across the server's WAF websites, it sends 20 requests over the anomaly threshold to enforcing
  websites (attack) or hits 15 distinct paths with scanner, protocol or restricted-file rules (scan, also on
  detection websites). One hour, a week for the third ban within a day. Allowlisted, private and reserved
  addresses, the server's own and `/etc/ispconfig-waf/ban-ignore.conf` are never banned; an allowlisted client is
  unbanned within a minute. Settings in `/etc/ispconfig-waf/ban.local.json`; `ispconfig-waf bans` and
  `ispconfig-waf unban ADDRESS`. The WAF installer installs fail2ban and its jails, and warns instead of failing
  when another jail keeps fail2ban from running.
- `GET /sites/web-domains/{id}/waf/clients`: the website's clients of the last 7 days with events, requests,
  requests over the threshold, first/last seen and their current ban.
- `client_ip` (address or CIDR block) and `banned` filters for `GET /sites/web-domains/{id}/waf/events`, and
  `client_banned` on each event.

### Changed

- The WAF worker keeps at most 100 events per client of a website (within the 1,000 per website), so a single
  scanner no longer evicts the other clients' events. Per-client totals count every collected event.
- The WAF worker's database account also needs SELECT/INSERT/UPDATE/DELETE on `api_web_waf_clients` and
  `api_web_waf_bans`.

### Upgrade notes

- Run the migrations (`ispconfig-rest extension:update hosting --tag v1.3.0`), then
  `ispconfig-rest server-tools update --components waf --yes` for the worker, its grants and fail2ban.
- Check `ispconfig-waf bans` on each web server afterwards. If the installer warned that fail2ban does not run,
  run `fail2ban-client -t` and fix or disable the reported jail (often `dovecot` or `postfix-sasl` without a mail
  log on a web-only server).
- Add the addresses of monitoring services and administrators to `/etc/ispconfig-waf/ban-ignore.conf`.

## [1.2.6] - 2026-11-06

### Added

- `ispcp-migrate DOMAIN CLIENT_ID --php 5.6` selects the new website's PHP version per migration. The plan resolves
  it to the single active PHP-FPM configuration of the destination web server that the client may use (by name
  or FPM/CLI path), prints it, and stops before any write for an unknown, inactive or ambiguous version. The choice
  is kept on resume; without `--php`, `target.server_php_id` still applies. A `--php` differing from an already
  created website stops instead of changing it.

## [1.2.5] - 2026-11-06

### Added

- Migration `state_dir` configuration setting: the per-site state, staging copy, backups and SQL snapshots can live
  on the website file system (e.g. `/var/www/ispcp-migration`) when the root file system is small. It does not
  change the configuration fingerprint, so a started migration continues after moving its directory; the command
  refuses to start over while the state is still in the previous location. Website roots remain refused.

### Fixed

- The migration plan checks the free space of the state file system before any write. Previously the staging
  copy could fill the root file system (`rsync ... No space left on device`).

### Upgrade notes

- Update hosting and run `sudo ispconfig-rest server-tools update --components migration --server ID`. To move a
  started migration: `mkdir -m 700 /var/www/ispcp-migration`, move its directory there, set `"state_dir"` (see the
  migration README) and repeat the original command.

## [1.2.4] - 2026-11-06

### Fixed

- Migration databases are created with a database quota derived from the client allowance. v1.2.3 omitted
  `database_quota`, which the API treats as unlimited and refuses for a client with a finite database quota
  (`quota-exceeded: limit_database_quota ... requested=unlimited`). The unallocated quota is split across the
  migrated databases in proportion to their source size; an unlimited plan keeps `-1`.
- Website traffic quota also follows the client allowance; `target.traffic_quota_mb` is ignored like
  `target.hd_quota_mb`, without changing existing configuration fingerprints.
- The plan validates the client count limits (websites, alias domains, subdomains, databases, database users)
  and measures the source read-only (website files with `du`, databases with `information_schema`) before the
  first write. Migrations that cannot fit now stop before provisioning instead of between created objects,
  during publication or with an over-quota database. The plan prints each quota with its source size, and
  verifies the old database route before any write.
- A resume refuses an uncertain previous create already during the plan.

### Upgrade notes

- Update hosting, then run `sudo ispconfig-rest server-tools update --components migration --server ID` and
  repeat the original command. Existing configuration and state are kept; objects created by an earlier attempt
  are reused, and a database refused by v1.2.3 is created on the retry.

## [1.2.3] - 2026-11-06

### Fixed

- Migration website disk quota now uses the client's remaining allocation from `/usage/summary`: plan limit
  minus quotas already assigned to websites, or unlimited for an unlimited plan. The plan displays the result
  and refreshes it before creating the website. Existing websites keep their quota on resume and final sync.
- Old `hd_quota_mb` configuration values no longer override the client's allowance. Existing configuration and
  state can be retained unchanged, including a migration rejected because the former 10 GB default exceeded a
  5 GB account. Traffic quota remains separately configured.
- REST refusals show recognized problem identifiers and numeric limit information without printing raw response
  bodies, request payloads or potentially reflected credentials.

### Upgrade notes

- After updating hosting, refresh the migration CLI with
  `sudo ispconfig-rest server-tools update --components migration --server ID`, then repeat the original command.
  No product limit or API permission is increased.

## [1.2.2] - 2026-11-06

### Fixed

- The installed migration CLI accesses its destination web server locally instead of connecting back to itself
  over SSH. Website checks, backups and file publication no longer need a self-SSH key or known-host entry.
  Local ISPConfig server identity is checked and filesystem transfers still drop to the website user's privileges.
- Existing installed-tool configuration and migration state work unchanged. Administrators running from a
  separate host can explicitly select `target.web_transport: "ssh"`; standalone source-tree runs retain SSH
  as their default. Source and database SSH connections keep strict host-key verification.

### Upgrade notes

- Update hosting, then run `sudo ispconfig-rest server-tools update --components migration --server ID` on the
  panel. Continue the original command on the destination web server without editing configuration or state.

## [1.2.1] - 2026-11-06

### Fixed

- Migration inventory accepts source `web_domain` tables without `server_php_id`. Newer sources retain their
  existing inventory value; the destination PHP selection still comes from the migration configuration.
- Failed source inventory queries identify the query section and MySQL error instead of reporting only
  `Source inventory query failed`. Connection failures report an error code without credential-bearing traces.

### Upgrade notes

- Update the hosting extension, then refresh the installed CLI from the panel:
  `sudo ispconfig-rest server-tools update --components migration --server ID`.
  Existing configuration and migration progress are preserved.

## [1.2.0] - 2026-11-06

### Added

- Optional `migration` server tool for websites moved from an old ISPConfig into accounts manually created by
  WHMCS. Install it on a new web server with `ispconfig-rest server-tools install --components migration --server ID`,
  then run `ispcp-migrate DOMAIN NEW_CLIENT_ID` after one-time connection setup. It supports source DB export through
  the old web server, client-scoped REST provisioning, file/SQL snapshots, WordPress configuration updates and final
  synchronization. [Installation and migration guide](site-migration/README.md).
- Migration-tool updates preserve configuration and saved progress, and refuse to replace code while the installed
  command is running. The tool is opt-in and adds no cron job or worker-table grants.

### Upgrade notes

- Existing hosting features remain compatible with ispconfig-rest 1.x from 1.1.0. The migration tool requires
  ispconfig-rest 1.4.2+ and one-time connection setup on the destination web server.
- Install the optional tool from the panel after updating hosting to v1.2.0:
  `sudo ispconfig-rest server-tools install --components migration --server ID`.

## [1.1.4] - 2026-10-28

### Security

- Database imports and copies discard unused SQL query output instead of writing it to the worker filesystem.
  Exported dump output and configured raw-SQL limits keep their existing behavior.

### Upgrade notes

- After updating the extension, refresh the database worker on the database servers:
  `sudo ispconfig-rest server-tools update --components database`.
- No migrations. Compatible with ispconfig-rest 1.x from 1.1.0.

## [1.1.3] - 2026-10-17

### Fixed

- `dns-catalog`: when ISPConfig processed several zone changes in one run (for example two deleted zones), only the first
  reached the catalog at once and the others waited for the five-minute timer. ISPConfig rewrites `named.conf.local`
  for each change, and a rewrite while the sync runs does not start its path unit again. The sync now repeats until the
  file stays as it was read (it waits two seconds for further rewrites).

## [1.1.2] - 2026-10-17

### Fixed

- `server-tools update` (and `status`) without `--components` covered only the default install selection, so it never
  updated `php-limits` or `dns-catalog` on the servers that have them, as documented. They now default to every
  component, and `update` still acts only on what each server has installed. To get the `php-limits` fix of 1.1.1 onto
  a server: `sudo ispconfig-rest server-tools update`.
- `php-limits` no longer writes `CPUAccounting=` into its units. systemd 258 and later (Ubuntu 26.04) removed the option
  and logged a warning at every start; cgroup v2 counts CPU time without it and `CPUQuota=` enables the CPU controller.

## [1.1.1] - 2026-10-17

### Fixed

- `php-limits` manages an FPM service of `Type=simple`, such as PHP 5.3 built by the Ansible roles, which has no
  systemd support: its dedicated pools run as simple services too. They were written as `notify` units, which wait for
  a readiness message that PHP 5.3 never sends. Packaged versions keep `notify`. (PHP 5.3 also needs ispconfig-ansible
  to install its FPM as `/usr/sbin/php-fpm5.3`, the packaged layout; until then it is reported as
  `unmanaged (exec_start_changed)`.)

## [1.1.0] - 2026-10-17

### Changed

- The file manager accepts every outgoing address of WHMCS: `--whmcs-ip` takes up to four IPv4 and IPv6 addresses,
  comma separated, and the WHMCS key is restricted to all of them. A WHMCS host with both IPv4 and IPv6 connects to a
  dual-stack webserver over IPv6, so with only its IPv4 address the file manager's login was refused and the file
  manager stayed unavailable. To add an address, rerun `server-tools install --components file-manager` with
  `--file-manager-key` and the full `--whmcs-ip` list; installations with one address keep working.

## [1.0.2] - 2026-10-17

### Changed

- Works with every ispconfig-rest 1.x from 1.1.0 (`requires` is now `>=1.1.0 <2.0.0`), so a new minor release of the
  core such as 1.2.0 keeps loading the extension without waiting for a release of it. A core 2.0 needs an extension
  release that declares it.

## [1.0.1] - 2026-10-17

### Fixed

- Installing the `file-manager` server tool on a webserver without bubblewrap (Ubuntu 26.04) also installed
  `default-mysql-client`, which on Ubuntu is MySQL's client and made apt remove the server's MariaDB. The installer now
  adds only what is missing, uses the MariaDB client where MariaDB is installed, and the worker installers let apt
  abort instead of removing any package (`--no-remove`). To repair a server it happened to, reinstall MariaDB:
  `apt-get install mariadb-server mariadb-client` (its data and configuration were kept).

## [1.0.0] - 2026-10-11

First release as an extension, for ispconfig-rest 1.1. Install it with `sudo ispconfig-rest extension:install hosting`
right after updating ispconfig-rest; see the [README](README.md#upgrade-from-ispconfig-rest-10x).

### Added

- The hosting features of ispconfig-rest up to 1.0.7 as an extension for ispconfig-rest 1.1 (spec 058 of
  ispconfig-rest): database operations, website logs and runtime/PHP settings, scheduled task output logs, file
  manager and WordPress tools, website WAF, product PHP policies and PHP-FPM limits, DNS catalog zones and the server
  tools. Endpoints, fields, database tables and workers are unchanged; the history of these files is kept.
- `bin/ispconfig-rest-extension`: the `server-tools`, `workers:*`, `waf:*`, `php-limits:*` and `dns-catalog:*`
  commands of the ispconfig-rest manager, run from its verified copy.
- The served OpenAPI document gains the extension's paths and fields (`api/openapi.yaml`, `api/patches/`).

### Changed

- PHP classes moved from `App\` to `IspconfigRestHosting\` (`src/`); worker installers read `src/Support/`.
- The server tools fetch worker sources from this repository at the extension's installed commit and ref.
