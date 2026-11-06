# Changelog

All notable changes to ispconfig-rest-hosting. The format follows [Keep a Changelog](https://keepachangelog.com/),
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
