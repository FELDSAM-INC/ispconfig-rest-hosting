# Changelog

All notable changes to ispconfig-rest-hosting. The format follows [Keep a Changelog](https://keepachangelog.com/),
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
