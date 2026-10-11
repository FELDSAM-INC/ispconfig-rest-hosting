# Changelog

All notable changes to ispconfig-rest-hosting. The format follows [Keep a Changelog](https://keepachangelog.com/),
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
