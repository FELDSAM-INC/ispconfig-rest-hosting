# Changelog

All notable changes to ispconfig-rest-hosting. The format follows [Keep a Changelog](https://keepachangelog.com/),
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- `ispcp-migrate --from plesk example.com CLIENT --subscription` migrates the subscription's other websites
  (additional domains, subdomains with a folder of their own) in the same run, each as a **website of its own**
  (system user, quota, cgroups, databases, cron jobs, PHP and DNS zones), instead of 1.12.0's domains with their own
  folder of one website. The run plans every website, checks the client's limits for all of them, asks once and
  migrates them one after another; a website waiting for the review of its prepared files does not stop the others.
  The websites are kept in the main domain's state for `--sync` and `--status`.
- A new website gets twice the size of its files as disk quota, at least 1 GB, and a new database twice its size, at
  least 1 GB; the rest of the client's quota stays free for other websites. Before, a migrated website took the
  client's whole unallocated disk quota (e.g. 20 GB) and its databases the whole database quota. When the client's
  quota cannot hold the reserves, it is shared among the websites and databases still to create.

### Fixed

- A Plesk website takes the databases its configuration uses (`wp-config.php` and other configuration files, read
  on Plesk as the subscription's user), and those Plesk assigns to it that no website's configuration names. Plesk
  often assigns all of a subscription's databases to its main domain, so migrating the main domain took the other
  websites' databases too. A migration that has already created objects keeps the databases it chose.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.13.0`, then
  `ispconfig-rest server-tools update --components migration --server <id>` (the Plesk helper reads the websites'
  configuration). No database migration. A migration started with 1.12.0's `--subscription` stops with instructions:
  delete its website with its domains in the panel and move its state directory aside before starting again.

## [1.12.0] - 2026-11-13

### Added

- `ispcp-migrate --from plesk example.com CLIENT --subscription` migrates a whole Plesk subscription as one website,
  as in Plesk's webspace: its additional domains (and subdomains with a folder of their own) become domains with their
  own folder (`vhostalias`, the folder they have in the webspace, e.g. `shop.example/` next to `web/`), with their
  Plesk PHP version and OPcache, their files, DNS zones and cron jobs, and all of the subscription's databases. Before,
  each additional domain was migrated as a website of its own, and the main domain took every database, because
  Plesk often assigns them all to the subscription's main domain. Later runs keep the option.

### Changed

- A migration whose earlier runs created nothing yet (e.g. only `--plan`) takes over a changed source inventory
  instead of stopping, so options such as `--subscription` or `--database` can still change.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.12.0`, then
  `ispconfig-rest server-tools update --components migration --server <id>`. No database migration. A migration of a
  subscription's main domain started without `--subscription` keeps its inventory; to migrate the whole subscription,
  delete the new website with its databases and database users, move the state directory aside and start again.

## [1.11.2] - 2026-11-13

### Fixed

- `ispcp-migrate` creates alias domains and subdomains sharing the website's folder in the website's Let's Encrypt
  certificate, as the panel does (*Include the alias in the certificate of the main website*). Before, they were
  left out of it, so HTTPS on an alias such as `example.sk` of `example.com` needed the switch in the panel. ISPConfig
  leaves out a name whose DNS does not point to the new server yet, and the Let's Encrypt wait adds it later.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.11.2`, then
  `ispconfig-rest server-tools update --components migration --server <id>`. No database migration. Aliases migrated
  before stay out of the certificate; switch on *Include the alias in the certificate of the main website* in the
  panel.

## [1.11.1] - 2026-11-13

### Fixed

- `ispcp-migrate --from plesk` keeps the DNS zone of a domain alias in step with the domain's when Plesk does
  (*Synchronize DNS zone with the primary domain*, e.g. an alias `example.sk` of `example.com`): once the domain's zone
  is created, the alias's DNS synchronization is switched on, so the alias's zone is a read-only copy of the domain's,
  as in the panel. Before, Plesk's copy became a zone of its own and later changes of the domain's zone did not reach
  it. Without the domain's zone in the migration, or for an alias used only for mail or DNS, the zone is still copied
  on its own, and the plan says so.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.11.1`, then
  `ispconfig-rest server-tools update --components migration --server <id>` (the Plesk helper also reads the alias's
  DNS switch). No database migration. Aliases migrated before keep zones of their own; switch on the alias's DNS
  synchronization in the panel where Plesk had it.

## [1.11.0] - 2026-11-13

### Fixed

- `ispcp-migrate --from plesk` gives the new website, and each subdomain with its own folder, OPcache as Plesk ran
  it, read from the domain's generated `php.ini` or, when that does not set it, from the PHP handler's configuration
  (on when Plesk does not tell). Since 1.8.0 migrated websites started with the new-site default OPcache off, and a
  WordPress site with many plugins then needed 127 MB instead of 46 MB for its homepage, exceeded the 128 MB memory
  limit and answered 503. The plan shows the setting; it is applied once through the website's PHP settings, so a
  change made in the panel stays during sync rounds.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.11.0`, then update the migration tool on the web server that
  runs migrations: `ispconfig-rest server-tools update --components migration --server <id>`. No database migration.
- Websites migrated with 1.8.0–1.10.0 keep OPcache off; switch it on in the panel where Plesk had it on.

## [1.10.0] - 2026-11-12

### Changed

- The WAF's outbound rules (OWASP CRS `RESPONSE-95x`: PHP error messages, PHP source code or SQL errors in a page)
  only report: their findings stay in the audit log and the website's WAF events, but a response is no longer
  blocked (`959100`/`959101` are removed in the generated `owasp.conf`). On shared hosting they mostly matched
  ordinary content, for example a PHP code sample in an article (`953120`), a shop text like `<b>5</b> in all`
  (`953100`) or a `warning` CSS class with `sqlite_` elsewhere in a WordPress admin page (`951250`); Apache answered
  403 and nginx cut the page off, and the visitors counted towards WAF bans. Website exceptions added for these rules
  can be removed. Attacks in requests are blocked as before.
- The weekly `crs-update` workflow also moves the rule exclusion plugins to their newest commit that changes their
  rule files (SHA-256 pins, native Apache and nginx checks, commit to `develop`, issue to release).

### Fixed

- The WordPress, Nextcloud, DokuWiki and XenForo application profiles use the official CRS rule exclusions of the
  upstream main branch instead of the last release tag, which lacks later false-positive fixes (WordPress 1.2.0 is
  from 2025, DokuWiki and XenForo 1.0.0 from 2024). At the default paranoia level 1, WordPress 1.2.0 still blocked,
  for example, link embedding in the editor (`parse-embed`) and saving a post opened from a filtered post list
  (`referredby`); the newer exclusions also cover the login redirect, search, media captions and plugin zip uploads,
  partly at higher paranoia levels. Plugins are pinned by commit and SHA-256 in `waf-server/crs.json`.

### Upgrade notes

- An install checked out before the history rewrite of 2026-11-09 first re-fetches the tags (see 1.9.0).
- `ispconfig-rest extension:update hosting --tag v1.10.0 && ispconfig-rest server-tools update --components waf --yes`
  (every web server with the WAF; it downloads the pinned plugin files from `raw.githubusercontent.com` and rewrites
  `owasp.conf`). Coming from 1.7.x, also update the migration tool as in 1.8.0. No database migration.
- Website exceptions for outbound rules (`951…`–`956…`, for example `953100`, `953120`, `951250`) are no longer needed
  and can be removed in the panel.

## [1.9.0] - 2026-11-09

### Added

- PHP `error_reporting` choice `E_ALL & ~E_WARNING & ~E_NOTICE & ~E_DEPRECATED & ~E_STRICT`: errors are logged,
  warnings, notices and deprecations are not.

### Changed

- New websites start with that `error_reporting` (besides OPcache off and `short_open_tag` on), so their logs are not
  filled with warnings; the customer can change it in the panel. Existing websites keep their settings.
  `WEB_PHP_NEW_SITE_DEFAULTS` also accepts `error_reporting` (one of the panel's choices).

### Upgrade notes

- The repository history was rewritten on 2026-11-09 (every commit and tag has a new hash). An install checked out
  before that first re-fetches the tags, as root:
  `. /etc/ispconfig-rest/install.conf; sudo -u "$RUN_USER" git -C "$INSTALL_DIR/extensions/hosting" fetch --force --tags origin`
- `ispconfig-rest extension:update hosting --tag v1.9.0`. No database migration and no change to the server tools
  (coming from 1.7.x, also update them as in 1.8.0).
- Existing websites keep their PHP settings; `WEB_PHP_NEW_SITE_DEFAULTS` in the API's `.env` overrides the new
  defaults as before.

## [1.8.0] - 2026-11-09

### Changed

- New websites (with subdomain and alias websites that have their own folder) start with OPcache off and
  `short_open_tag` on in their own PHP settings, which the customer can change in the panel. Existing websites keep
  their settings. `WEB_PHP_NEW_SITE_DEFAULTS` in the API's `.env` sets other on/off defaults (`{}`: the server's
  `php.ini`), see [website PHP settings](docs/website-php-settings.md).
- `ispcp-migrate --from plesk` changes the old document root in the copied configuration to the new website's, e.g.
  Wordfence's `auto_prepend_file` in `.user.ini` and the paths in `wordfence-waf.php` (with the PHP-FPM chroot,
  `/web/…` in the files only PHP reads). The files are printed and listed in `configuration-report.json`
  (`old_paths_rewritten`); what still names the old webspace stops publication for review as before.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.8.0 && ispconfig-rest server-tools update --components migration --server 4`
  (the web server with the migration tool). No database migration.
- Existing websites keep their PHP settings; only websites created after the update start with OPcache off and
  `short_open_tag` on. `WEB_PHP_NEW_SITE_DEFAULTS={}` in the API's `.env` keeps the previous behaviour.

## [1.7.0] - 2026-11-09

### Added

- `ispcp-migrate --from plesk` recreates the website's DNS zones in the new ISPConfig: the zones of the domain, its
  aliases and the subdomains migrated with it, when Plesk serves them (switched on, and their public NS records
  include one of the zone's Plesk name servers). Records, TTLs and SOA timers are copied; the zone's NS records and SOA
  primary become the name servers of the client's DNS server, A/AAAA records with an address of the Plesk server get
  the new web server's address, SPF/DMARC become ISPConfig's SPF/DMARC records (same rules, ISPConfig's order) and
  DKIM is copied verbatim. What ISPConfig cannot hold (DMARC in a zone without DKIM, unusual SPF/DMARC, other record
  types) and records it refuses are listed as `MANUAL`. The zones are created with the client's key after the copy
  (inactive, the records, then switched on), and the plan checks the client's DNS limits. `--dns` creates only the
  zones, e.g. for websites copied earlier; `--no-dns` skips them.
- `ispcp-migrate --from plesk` gives the new website the PHP version of the Plesk domain (`alt-php74-fpm` → 7.4), and
  each subdomain with its own folder its own version. A version the new web server does not offer stops the plan
  before any write; `--php` chooses another one, for the website and its subdomains.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.7.0 && ispconfig-rest server-tools update --components migration --server 4`
  (the web server with the migration tool).
- The client needs a DNS server in the new ISPConfig for the DNS zones (else the plan stops; `--no-dns` migrates
  without them). Websites copied earlier get their zones with `ispcp-migrate --from plesk DOMAIN CLIENT_ID --dns`.

## [1.6.2] - 2026-11-08

### Changed

- `ispcp-migrate --from plesk` no longer migrates WordPress cron: WP Toolkit's jobs (`php -f httpdocs/wp-cron.php`,
  whatever their PHP version or description) and fetches of `wp-cron.php` are left out, with one note in the plan to
  turn on the website's WordPress cron in the panel after the DNS switch. Websites migrated earlier keep their
  inactive `wp-cron.php` job; delete it before turning the WordPress cron on, it counts against the cron job limit.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.6.2 && ispconfig-rest server-tools update --components migration --server 4`
  (the web server with the migration tool).

## [1.6.1] - 2026-11-08

### Fixed

- WordPress tools on websites with PHP 5.6 to 7.4 failed with "the matching PHP CLI runtime is unavailable"
  (`unsupported_php_layout`). The sandbox checked the CLI with `php -n` and `json_encode()`, but before PHP 8.0 json
  is an extension of its own (`json.so`), which `-n` does not load; WP-CLI did not get it either. The check now uses
  core functions only and `json.so` is loaded where it exists. The verification file served through the website no
  longer uses `??`, which PHP 5.6 cannot parse. Checked with the Sury packages of PHP 5.6, 7.0, 7.4 and 8.3 and
  WP-CLI 2.12.0.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.6.1 && ispconfig-rest server-tools update --components file-manager --yes`
  updates the WordPress sandbox on the web servers.

## [1.6.0] - 2026-11-08

### Added

- Let's Encrypt once the domain points to the server (spec 059): `PUT /sites/web-domains/{id}/ssl/letsencrypt-wait`
  waits until the website's preferred name (www when the website redirects to www, otherwise the domain) resolves to
  its server's public addresses at the public resolvers 1.1.1.1, 8.8.8.8 and 9.9.9.9, then enables Let's Encrypt
  through the normal website update. ISPConfig itself tries only once and switches Let's Encrypt off when the domain
  does not reach the server yet. Checks run every 5 minutes during the first day, then every 30 minutes, for up to
  7 days; names that still point elsewhere are added with a renewal when they point too, `redirect_https` switches the
  redirect to HTTPS on after issuance, and a failed issuance is retried five times. `GET` shows every name with the
  addresses found and whether the certificate covers it, `DELETE` stops waiting, and websites carry
  `letsencrypt_wait`. A manual SSL change, a rename, a transfer or deletion ends the wait.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.6.0` adds the table and the `letsencrypt:wait` task of the API
  scheduler (run `ispconfig-rest schedule:install` if `/etc/cron.d/ispconfig-rest` is missing). The
  panel needs outgoing DNS (UDP 53) to the resolvers, and ISPConfig's server IP list must hold the web servers'
  public addresses, IPv6 included where domains have AAAA records; behind NAT set `LETSENCRYPT_WAIT_SERVER_ADDRESSES`.

## [1.5.0] - 2026-11-08

### Added

- WAF rule exceptions accept a path prefix: a path ending in `*` (`/admin/pages/edit/*`) covers every page below it,
  for example `/admin/pages/edit/102`. The prefix is compared with the URL-decoded request path after dot segments and
  repeated slashes are removed, so `/admin/pages/edit/../other` or `/admin/pages/edit/%2e%2e/other` do not match it.
  Exact paths work as before.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.5.0 && ispconfig-rest server-tools update --components waf --yes`
  updates the API and the WAF worker on every web server. Update the workers before customers save a prefix. An older
  worker cannot read a website with a prefix exception, so it stops collecting that website's events and honouring its IP
  allowlist for bans until it is updated.

## [1.4.0] - 2026-11-08

### Added

- `ispcp-migrate --from plesk` migrates websites of a Plesk Obsidian (Linux) server, and `ispcp-migrate --sites --from
  plesk` lists which of them are live. The Plesk server is configured once under `sources` in the configuration; it
  needs only root SSH and its own Python 3.6+, and nothing is written there: metadata comes from `plesk db` SELECTs,
  files and sizes are read as the subscription's system user, dumps run as the Plesk administrator with the password
  passed through a pipe. The document root becomes `web/`; `www.` and a wildcard subdomain, aliases (Plesk's 301 to the
  domain included), subdomains in the same folder or inside the document root, the domain's local MySQL/MariaDB
  databases (`--database NAME` selects others of the subscription) and the subscription's cron jobs are migrated. Cron
  jobs get the new paths and PHP CLI and are created **inactive**; jobs ISPConfig or the client's plan cannot run are
  listed for manual review. Configuration files that still name the old webspace (e.g. Wordfence's `.user.ini`) stop
  publication for review. Everything else is listed in the plan. A wildcard subdomain the client's plan does not allow
  stops the migration before any write, for ISPConfig sources too.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.4.0 && ispconfig-rest server-tools update --components migration --server 4`
  installs `plesk-source.py`. Existing configuration and migration state are unchanged; add the Plesk server under
  `sources` in `/etc/ispconfig-rest-migration/config.json` (see the migration README) and give root on the new web
  server key-based SSH to it with a verified host key.

## [1.3.4] - 2026-11-08

### Fixed

- WordPress checks and scans no longer fail with `site_not_applied` on a website whose `web_folder` is `''` on the
  panel and `NULL` on the web server. ISPConfig's datalog does not replicate that difference, so the worker now
  treats them as equal, as ISPConfig does; every other difference between the panel and the web server copy is
  still refused.
- A missing or broken PHP CLI for the website's PHP version is reported as `unsupported_php_layout` instead of
  `worker_failed`. Other unexpected sandbox failures write their exception class, file and line to the
  `ispconfig-rest-wordpress` journal (`wordpress_sandbox_failed`), never messages or site content.

### Upgrade notes

- `ispconfig-rest extension:update hosting --tag v1.3.4 && ispconfig-rest server-tools update --components file-manager`
  installs the WordPress worker on the web servers and restarts it. No migrations.

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
