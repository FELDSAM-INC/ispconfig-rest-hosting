# WAF attackers: IP filter, clients and bans

Website owners cannot find false positives among attack traffic, and the WAF only
scores attacks, it never stops an attacker who keeps trying. Add an IP filter and a
per-client view to the WAF events, keep one client from evicting the others, and
ban attacking clients on the web server with fail2ban.

## Production evidence (2026-11-06)

One website on the new web server, about six hours after WAF was enabled: three of 44 client
addresses produced about 1,850 of 2,000 rule events.

| Client | Activity | Rule events | Requests |
| --- | --- | --- | --- |
| `198.18.34.229` | secret-file scan (`.env*`, cloud credentials, `phpinfo`), 245 paths in 42 s; 920440/920500/930130 | 501 | about 170, none over the anomaly threshold |
| `198.18.45.59` | 18 login/auth endpoints with malformed `Content-Type` charsets for 7 minutes; 920480/920530 | 977 | about 325, none over the threshold |
| `198.18.93.178` | SQL injection on `/`; 942100/942151/942190/942500 | 370 | 74 over the threshold in 2.5 minutes, all blocked |

The other 41 addresses had at most four requests over the threshold each. The worker
kept the newest 1,000 events per website, so a single scanner could evict
everything else, including the false positives the owner was looking for. A score
below the threshold is never blocked, so the second scanner was never stopped.

## Requirements

1. **Retention.** Keep at most 100 events per client address and website (newest
   first) within the existing 1,000 per website and 7 days. Count every event and
   request of a client per website in `api_web_waf_clients` (events, requests,
   requests over the anomaly threshold, first and last seen; kept for 7 days after
   the last request), so totals stay correct when events are not stored.
2. **API.** `GET /sites/web-domains/{id}/waf/events` accepts `client_ip` (an address
   or CIDR block) and `banned` (`true`/`false`), and reports `client_banned` for each
   event. `GET /sites/web-domains/{id}/waf/clients` lists the website's clients with
   their totals and ban (reason, start, expected end), ordered by requests, with the
   same `client_ip` filter and paging. Same tenant authorization as the events.
3. **Bans.** The root WAF worker of each web server evaluates every client address
   over a rolling 10 minutes across all WAF-enabled websites of that server:
   - **A (attack):** at least 20 requests over the anomaly threshold (949110/949111
     inbound, 959100/959101 outbound) on websites in enforcing mode;
   - **B (scan):** at least 15 distinct paths among requests that matched scanner,
     protocol or restricted-file rules (913xxx, 920xxx, 921xxx, 930xxx), on websites
     in detection or enforcing mode. Injection rules (932/941/942 …) do not count
     for B: they are the usual false positives of normal browsing.

   A matching client is written to `/var/log/ispconfig-waf/bans.log`. The fail2ban
   jail `ispconfig-waf` bans it on HTTP and HTTPS of that server for one hour;
   `ispconfig-waf-recidive` bans it for a week after three bans within a day.
   Owner decisions: websites are not behind proxies, bans start immediately (no
   observation phase), and websites in detection mode count only for B.
4. **Never banned:** addresses and blocks in the IP allowlist of any WAF website on
   the server (a client banned before it was allowlisted is unbanned within a
   minute), loopback, private and reserved addresses, the server's own addresses
   (fail2ban `ignoreself`), and entries of `/etc/ispconfig-waf/ban-ignore.conf`.
5. **Administration.** Thresholds, window and on/off in the optional root-owned
   `/etc/ispconfig-waf/ban.local.json`; the installer keeps it. The worker reports
   the jails' current bans to `api_web_waf_bans` every minute. `ispconfig-waf bans`
   lists them, `ispconfig-waf unban ADDRESS` lifts one.
6. **WHMCS.** The WAF tab gets an IP filter (address or CIDR) and "hide banned
   clients" for the events, a clients table (requests, over threshold, last seen,
   banned) and "show only this client" from an event or client. Customers cannot
   unban: a ban covers every website of the server. Adding their own address to the
   website's IP allowlist lifts it within a minute.

## Validation

- Unit: ban rules A/B with window expiry, enforcing/detection modes, ignored
  addresses and allowlists, bounded state; request grouping of audit records;
  per-client retention and totals.
- Feature: event filters (address, CIDR, banned), clients endpoint, tenant isolation,
  invalid filters.
- Native: fail2ban filter against the worker's ban lines (`fail2ban-regex`) and the
  generated jails accepted by fail2ban, in the WAF test container.
- WHMCS module suite on PHP 7.4 and 8.3, both themes.

## Implementation (hosting 1.3.0)

`WebWafBans` holds the ban rules and address matching (worker and API), `WebWafCollector` the worker's
master-database side; `waf-server/run.php` only glues them to the audit reader. The worker decides, fail2ban only
enforces (`maxretry = 1` on the worker's lines), so both rules, the website modes and the allowlists stay in one
tested place. The third ban within a day is decided by the worker as `reason=repeat` for the recidive jail, instead
of parsing fail2ban's own log. Only newly stored events count for totals and bans, so a parser upgrade's re-read
of the audit tail is not counted twice.

Verified: hosting suite 249 tests on PHP 8.3 (as root and as a user); `tests/Integration/waf/collector.sh` on
Ubuntu 24.04 with MariaDB and fail2ban: per-client retention and totals, the 1,000-event cap, re-reads, ban
mirroring and unbanning, the filters with `fail2ban-regex`, both jails with `fail2ban-client -t`, and the installed
worker end to end (two websites, audit logs, a running fail2ban with the dummy action banning the attacker and the
scanner, mirrored with their reasons, nothing decided or counted twice on the next run); the native Apache and
nginx installer and engine checks on Debian 13. The replay of the production clients of 2026-11-06 bans exactly
the three attackers.
