# Let's Encrypt once the domain points to the server

After a website migration the domain still points to the old server until DNS caches expire (two hours for the
first migrated Plesk website). ISPConfig 3.3.1p1 requests a certificate only while it processes the change that
enables Let's Encrypt: it fetches a random file through every name (`letsencrypt.inc.php`
`assemble_domains_to_request`), leaves out the names that do not reach the server, and when none is left switches
`ssl_letsencrypt` (and `ssl` when it was off) back off with plain UPDATEs (`apache2_plugin.inc.php` 1305-1330,
`nginx_plugin.inc.php` 1374-1399). There is no retry, so the customer has to come back and enable HTTPS again.
Plesk instead keeps watching DNS and issues the certificate once the domain resolves to the server.

## Owner decisions (2026-11-08)

- Issue as soon as the preferred name points to the server, and add the other names later. The preferred name is
  `www` when the website redirects to www (`non_www_to_www`, `*_domain_tld_to_www_domain_tld`, `*_to_www_domain_tld`),
  otherwise the domain: a certificate without the name visitors end on is of no use.
- Panel (WHMCS) and REST only; `ispcp-migrate` does not start waits.

## Requirements

1. `GET/PUT/DELETE /sites/web-domains/{id}/ssl/letsencrypt-wait` (vhost, vhostsubdomain, vhostalias). `PUT` needs
   website update permission, an unlocked account, SSL and Let's Encrypt in the plan, an active website and a public
   address to compare with; it starts or restarts the wait and checks once in the request. `redirect_https` switches
   the redirect to HTTPS on after issuance. `DELETE` ends the wait and keeps applied settings.
2. **Names** as ISPConfig requests them: the domain (a wildcard website's base domain), `www.` for `www` and `*`
   websites, active subdomains and aliases (with their `www.`) whose `ssl_letsencrypt_exclude` is not `y`.
3. **Expected addresses**: the website's own IPv4/IPv6 address when it has a public one, otherwise the public
   `server_ip` addresses of its server (shared or of the owner), or `LETSENCRYPT_WAIT_SERVER_ADDRESSES` (JSON per
   server id) behind NAT.
4. **DNS check** through public resolvers (`LETSENCRYPT_WAIT_RESOLVERS`, default 1.1.1.1, 8.8.8.8, 9.9.9.9) over UDP,
   never the panel's resolver, which may be authoritative for the zone. A name points when at least two resolvers
   (all when fewer are configured) answer and every answer has IPv4 addresses that are all expected and only expected
   IPv6 addresses (the CA prefers IPv6). Every 5 minutes during the first day, then every 30 minutes, up to 7 days.
5. **Issuance** through the normal website update (`ssl` + `ssl_letsencrypt`), journaled as the account that started
   the wait; a renewal (forced no-change entry) when Let's Encrypt is already on. The request is processed when the
   server's `updated` reaches the entry. Let's Encrypt off afterwards, or a certificate without the preferred name,
   is a failed attempt; one not processed within 30 minutes too. Retry after 15 minutes, at most 5 attempts. A plan
   without Let's Encrypt at that moment, or a website update that refuses SSL (no SNI), fails the wait at once.
6. **Certificate names** are read fresh from the certificate the web server presents (core `TlsCertificateProbe`, the
   website's IP address, then its server's name). Names left out are watched (`extending`) and added with a renewal
   at most once an hour when they point to the server; the wait completes when all are in the certificate, or as
   `partial` when it expires.
7. A manual SSL change, a rename, a transfer or deletion of the website ends the wait. Finished waits are removed
   after 30 days. `letsencrypt_wait` on websites shows the state.

## Verification

`tests/Unit/DnsLookupTest.php` (codec, a UDP responder child process with a dropped packet and a silent resolver),
`tests/Feature/LetsEncryptWaitApiTest.php` (state machine, resolver agreement, IPv6, names, permissions, cancellation,
retries, expiry, scheduler). The DNS client was checked against the public resolvers.
