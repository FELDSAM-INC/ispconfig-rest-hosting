# ispconfig-rest-hosting

Hosting features for the [ISPConfig REST API](https://github.com/FELDSAM-INC/ispconfig-rest), as an extension
(spec 058). They power the FeldHost WHMCS integration and need workers on the ISPConfig servers:

| Feature | API | Server component |
| --- | --- | --- |
| Database import, export and copy | `/sites/databases/{id}/operations`, `operations` on databases | [database worker](worker/README.md) |
| Website access/error logs, scheduled task output logs | `/sites/web-domains/{id}/logs/{kind}`, `/sites/cron-jobs/{id}/log`, `logs_available`, `output_log` | [web log worker](web-log-worker/README.md) |
| Website runtime settings (public subfolder, environment) and PHP settings | `runtime_settings`, `php_settings`, `runtime_capabilities`, `public_document_root` on websites | [web log worker](web-log-worker/README.md), [guide](docs/website-php-settings.md) |
| File manager and WordPress tools | `/sites/web-domains/{id}/wordpress`, `wordpress` on websites and scheduled tasks | [file manager worker](file-manager-worker/README.md), [guide](docs/WORDPRESS-TOOLS.md) |
| Website WAF (ModSecurity, OWASP CRS) | `/sites/web-domains/{id}/waf`, `waf_available`, `waf_mode` | [WAF installer](waf-server/README.md) |
| Product PHP policies and PHP-FPM limits | `web_php_policy`, `web_resource_limits` on clients, `/usage/resources` | [PHP-FPM limits](php-limits/README.md), [guide](docs/product-php-policy.md) |
| DNS catalog zones for secondaries | — | [DNS catalog](dns-catalog/README.md) |
| Old ISPConfig website migration into WHMCS-created accounts | Existing core REST endpoints | [Migration CLI](site-migration/README.md), `ispcp-migrate DOMAIN NEW_CLIENT_ID` |

The endpoints and fields are the same as in ispconfig-rest up to 1.0.7, where these features shipped; the served
OpenAPI document at `/api/documentation` includes them while the extension is installed.

## Install

On the REST host, with ispconfig-rest 1.1 or a later 1.x installed:

```sh
sudo ispconfig-rest extension:install hosting                 # follows main
sudo ispconfig-rest extension:install hosting --tag v1.2.3    # or a pinned release
sudo ispconfig-rest server-tools install --help               # workers on the ISPConfig servers
```

New installations can add `--extension hosting` (or `hosting@v1.2.3`) to ispconfig-rest's `install.sh`.
`ispconfig-rest update` also updates the extension on its own channel (branch or pinned release);
`ispconfig-rest extension:update hosting [--branch NAME | --tag VERSION]` changes or updates it alone.
`ispconfig-rest extension:list` shows whether it is loaded. A release states the ispconfig-rest versions it supports
in [extension.json](extension.json); an incompatible extension is not loaded and reported there.

The extension lives in `/opt/ispconfig-rest/extensions/hosting`, owned by the API's run user like the API itself. Its
command-line tools (`server-tools`, `workers:*`, `waf:*`, `php-limits:*`, `dns-catalog:*`) run as root from a copy
the manager takes from the verified published commit of this repository, never from that checkout.

### Upgrade from ispconfig-rest 1.0.x

Installations up to 1.0.7 had these features built in. Their database tables keep the same migration names, so
nothing is migrated again:

```sh
sudo ispconfig-rest update --tag v1.4.2      # or --branch main
sudo ispconfig-rest extension:install hosting
sudo ispconfig-rest server-tools update      # refreshes the workers from this repository
```

Between the two commands the hosting endpoints are unavailable; run them together. The workers already installed on
the servers keep working; `server-tools update` replaces them with the same code from this repository.

## Server tools

[server-tools/README.md](server-tools/README.md) covers automatic ISPConfig server discovery, SSH key setup,
component selection and the file-manager public key.

The optional [migration tool](site-migration/README.md) installs on a selected new web server through
`ispconfig-rest server-tools install --components migration --server ID`. After one-time connection setup,
run `ispcp-migrate example.com 123` there as root (`123` is the new ISPConfig client ID). It reads the old
ISPConfig through root SSH, can export the old database through the old web server, and creates destination
resources through client-scoped REST permissions. Product changes and **Create** in WHMCS remain manual.
This component requires hosting v1.2.0+ and ispconfig-rest v1.4.2+.

## Let's Encrypt when the domain points to the server

ISPConfig requests a Let's Encrypt certificate only once, while it applies the change that enables it, and switches
Let's Encrypt off again when the domain does not reach the server yet (for example right after a migration, until
DNS caches expire). `PUT /api/v1/sites/web-domains/{id}/ssl/letsencrypt-wait` keeps the request instead: the API asks
public resolvers (1.1.1.1, 8.8.8.8 and 9.9.9.9) every 5 minutes during the first day, then every 30 minutes, for up to
7 days, and enables Let's Encrypt as soon as the website's preferred name (www when it redirects to www) points to
the server. Names that point elsewhere are added to the certificate later. The redirect to HTTPS can follow the
certificate. See [spec 059](specs/059-letsencrypt-dns-wait/spec.md).

It needs the API scheduler (`ispconfig-rest schedule:install`, set up by the installer) and outgoing DNS (UDP 53) from
the panel to the resolvers. The names must resolve to the public addresses in ISPConfig's server IP list, IPv6
included when the domains have AAAA records. Behind NAT, set the public addresses in the API's `.env`:
`LETSENCRYPT_WAIT_SERVER_ADDRESSES={"4": ["203.0.113.10", "2001:db8::10"]}` (server id 4). Other resolvers:
`LETSENCRYPT_WAIT_RESOLVERS=1.1.1.1,8.8.8.8,9.9.9.9`.

## Development

The extension runs inside an ispconfig-rest checkout:

```sh
git clone https://github.com/FELDSAM-INC/ispconfig-rest.git && cd ispconfig-rest
composer install && cp .env.example .env && php artisan key:generate
git clone https://github.com/FELDSAM-INC/ispconfig-rest-hosting.git extensions/hosting
cd extensions/hosting && ../../vendor/bin/phpunit
```

The PHP code is the `IspconfigRestHosting\` namespace in `src/`; [HostingServiceProvider](src/HostingServiceProvider.php)
registers routes, migrations and the hooks that add fields and behaviour to ispconfig-rest's websites, scheduled
tasks, databases and clients. The contract is in [api/](api/): `api/openapi.yaml` lists the paths merged into the
served document, `api/patches/` adds properties to ispconfig-rest's schemas. Worker and integration tests are
described next to each component.

## License

BSD-3-Clause, like ispconfig-rest.
