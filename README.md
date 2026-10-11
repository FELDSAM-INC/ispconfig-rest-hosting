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

The endpoints and fields are the same as in ispconfig-rest up to 1.0.7, where these features shipped; the served
OpenAPI document at `/api/documentation` includes them while the extension is installed.

## Install

On the REST host, with ispconfig-rest 1.1 installed:

```sh
sudo ispconfig-rest extension:install hosting                 # follows main
sudo ispconfig-rest extension:install hosting --tag v1.0.0    # or a pinned release
sudo ispconfig-rest server-tools install --help               # workers on the ISPConfig servers
```

New installations can add `--extension hosting` (or `hosting@v1.0.0`) to ispconfig-rest's `install.sh`.
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
sudo ispconfig-rest update --tag v1.1.0      # or --branch main
sudo ispconfig-rest extension:install hosting
sudo ispconfig-rest server-tools update      # refreshes the workers from this repository
```

Between the two commands the hosting endpoints are unavailable; run them together. The workers already installed on
the servers keep working; `server-tools update` replaces them with the same code from this repository.

## Server tools

[server-tools/README.md](server-tools/README.md) covers automatic ISPConfig server discovery, SSH key setup,
component selection and the file-manager public key.

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
