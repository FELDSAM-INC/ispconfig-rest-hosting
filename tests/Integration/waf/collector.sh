#!/usr/bin/env bash
# Spec 048 on MariaDB and fail2ban: the WAF worker's master-database side (WebWafCollector) and the shipped fail2ban
# filters/jails against the worker's ban lines. Disposable container only.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
image=ispcp-waf-collector-test
docker build -q -t "$image" - <<'DOCKERFILE' >/dev/null
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends php-cli php-mysql php-mbstring mariadb-server mariadb-client fail2ban ca-certificates && rm -rf /var/lib/apt/lists/*
DOCKERFILE
docker run --rm -i -v "$root:/repo:ro" "$image" bash -s <<'SCRIPT'
set -euo pipefail
mkdir -p /run/mysqld && chown mysql:mysql /run/mysqld
mariadbd --user=mysql --skip-networking > /tmp/mariadb.log 2>&1 &
for attempt in $(seq 1 60); do mysqladmin ping --silent && break; sleep 1; done
php /repo/tests/Integration/waf/collector.php

# The worker's lines: two for the base jail, one for the recidive jail.
mkdir -p /var/log/ispconfig-waf
php -r 'require "/repo/src/Support/WebWafBans.php"; use IspconfigRestHosting\Support\WebWafBans as B; $t = time();
    echo B::line("203.0.113.5", "attack", 20, $t), B::line("2001:db8::5", "scan", 15, $t), B::line("203.0.113.6", "repeat", 15, $t);' > /var/log/ispconfig-waf/bans.log
matched() { fail2ban-regex /var/log/ispconfig-waf/bans.log "/repo/waf-server/fail2ban/$1.conf" | sed -n 's/^Lines: .* \([0-9]*\) matched.*/\1/p'; }
[[ $(matched ispconfig-waf) = 2 ]] || { fail2ban-regex -v /var/log/ispconfig-waf/bans.log /repo/waf-server/fail2ban/ispconfig-waf.conf; exit 1; }
[[ $(matched ispconfig-waf-recidive) = 1 ]] || { fail2ban-regex -v /var/log/ispconfig-waf/bans.log /repo/waf-server/fail2ban/ispconfig-waf-recidive.conf; exit 1; }
echo 'ok: the filters match the worker ban lines (attack/scan and repeat)'

# The jails as the installer places them, without the distribution's own jails (no sshd log in a container).
cp -r /etc/fail2ban /tmp/f2b && rm -f /tmp/f2b/jail.d/*
cp /repo/waf-server/fail2ban/ispconfig-waf.local /tmp/f2b/jail.d/
cp /repo/waf-server/fail2ban/ispconfig-waf.conf /repo/waf-server/fail2ban/ispconfig-waf-recidive.conf /tmp/f2b/filter.d/
fail2ban-client -c /tmp/f2b -t
fail2ban-client -c /tmp/f2b -d | grep -q "'ispconfig-waf-recidive', 'bantime', '604800'"
echo 'ok: fail2ban accepts both jails with their ban times'

# The installed worker end to end: run.php with its Support files as the installer places them, an ISPConfig server
# configuration for the local MariaDB, two WAF websites, and fail2ban running the WAF jails with the dummy action.
install -d -m 0700 /usr/local/lib/ispconfig-rest-waf /var/lib/ispconfig-rest-waf /var/log/ispconfig-waf
install -m 0600 /repo/waf-server/run.php /repo/src/Support/{WebWafPolicy,WebWafAudit,WebWafProfiles,WebWafBans,WebWafCollector}.php /usr/local/lib/ispconfig-rest-waf/
mkdir -p /usr/local/ispconfig/server/lib /etc/ispconfig-waf /etc/apache2/mods-enabled
printf '%s\n' '<?php' '$conf["db_host"] = "localhost"; $conf["db_port"] = 3306; $conf["db_database"] = "dbispconfig"; $conf["db_user"] = "root"; $conf["db_password"] = "";' \
    '$conf["dbmaster_host"] = ""; $conf["server_id"] = 4;' > /usr/local/ispconfig/server/lib/config.inc.php
printf '{"engine":"apache","rules_version":"4.25.1"}' > /etc/ispconfig-waf/installed.json
touch /etc/ispconfig-waf/base.conf /etc/ispconfig-waf/owasp.conf /etc/apache2/mods-enabled/security2.load
: > /var/log/ispconfig-waf/bans.log && chmod 0600 /var/log/ispconfig-waf/bans.log
php /repo/tests/Integration/waf/worker.php setup
printf '[DEFAULT]\nbanaction = dummy\nbanaction_allports = dummy\n' > /tmp/f2b/jail.d/zz-test.local
fail2ban-client -c /tmp/f2b start >/dev/null
php /usr/local/lib/ispconfig-rest-waf/run.php
php /repo/tests/Integration/waf/worker.php first
for attempt in $(seq 1 20); do fail2ban-client status ispconfig-waf | grep -q '198.18.93.178' && break; sleep 1; done
fail2ban-client status ispconfig-waf | grep 'Banned IP list'
php /usr/local/lib/ispconfig-rest-waf/run.php
php /repo/tests/Integration/waf/worker.php second
fail2ban-client status ispconfig-waf-recidive | grep -q 'Currently banned:.0'
echo 'ok: the recidive jail bans nobody yet'
echo 'PASS WAF bans with MariaDB and fail2ban'
SCRIPT
