#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) = 0 ]] || { echo 'Run as root through ispconfig-rest server-tools.' >&2; exit 1; }
[[ $# = 0 ]] || { echo 'Usage: install.sh' >&2; exit 1; }
migration_source=$(cd -- "$(dirname -- "$0")" && pwd)

trusted_path() {
    local item=$1
    while [[ "$item" != / ]]; do
        [[ ! -L "$item" && $(stat -c %u -- "$item") = 0 && $((8#$(stat -c %a -- "$item") & 0022)) = 0 ]] || {
            echo "Unsafe migration installation path: $item" >&2; exit 1;
        }
        item=$(dirname -- "$item")
    done
}
files=(migrate.py target-files.py source-inventory.php server-check.php db-io.php wordpress-config.php normalize-sql.php ispcp-migrate config.example.json README.md)
trusted_path "$migration_source"
trusted_path "$migration_source/../worker"
for item in "${files[@]}" install.sh; do
    [[ -f "$migration_source/$item" ]] || { echo "Missing migration file: $item" >&2; exit 1; }
    trusted_path "$migration_source/$item"
done
[[ -f "$migration_source/../worker/SqlDump.php" ]] || { echo 'Missing SQL normalizer.' >&2; exit 1; }
trusted_path "$migration_source/../worker/SqlDump.php"
[[ -f /usr/local/ispconfig/server/lib/config.inc.php ]] || { echo 'Install on the destination ISPConfig web server.' >&2; exit 1; }
for command in python3 php ssh rsync flock; do
    command -v "$command" >/dev/null || { echo "Missing requirement: $command" >&2; exit 1; }
done
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || { echo 'Python 3.9+ is required.' >&2; exit 1; }
php -r 'exit(PHP_VERSION_ID >= 70400 && extension_loaded("tokenizer") ? 0 : 1);' || { echo 'PHP CLI 7.4+ with tokenizer is required.' >&2; exit 1; }

for directory in /usr/local/lib/ispconfig-rest-migration /etc/ispconfig-rest-migration /var/lib/ispconfig-rest-migration; do
    if [[ -e "$directory" || -L "$directory" ]]; then
        trusted_path "$directory"
    else
        trusted_path "$(dirname -- "$directory")"
    fi
done
trusted_path /usr/local/sbin
for path in /usr/local/sbin/ispcp-migrate /etc/ispconfig-rest-migration/config.json /var/lib/ispconfig-rest-migration/.install.lock; do
    if [[ -e "$path" || -L "$path" ]]; then trusted_path "$path"; fi
done
install -d -m 0700 -o root -g root /usr/local/lib/ispconfig-rest-migration /etc/ispconfig-rest-migration /var/lib/ispconfig-rest-migration
umask 077
exec 9>/var/lib/ispconfig-rest-migration/.install.lock
flock --exclusive --nonblock 9 || { echo 'A migration is running. Retry the tool update after it finishes.' >&2; exit 1; }
for item in "${files[@]}"; do
    if [[ -e /usr/local/lib/ispconfig-rest-migration/$item || -L /usr/local/lib/ispconfig-rest-migration/$item ]]; then
        trusted_path /usr/local/lib/ispconfig-rest-migration/"$item"
    fi
done
if [[ -e /usr/local/lib/ispconfig-rest-migration/SqlDump.php || -L /usr/local/lib/ispconfig-rest-migration/SqlDump.php ]]; then
    trusted_path /usr/local/lib/ispconfig-rest-migration/SqlDump.php
fi
for item in "${files[@]}"; do
    install -m 0600 -o root -g root "$migration_source/$item" /usr/local/lib/ispconfig-rest-migration/"$item"
done
install -m 0600 -o root -g root "$migration_source/../worker/SqlDump.php" /usr/local/lib/ispconfig-rest-migration/SqlDump.php
if [[ ! -e /etc/ispconfig-rest-migration/config.json ]]; then
    install -m 0600 -o root -g root "$migration_source/config.example.json" /etc/ispconfig-rest-migration/config.json
fi
install -m 0755 -o root -g root "$migration_source/ispcp-migrate" /usr/local/sbin/ispcp-migrate
echo 'Installed ispcp-migrate. Configure /etc/ispconfig-rest-migration/config.json once, then run: ispcp-migrate DOMAIN NEW_CLIENT_ID'
echo 'Guide: /usr/local/lib/ispconfig-rest-migration/README.md. Existing configuration and migration state were preserved.'
