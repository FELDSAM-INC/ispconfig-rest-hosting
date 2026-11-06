#!/usr/bin/env bash
set -euo pipefail
# The fixture creates Linux users and database schemas: always isolate it.
root=$(cd "$(dirname "$0")/../.." && pwd)
image=ispcp-migration-test
docker build -q -t "$image" - <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 php-cli php-mysql rsync openssh-server openssh-client mariadb-server mariadb-client ca-certificates && rm -rf /var/lib/apt/lists/*
DOCKERFILE
for source_mode in direct via-web; do
docker run --rm -i -e "ISPCP_TEST_SOURCE_MODE=$source_mode" -v "$root:/repo:ro" "$image" bash -s <<'SCRIPT'
set -euo pipefail
mkdir -p /run/sshd /run/mysqld /root/.ssh
chmod 700 /root/.ssh
chown mysql:mysql /run/mysqld
mariadbd --user=mysql --bind-address=127.0.0.1 > /tmp/mariadb.log 2>&1 &
for attempt in $(seq 1 60); do
  if mysqladmin ping --silent; then break; fi
  sleep 1
done
mysqladmin ping --silent
ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519
cp /root/.ssh/id_ed25519.pub /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
# Pin the public key read directly from this disposable server, not from an untrusted scan.
awk '{print "127.0.0.1 "$1" "$2}' /etc/ssh/ssh_host_ed25519_key.pub > /root/.ssh/known_hosts
/usr/sbin/sshd
python3 /repo/tests/Migration/test_migration.py
python3 /repo/tests/Migration/integration.py
SCRIPT
done
