<?php
// Trusted ISPConfig config only; compatible with PHP 5.3 on old hosts.
$request = json_decode(fgets(STDIN), true);
if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
    fwrite(STDERR, "Root SSH is required\n"); exit(1);
}
require '/usr/local/ispconfig/server/lib/config.inc.php';
if ((int)$conf['server_id'] !== (int)$request['server_id']) {
    fwrite(STDERR, "SSH host has a different ISPConfig server ID\n"); exit(1);
}
echo "ready\n";
