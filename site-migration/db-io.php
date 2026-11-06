<?php
// Executed through root SSH, never installed in a customer's document root.
// PHP 5.3 compatible on the source. Credentials arrive over stdin, not argv.
error_reporting(E_ALL);
ini_set('display_errors', 'stderr');
$request = json_decode(fgets(STDIN), true);
if (!is_array($request) || !in_array($request['action'], array('dump', 'import', 'probe'), true)
    || !preg_match('/^[a-zA-Z0-9_]{1,64}$/D', $request['database'])) {
    fwrite(STDERR, "Invalid database request\n"); exit(1);
}
$source = !empty($request['source']);
require '/usr/local/ispconfig/server/lib/config.inc.php';
if (!function_exists('posix_geteuid') || posix_geteuid() !== 0 || (int)$conf['server_id'] !== (int)$request['server_id']) {
    fwrite(STDERR, "Wrong DB server ID or missing root SSH\n"); exit(1);
}
$connection = array();
$externalDefaults = null;
if ($source) {
    if ($request['action'] !== 'dump') { exit(1); }
    if (isset($request['source_connection'])) {
        $connection = $request['source_connection'];
        if (!is_array($connection) || !isset($connection['host']) || !is_string($connection['host'])
            || !preg_match('/^[a-zA-Z0-9][a-zA-Z0-9.-]*$/D', $connection['host'])) {
            fwrite(STDERR, "Invalid source MySQL host\n"); exit(1);
        }
        $connection['port'] = isset($connection['port']) ? $connection['port'] : 3306;
        if (!is_int($connection['port']) || $connection['port'] < 1 || $connection['port'] > 65535) {
            fwrite(STDERR, "Invalid source MySQL port\n"); exit(1);
        }
        if (isset($connection['defaults_file'])) {
            $externalDefaults = $connection['defaults_file'];
            if (!is_string($externalDefaults) || substr($externalDefaults, 0, 1) !== '/'
                || preg_match('/[\x00\r\n]/', $externalDefaults) || is_link($externalDefaults)
                || !is_file($externalDefaults) || fileowner($externalDefaults) !== 0
                || (fileperms($externalDefaults) & 0077) !== 0) {
                fwrite(STDERR, "Source defaults file must be a root-owned private regular file (0600) on the SSH host\n"); exit(1);
            }
        }
    }
    if ($externalDefaults === null) {
        require '/usr/local/ispconfig/server/lib/mysql_clientdb.conf';
        $request['user'] = $clientdb_user;
        $request['password'] = $clientdb_password;
        $request['host'] = isset($clientdb_host) ? $clientdb_host : 'localhost';
    }
} else {
    // ISPConfig provisions the scoped website user on the selected DB host.
    $request['host'] = 'localhost';
}
function optionValue($s) {
    return '"'.str_replace(array('\\', '"', "\n", "\r"), array('\\\\', '\\"', '\\n', '\\r'), $s).'"';
}
umask(0077);
$defaults = $externalDefaults;
if ($defaults === null) {
    $directory = sys_get_temp_dir().'/ispcp-migrate-'.bin2hex(openssl_random_pseudo_bytes(16));
    if (!mkdir($directory, 0700)) { exit(1); }
    $defaults = $directory.'/client.cnf';
    register_shutdown_function(function () use ($defaults, $directory) { @unlink($defaults); @rmdir($directory); });
    $body = "[client]\nhost=".optionValue($request['host'])."\nuser=".optionValue($request['user'])."\npassword=".optionValue($request['password'])."\n";
    if (file_put_contents($defaults, $body) === false) { exit(1); }
}
$prefix = '';
if (!$source) {
    $nobody = posix_getpwnam('nobody');
    if (!$nobody || !is_executable('/usr/bin/setpriv')) { fwrite(STDERR, "setpriv/nobody required on target DB server\n"); exit(1); }
    chown($defaults, $nobody['uid']); chgrp($defaults, $nobody['gid']);
    chown($directory, $nobody['uid']); chgrp($directory, $nobody['gid']);
    $prefix = '/usr/bin/setpriv --reuid='.(int)$nobody['uid'].' --regid='.(int)$nobody['gid'].' --clear-groups --no-new-privs -- ';
}
if ($request['action'] === 'dump') {
    $help = (string)shell_exec('mysqldump --no-defaults --help 2>/dev/null');
    $command = 'mysqldump --defaults-file='.escapeshellarg($defaults).' --single-transaction --quick --hex-blob --routines --events --triggers';
    if (strpos($help, 'no-tablespaces') !== false) { $command .= ' --no-tablespaces'; }
    if (strpos($help, 'set-gtid-purged') !== false) { $command .= ' --set-gtid-purged=OFF'; }
    if (strpos($help, 'column-statistics') !== false) { $command .= ' --column-statistics=0'; }
    if ($connection) {
        // Explicit options override any host/socket from the credential file.
        // This TCP connection originates on the old web server, never the runner.
        $command .= ' --protocol=TCP --host='.escapeshellarg($connection['host']).' --port='.(int)$connection['port'];
    }
} else {
    $command = 'mysql --defaults-file='.escapeshellarg($defaults).' --binary-mode --local-infile=0 --batch';
    if ($request['action'] === 'probe') { $command .= ' --execute='.escapeshellarg('SELECT 1'); }
}
$command .= ' -- '.escapeshellarg($request['database']);
// Pass the already-open stdin through. The JSON header is consumed one line at a time.
$process = proc_open($prefix.$command, array(0=>array('pipe', 'r'), 1=>STDOUT, 2=>STDERR), $pipes);
if (!is_resource($process)) { exit(1); }
if ($request['action'] === 'import') { stream_copy_to_stream(STDIN, $pipes[0]); }
fclose($pipes[0]);
exit(proc_close($process));
