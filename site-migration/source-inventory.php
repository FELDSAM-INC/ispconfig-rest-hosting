<?php
// Runs on the OLD ISPConfig panel. PHP 5.3 compatible; reads control metadata only.
error_reporting(E_ALL);
ini_set('display_errors', 'stderr');
$request = json_decode(fgets(STDIN), true);
if (!is_array($request) || !preg_match('/^[a-z0-9][a-z0-9.-]+$/D', $request['domain'])) {
    fwrite(STDERR, "Invalid domain\n"); exit(1);
}
require '/usr/local/ispconfig/server/lib/config.inc.php';
if (!function_exists('mysqli_connect')) {
    fwrite(STDERR, "Source panel PHP needs mysqli (Python is not required).\n"); exit(1);
}
$db = @mysqli_connect($conf['db_host'], $conf['db_user'], $conf['db_password'], $conf['db_database'], isset($conf['db_port']) ? (int)$conf['db_port'] : 3306);
if (!$db) { fwrite(STDERR, "Cannot read source ISPConfig database\n"); exit(1); }
mysqli_set_charset($db, 'utf8');
function rows($db, $sql) {
    $result = mysqli_query($db, $sql);
    if (!$result) { fwrite(STDERR, "Source inventory query failed\n"); exit(1); }
    $rows = array();
    while ($row = mysqli_fetch_assoc($result)) { $rows[] = $row; }
    return $rows;
}
$domain = mysqli_real_escape_string($db, $request['domain']);
$sites = rows($db, "SELECT domain_id, server_id, domain, type, document_root, system_user, system_group, php, server_php_id, subdomain, hd_quota, traffic_quota, active FROM web_domain WHERE domain='$domain' AND type='vhost'");
if (count($sites) !== 1) { fwrite(STDERR, "Expected exactly one source vhost\n"); exit(1); }
$id = (int)$sites[0]['domain_id'];
$databases = rows($db, "SELECT d.database_id, d.server_id, d.database_name, d.database_charset, d.type, d.active, u.database_user FROM web_database d LEFT JOIN web_database_user u ON u.database_user_id=d.database_user_id WHERE d.parent_domain_id=$id ORDER BY d.database_id");
$children = rows($db, "SELECT domain_id, domain, type, subdomain, redirect_type, redirect_path, active FROM web_domain WHERE parent_domain_id=$id ORDER BY domain_id");
$servers = rows($db, 'SELECT server_id, server_name FROM server');
echo json_encode(array('site'=>$sites[0], 'databases'=>$databases, 'children'=>$children, 'servers'=>$servers)), "\n";
