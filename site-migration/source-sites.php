<?php
// Runs on the OLD ISPConfig panel for `ispcp-migrate --sites`. PHP 5.3 compatible;
// reads control metadata only: every website, its hostnames, server addresses and traffic.
error_reporting(E_ALL);
ini_set('display_errors', 'stderr');
require '/usr/local/ispconfig/server/lib/config.inc.php';
if (!function_exists('mysqli_connect')) {
    fwrite(STDERR, "Source panel PHP needs mysqli (Python is not required).\n"); exit(1);
}
mysqli_report(MYSQLI_REPORT_OFF);
$db = @mysqli_connect($conf['db_host'], $conf['db_user'], $conf['db_password'], $conf['db_database'], isset($conf['db_port']) ? (int)$conf['db_port'] : 3306);
if (!$db) { fwrite(STDERR, "Cannot read source ISPConfig database (MySQL ".mysqli_connect_errno().")\n"); exit(1); }
function queryFailure($db, $section) {
    $error = str_replace(array("\r", "\n"), ' ', mysqli_error($db));
    fwrite(STDERR, "Source sites query failed [".$section."] (MySQL ".mysqli_errno($db)."): ".$error."\n");
    exit(1);
}
if (!mysqli_set_charset($db, 'utf8')) { queryFailure($db, 'connection charset'); }
function rows($db, $sql, $section) {
    $result = @mysqli_query($db, $sql);
    if (!$result) { queryFailure($db, $section); }
    $rows = array();
    while ($row = mysqli_fetch_assoc($result)) { $rows[] = $row; }
    return $rows;
}
// Column names of a table, empty when the table does not exist (older or partial schemas).
function columns($db, $table) {
    if (!count(rows($db, "SHOW TABLES LIKE '".str_replace('_', '\\_', $table)."'", $table.' schema'))) { return array(); }
    $names = array();
    foreach (rows($db, 'SHOW COLUMNS FROM `'.$table.'`', $table.' schema') as $column) { $names[$column['Field']] = true; }
    return $names;
}
function has($columns, $names) {
    foreach ($names as $name) { if (!isset($columns[$name])) { return false; } }
    return true;
}
$web = columns($db, 'web_domain');
$required = array('domain_id', 'server_id', 'parent_domain_id', 'domain', 'type', 'subdomain', 'active', 'document_root');
foreach ($required as $name) {
    if (!isset($web[$name])) { fwrite(STDERR, "Source web_domain lacks column $name\n"); exit(1); }
}
$select = array();
foreach ($required as $name) { $select[] = 'w.'.$name; }
foreach (array('ip_address', 'ipv6_address', 'redirect_type', 'redirect_path') as $name) {
    $select[] = isset($web[$name]) ? 'w.'.$name : "'' AS ".$name;
}
// Owner: web_domain.sys_groupid -> sys_group.client_id -> client.
$join = '';
if (isset($web['sys_groupid']) && has(columns($db, 'sys_group'), array('groupid', 'client_id'))
        && has(columns($db, 'client'), array('client_id', 'username', 'company_name', 'contact_name'))) {
    $join = ' LEFT JOIN sys_group g ON g.groupid=w.sys_groupid LEFT JOIN client c ON c.client_id=g.client_id AND g.client_id>0';
    $select[] = 'c.client_id';
    $select[] = 'c.username AS client_username';
    $select[] = 'c.company_name AS client_company';
    $select[] = 'c.contact_name AS client_contact';
}
$websites = rows($db, 'SELECT '.implode(', ', $select).' FROM web_domain w'.$join.' ORDER BY w.domain_id', 'websites');
$databases = array();
if (has(columns($db, 'web_database'), array('parent_domain_id'))) {
    foreach (rows($db, 'SELECT parent_domain_id, COUNT(*) AS n FROM web_database GROUP BY parent_domain_id', 'databases') as $row) {
        $databases[$row['parent_domain_id']] = (int)$row['n'];
    }
}
$servers = rows($db, 'SELECT server_id, server_name FROM server ORDER BY server_id', 'servers');
$ips = has(columns($db, 'server_ip'), array('server_id', 'ip_address'))
    ? rows($db, 'SELECT server_id, ip_address FROM server_ip', 'server addresses') : array();
// ISPConfig's daily traffic statistics per vhost hostname; null when unavailable.
$traffic = null;
if (has(columns($db, 'web_traffic'), array('hostname', 'traffic_date', 'traffic_bytes'))) {
    $traffic = array();
    foreach (rows($db, 'SELECT hostname, SUM(traffic_bytes) AS bytes FROM web_traffic WHERE traffic_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY) GROUP BY hostname', 'traffic') as $row) {
        $traffic[strtolower($row['hostname'])] = (float)$row['bytes'];
    }
}
// Objects even when empty or numerically keyed, never JSON lists.
echo json_encode(array('websites'=>$websites, 'databases'=>(object)$databases, 'servers'=>$servers, 'ips'=>$ips,
    'traffic'=>$traffic === null ? null : (object)$traffic)), "\n";
