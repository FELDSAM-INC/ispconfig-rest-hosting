<?php

// Disposable container only (collector.sh): the installed WAF worker (waf-server/run.php) end to end, against a local
// MariaDB as the ISPConfig master database and Apache JSON audit logs. `setup` prepares, `first`/`second` check runs.
declare(strict_types=1);
require '/repo/src/Support/WebWafProfiles.php';
require '/repo/src/Support/WebWafPolicy.php';

use IspconfigRestHosting\Support\WebWafPolicy;

function check(bool $ok, string $what): void
{
    if (! $ok) {
        fwrite(STDERR, "FAIL $what\n");
        exit(1);
    }
    echo "ok: $what\n";
}

$db = new PDO('mysql:unix_socket=/run/mysqld/mysqld.sock;charset=utf8mb4', 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$sites = [['domain_id' => 11, 'server_id' => 4, 'sys_groupid' => 7, 'domain' => 'enforcing.test', 'mode' => 'enforcing'],
    ['domain_id' => 12, 'server_id' => 4, 'sys_groupid' => 7, 'domain' => 'detection.test', 'mode' => 'detection']];
$value = fn (string $sql) => $db->query($sql)->fetchColumn();

if ($argv[1] === 'setup') {
    $db->exec('CREATE DATABASE dbispconfig');
    $db->exec('USE dbispconfig');
    $db->exec('CREATE TABLE web_domain (domain_id int primary key, server_id int, sys_groupid int, domain varchar(255), type varchar(32), apache_directives mediumtext, nginx_directives mediumtext)');
    $db->exec('CREATE TABLE api_web_waf_workers (server_id int unsigned primary key, heartbeat bigint unsigned, engine varchar(16), rules_version varchar(128), atomic_available tinyint(1) default 0, application_profiles text)');
    foreach (explode(';', file_get_contents('/tmp/collector-tables.sql')) as $sql) {
        if (trim($sql) !== '') {
            $db->exec($sql);
        }
    }
    $now = time();
    foreach ($sites as $site) {
        $settings = ['enabled' => true, 'mode' => $site['mode'], 'ip_allowlist' => $site['mode'] === 'detection' ? ['198.51.100.0/24'] : []];
        $db->prepare("INSERT INTO web_domain VALUES (?,?,?,?,'vhost',?,'')")->execute([$site['domain_id'], $site['server_id'], $site['sys_groupid'], $site['domain'], WebWafPolicy::compile($site, 'apache', $settings)]);
        $records = '';
        $request = function (string $ip, string $path, array $rules, bool $blocked) use (&$records, $now): void {
            static $n = 0;
            $messages = array_map(fn (int $rule) => ($blocked ? 'Access denied with code 403 (phase 2). ' : 'Warning. ').'Pattern match [file "/rules.conf"] [id "'.$rule.'"] [severity "CRITICAL"]', $rules);
            $records .= json_encode(['transaction' => ['time' => date('d/M/Y:H:i:s.000000 O', $now - 120 + (++$n % 60)), 'transaction_id' => 'tx-'.$n, 'remote_address' => $ip],
                'request' => ['request_line' => 'GET '.$path.' HTTP/1.1'], 'audit_data' => ['engine_mode' => $blocked ? 'ENABLED' : 'DETECTION_ONLY', 'messages' => $messages]])."\n";
        };
        if ($site['mode'] === 'enforcing') {
            for ($i = 0; $i < 25; $i++) {
                $request('93.123.109.178', '/', [942100, 949110], true);
            }
            for ($i = 0; $i < 5; $i++) {
                $request('203.0.113.9', '/contact', [942100, 949110], true);
            }
        } else {
            for ($i = 0; $i < 20; $i++) {
                $request('34.174.190.229', '/.env'.$i, [930130], false);
                $request('198.51.100.7', '/.git/'.$i, [930130], false);
                $request('203.0.113.50', '/', [942100, 949110], false);
            }
        }
        $file = '/var/log/ispconfig-waf/'.WebWafPolicy::identity($site).'.json';
        file_put_contents($file, $records);
        chmod($file, 0600);
    }
    echo "ok: setup\n";
    exit(0);
}

$db->exec('USE dbispconfig');
$bans = file_exists('/var/log/ispconfig-waf/bans.log') ? file_get_contents('/var/log/ispconfig-waf/bans.log') : '';
$identity = WebWafPolicy::identity($sites[0]);
if ($argv[1] === 'first') {
    check((int) $value('SELECT COUNT(*) FROM api_web_waf_workers WHERE server_id=4 AND engine="apache"') === 1, 'the worker reports its heartbeat');
    check((int) $value("SELECT COUNT(*) FROM api_web_waf_events WHERE website_id=11 AND client_ip='93.123.109.178'") === 50, 'the events of both websites are stored');
    check((int) $value("SELECT over_threshold FROM api_web_waf_clients WHERE website_id=11 AND identity='$identity' AND client_ip='93.123.109.178'") === 25, 'client totals are counted');
    check(preg_match_all('/ ispconfig-waf ban (\S+) reason=(\w+) /', $bans, $lines) === 2, 'exactly two clients are banned');
    $banned = array_combine($lines[1], $lines[2]);
    check(($banned['93.123.109.178'] ?? '') === 'attack' && ($banned['34.174.190.229'] ?? '') === 'scan', 'the attacker and the scanner, on enforcing and detection websites');
    check(! isset($banned['198.51.100.7']) && ! isset($banned['203.0.113.50']) && ! isset($banned['203.0.113.9']), 'allowlisted, detection-only attacks and few requests are not banned');
    exit(0);
}
// Second run: positions and ban state persisted, fail2ban's bans mirrored.
check(substr_count($bans, ' ispconfig-waf ban ') === 2, 'a second run decides nothing again');
check((int) $value("SELECT requests FROM api_web_waf_clients WHERE website_id=11 AND client_ip='93.123.109.178'") === 25, 'a second run does not count the audit log again');
$rows = $db->query('SELECT client_ip, jail, reason FROM api_web_waf_bans WHERE server_id=4 ORDER BY client_ip')->fetchAll(PDO::FETCH_NUM);
check($rows === [['34.174.190.229', 'ispconfig-waf', 'scan'], ['93.123.109.178', 'ispconfig-waf', 'attack']], 'the bans of the running fail2ban are mirrored with their reasons');
echo "PASS WAF worker end to end\n";
