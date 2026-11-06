<?php

// Disposable container only (tests/Integration/waf/collector.sh): a local MariaDB without a password for root.
declare(strict_types=1);
require '/repo/src/Support/WebWafBans.php';
require '/repo/src/Support/WebWafCollector.php';

use IspconfigRestHosting\Support\WebWafBans;
use IspconfigRestHosting\Support\WebWafCollector;

function check(bool $ok, string $what): void
{
    if (! $ok) {
        fwrite(STDERR, "FAIL $what\n");
        exit(1);
    }
    echo "ok: $what\n";
}

$db = new PDO('mysql:unix_socket=/run/mysqld/mysqld.sock;charset=utf8mb4', 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]);
$db->exec('CREATE DATABASE waf_collector');
$db->exec('USE waf_collector');
// The columns of database/migrations 2026_09_27_000002 and 2026_11_07_000001.
$db->exec('CREATE TABLE api_web_waf_events (id bigint unsigned auto_increment primary key, event_key varchar(64) not null unique, server_id int unsigned not null,
    website_id int unsigned not null, identity varchar(48) not null, occurred_at bigint unsigned not null, rule_id int unsigned not null, outcome varchar(16) not null,
    client_ip varchar(45) not null, method varchar(16) not null, path varchar(512) not null, parameter varchar(128) not null default "", message varchar(512) not null,
    severity varchar(32) not null default "", source varchar(16) not null, index (server_id, website_id, identity, id), index (occurred_at),
    index (server_id, website_id, identity, client_ip, id))');
$db->exec('CREATE TABLE api_web_waf_clients (id bigint unsigned auto_increment primary key, server_id int unsigned not null, website_id int unsigned not null,
    identity varchar(48) not null, client_ip varchar(45) not null, events int unsigned not null default 0, requests int unsigned not null default 0,
    over_threshold int unsigned not null default 0, first_seen bigint unsigned not null, last_seen bigint unsigned not null,
    unique (server_id, website_id, identity, client_ip), index (last_seen))');
$db->exec('CREATE TABLE api_web_waf_bans (id bigint unsigned auto_increment primary key, server_id int unsigned not null, client_ip varchar(45) not null,
    jail varchar(32) not null, reason varchar(16) not null default "", banned_at bigint unsigned not null, expires_at bigint unsigned not null default 0,
    unique (server_id, client_ip))');

file_put_contents('/tmp/collector-tables.sql', implode(";\n", array_map(fn ($t) => $db->query('SHOW CREATE TABLE '.$t)->fetch(PDO::FETCH_NUM)[1], ['api_web_waf_events', 'api_web_waf_clients', 'api_web_waf_bans'])));
$now = time();
$event = fn (string $ip, int $n, int $rule = 942100, string $path = '/') => ['event_key' => hash('sha256', $ip.':'.$n.':'.$rule), 'request_key' => hash('sha256', $ip.':'.$n),
    'occurred_at' => $now - 300 + ($n % 200), 'rule_id' => $rule, 'outcome' => 'blocked', 'client_ip' => $ip, 'method' => 'GET', 'path' => $path,
    'parameter' => '', 'message' => 'Rule matched', 'severity' => '2', 'source' => 'owasp'];
$count = fn (string $sql, array $values = []) => (function () use ($db, $sql, $values) { $q = $db->prepare($sql); $q->execute($values); return (int) $q->fetchColumn(); })();

// One noisy client cannot evict the others: 150 requests of a scanner, 5 of another client (two rule events each).
$events = [];
for ($n = 0; $n < 150; $n++) {
    array_push($events, $event('198.18.34.229', $n, 930130, '/.env'.$n), $event('198.18.34.229', $n, 980170, '/.env'.$n));
}
for ($n = 0; $n < 5; $n++) {
    array_push($events, $event('203.0.113.9', $n, 942100), $event('203.0.113.9', $n, 949110));
}
$state = [];
$new = WebWafCollector::store($db, 4, 17, '17-site', $events);
check(count($new) === 310 && isset($new[0]['request_key']), 'every collected event is stored as new once');
WebWafCollector::clients($db, 4, 17, '17-site', $new, ['enabled' => true, 'mode' => 'enforcing'], $state);
check($count('SELECT COUNT(*) FROM api_web_waf_events WHERE client_ip=?', ['198.18.34.229']) === WebWafCollector::CLIENT_EVENTS, 'a client keeps at most 100 stored events');
check($count('SELECT COUNT(*) FROM api_web_waf_events WHERE client_ip=?', ['203.0.113.9']) === 10, 'the other client keeps all its events');
check($count('SELECT events FROM api_web_waf_clients WHERE client_ip=?', ['198.18.34.229']) === 300
    && $count('SELECT requests FROM api_web_waf_clients WHERE client_ip=?', ['198.18.34.229']) === 150, 'totals count events beyond the stored ones');
check($count('SELECT over_threshold FROM api_web_waf_clients WHERE client_ip=?', ['203.0.113.9']) === 5, 'requests over the threshold are counted');
check(count($state['clients']['198.18.34.229']['scan'] ?? []) === 64, 'the scanner is counted for the ban rules (bounded)');

// A re-read of the audit tail (parser upgrade) neither duplicates events nor counts them again.
$again = WebWafCollector::store($db, 4, 17, '17-site', array_slice($events, 300));
WebWafCollector::clients($db, 4, 17, '17-site', $again, ['enabled' => true, 'mode' => 'enforcing'], $state);
check($again === [] && $count('SELECT requests FROM api_web_waf_clients WHERE client_ip=?', ['203.0.113.9']) === 5, 're-read events are not counted twice');

// Disabled websites keep totals but do not count for bans; first/last seen widen.
$late = [$event('198.51.100.20', 1, 930130, '/a'), ['occurred_at' => $now - 5000] + $event('198.51.100.20', 2, 930130, '/b')];
$state = [];
WebWafCollector::clients($db, 4, 17, '17-site', WebWafCollector::store($db, 4, 17, '17-site', $late), ['enabled' => false, 'mode' => 'enforcing'], $state);
check(! isset($state['clients']) && $count('SELECT last_seen - first_seen FROM api_web_waf_clients WHERE client_ip=?', ['198.51.100.20']) > 4000, 'disabled websites do not count for bans');

// The website keeps at most 1,000 events.
$many = [];
for ($ip = 1; $ip <= 20; $ip++) {
    for ($n = 0; $n < 60; $n++) {
        $many[] = $event('192.0.2.'.$ip, $n);
    }
}
WebWafCollector::clients($db, 4, 18, '18-site', WebWafCollector::store($db, 4, 18, '18-site', $many), ['enabled' => true, 'mode' => 'detection'], $state);
check($count('SELECT COUNT(*) FROM api_web_waf_events WHERE website_id=18') === WebWafCollector::WEBSITE_EVENTS, 'a website keeps at most 1,000 events');

// fail2ban bans are mirrored; allowlisted and private clients are unbanned.
$calls = [];
$jails = ['ispconfig-waf' => "`- Banned IP list:\t203.0.113.5 10.0.0.9 198.51.100.7 2A01:4F8::5\n", 'ispconfig-waf-recidive' => "`- Banned IP list:\t203.0.113.6 203.0.113.5\n"];
$fail2ban = function (array $args) use (&$calls, &$jails): ?string {
    $calls[] = implode(' ', $args);

    return $args[0] === 'status' ? ($jails[$args[1]] ?? null) : '';
};
$state = ['issued' => ['203.0.113.5' => ['reason' => 'attack', 'at' => $now - 30], '203.0.113.99' => ['reason' => 'scan', 'at' => $now],
    '203.0.113.98' => ['reason' => 'scan', 'at' => $now - 1000]]];
$db->prepare('INSERT INTO api_web_waf_bans (server_id,client_ip,jail,reason,banned_at,expires_at) VALUES (4,"203.0.113.77","ispconfig-waf","attack",?,?)')->execute([$now - 100, $now + 3500]);
WebWafCollector::syncBans($db, 4, $state, ['198.51.100.0/24'], $now, $fail2ban);
$rows = $db->query('SELECT client_ip, jail, reason, expires_at - banned_at AS length FROM api_web_waf_bans WHERE server_id=4 ORDER BY client_ip')->fetchAll(PDO::FETCH_ASSOC);
check(array_column($rows, 'client_ip') === ['203.0.113.5', '203.0.113.6', '2a01:4f8::5'], 'current bans are mirrored, ended ones removed');
check($rows[0]['jail'] === 'ispconfig-waf-recidive' && $rows[0]['reason'] === 'attack' && (int) $rows[0]['length'] === 604800, 'the recidive ban wins and keeps the reason');
check(in_array('set ispconfig-waf unbanip 10.0.0.9', $calls, true) && in_array('set ispconfig-waf unbanip 198.51.100.7', $calls, true) && ! in_array('set ispconfig-waf unbanip 2a01:4f8::5', $calls, true), 'private and allowlisted clients are unbanned');
check(isset($state['issued']['203.0.113.99']) && ! isset($state['issued']['203.0.113.98']), 'a fresh decision waits for fail2ban, an old one is forgotten');

// Without fail2ban only expired rows go.
$db->exec('UPDATE api_web_waf_bans SET expires_at='.($now - 1).' WHERE client_ip="203.0.113.6"');
WebWafCollector::syncBans($db, 4, $state, [], $now, fn (array $args): ?string => null);
check($count('SELECT COUNT(*) FROM api_web_waf_bans WHERE server_id=4') === 2, 'an unreachable fail2ban removes only expired bans');
echo "PASS WAF collector\n";
