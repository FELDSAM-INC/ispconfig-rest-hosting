<?php

namespace IspconfigRestHosting\Support;

use PDO;

/**
 * Master-database side of the root WAF worker (waf-server/run.php): stores collected events, keeps the per-client
 * totals and retention of spec 048, and mirrors the fail2ban bans of the server. Plain PHP and PDO (MariaDB/MySQL).
 */
final class WebWafCollector
{
    /** Stored events per website, and per client of a website (spec 048). */
    public const WEBSITE_EVENTS = 1000;

    public const CLIENT_EVENTS = 100;

    /** A ban decision waits this long for fail2ban to read it before its reason is forgotten. */
    private const ISSUE_GRACE = 300;

    /**
     * Store a website's collected events. A parser upgrade re-reads the bounded audit tail: existing events only have
     * their metadata repaired. Returns the newly stored events, still with their `request_key`, which alone count for
     * the client totals and the ban rules.
     */
    public static function store(PDO $db, int $server, int $website, string $identity, array $events): array
    {
        $new = [];
        foreach ($events as $event) {
            $request = (string) ($event['request_key'] ?? '');
            unset($event['request_key']);
            $event['event_key'] = hash('sha256', $identity.':'.$event['event_key']);
            $event = ['server_id' => $server, 'website_id' => $website, 'identity' => $identity] + $event;
            $insert = $db->prepare('INSERT INTO api_web_waf_events ('.implode(',', array_keys($event)).') VALUES ('.implode(',', array_fill(0, count($event), '?')).') ON DUPLICATE KEY UPDATE parameter=VALUES(parameter)');
            $insert->execute(array_values($event));
            if ($insert->rowCount() === 1) {
                $new[] = $event + ['request_key' => $request];
            }
        }

        return $new;
    }

    /**
     * Add newly stored events to the website's client totals, keep at most 100 events per client and 1,000 per
     * website, and count the requests of a WAF-enabled website for the ban rules.
     */
    public static function clients(PDO $db, int $server, int $website, string $identity, array $events, array $settings, array &$banState): void
    {
        $totals = [];
        foreach ($events as $event) {
            $ip = (string) $event['client_ip'];
            if ($ip === '') {
                continue;
            }
            $total = $totals[$ip] ?? ['events' => 0, 'requests' => 0, 'over_threshold' => 0, 'first' => PHP_INT_MAX, 'last' => 0];
            $total['events']++;
            $total['first'] = min($total['first'], (int) $event['occurred_at']);
            $total['last'] = max($total['last'], (int) $event['occurred_at']);
            $totals[$ip] = $total;
        }
        foreach (WebWafBans::requests($events) as $request) {
            $totals[$request['client_ip']]['requests']++;
            $totals[$request['client_ip']]['over_threshold'] += $request['over_threshold'] ? 1 : 0;
            if (! empty($settings['enabled'])) {
                WebWafBans::observe($banState, $request, (string) $settings['mode']);
            }
        }
        foreach ($totals as $ip => $total) {
            $db->prepare('INSERT INTO api_web_waf_clients (server_id,website_id,identity,client_ip,events,requests,over_threshold,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE events=events+VALUES(events),requests=requests+VALUES(requests),over_threshold=over_threshold+VALUES(over_threshold),first_seen=LEAST(first_seen,VALUES(first_seen)),last_seen=GREATEST(last_seen,VALUES(last_seen))')
                ->execute([$server, $website, $identity, (string) $ip, $total['events'], $total['requests'], $total['over_threshold'], $total['first'], $total['last']]);
            self::trim($db, 'AND client_ip=?', [$server, $website, $identity, (string) $ip], self::CLIENT_EVENTS);
        }
        self::trim($db, '', [$server, $website, $identity], self::WEBSITE_EVENTS);
    }

    /**
     * Mirror the bans of the WAF jails into api_web_waf_bans and unban clients that are allowlisted or ignored by now.
     * Without a reachable fail2ban only expired rows are removed.
     *
     * @param  callable(array): ?string  $fail2ban  runs `fail2ban-client ARGS`
     */
    public static function syncBans(PDO $db, int $server, array &$banState, array $ignored, int $now, callable $fail2ban): void
    {
        $known = $db->prepare('SELECT client_ip, banned_at FROM api_web_waf_bans WHERE server_id=?');
        $known->execute([$server]);
        $since = array_column($known->fetchAll(PDO::FETCH_ASSOC), 'banned_at', 'client_ip');
        $current = [];
        $reached = false;
        foreach (WebWafBans::JAILS as $jail => $bantime) {
            $status = $fail2ban(['status', $jail]);
            if ($status === null) {
                continue;
            }
            $reached = true;
            foreach (WebWafBans::banned($status) as $ip) {
                $ip = WebWafBans::canonical($ip);
                if (WebWafBans::ignored($ip, $ignored)) {
                    $fail2ban(['set', $jail, 'unbanip', $ip]);

                    continue;
                }
                $issued = $banState['issued'][$ip] ?? [];
                $at = (int) ($issued['at'] ?? $since[$ip] ?? $now);
                // Jails in order of ban time: the recidive jail's longer ban wins.
                $current[$ip] = ['jail' => $jail, 'reason' => (string) ($issued['reason'] ?? ''), 'at' => $at, 'expires' => $at + $bantime];
            }
        }
        if (! $reached) {
            $db->prepare('DELETE FROM api_web_waf_bans WHERE server_id=? AND expires_at>0 AND expires_at<?')->execute([$server, $now]);

            return;
        }
        foreach ($current as $ip => $ban) {
            $db->prepare('INSERT INTO api_web_waf_bans (server_id,client_ip,jail,reason,banned_at,expires_at) VALUES (?,?,?,?,?,?) ON DUPLICATE KEY UPDATE jail=VALUES(jail),reason=VALUES(reason),banned_at=VALUES(banned_at),expires_at=VALUES(expires_at)')
                ->execute([$server, $ip, $ban['jail'], $ban['reason'], $ban['at'], $ban['expires']]);
        }
        foreach (array_diff(array_map('strval', array_keys($since)), array_map('strval', array_keys($current))) as $ip) {
            $db->prepare('DELETE FROM api_web_waf_bans WHERE server_id=? AND client_ip=?')->execute([$server, $ip]);
        }
        // Keep a decision fail2ban may not have read yet; forget older ones it no longer bans.
        foreach ($banState['issued'] ?? [] as $ip => $issued) {
            if (! isset($current[$ip]) && (int) ($issued['at'] ?? 0) < $now - self::ISSUE_GRACE) {
                unset($banState['issued'][$ip]);
            }
        }
    }

    /** Output of `fail2ban-client ARGS`, or null when fail2ban is not installed, not running or refuses. */
    public static function fail2ban(array $args): ?string
    {
        if (! is_executable('/usr/bin/fail2ban-client')) {
            return null;
        }
        $process = proc_open(['/usr/bin/fail2ban-client', ...$args], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        if (! is_resource($process)) {
            return null;
        }
        $output = stream_get_contents($pipes[1], 1048576);
        fclose($pipes[1]);

        return proc_close($process) === 0 && is_string($output) ? $output : null;
    }

    /** Keep the newest $keep events of a website, or of one of its clients with $scope. */
    private static function trim(PDO $db, string $scope, array $values, int $keep): void
    {
        $cutoff = $db->prepare('SELECT id FROM api_web_waf_events WHERE server_id=? AND website_id=? AND identity=? '.$scope.' ORDER BY id DESC LIMIT 1 OFFSET '.($keep - 1));
        $cutoff->execute($values);
        if ($id = $cutoff->fetchColumn()) {
            $db->prepare('DELETE FROM api_web_waf_events WHERE server_id=? AND website_id=? AND identity=? '.$scope.' AND id<?')->execute([...$values, $id]);
        }
    }
}
