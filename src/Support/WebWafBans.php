<?php

namespace IspconfigRestHosting\Support;

/**
 * Ban decisions of the root WAF worker (spec 048), shared with the API for address/CIDR matching.
 *
 * The worker feeds every newly collected request of a WAF website; a client is banned when, within the window and
 * across all websites of the server, it sends enough requests over the anomaly threshold to enforcing websites
 * (attack) or requests matching scanner/protocol/restricted-file rules on enough distinct paths (scan). fail2ban
 * enforces the decision from the worker's ban log. Plain PHP without Laravel: it runs on web servers.
 */
final class WebWafBans
{
    public const DEFAULTS = ['enabled' => true, 'window' => 600, 'attack_requests' => 20, 'scan_paths' => 15];

    /** fail2ban jails and their ban times (waf-server/fail2ban/ispconfig-waf.local). */
    public const JAILS = ['ispconfig-waf' => 3600, 'ispconfig-waf-recidive' => 604800];

    /** The third ban within this time is a repeat and goes to the recidive jail. */
    public const REPEAT_WINDOW = 86400;

    public const REPEAT_BANS = 3;

    /** Inbound and outbound anomaly-threshold rules of CRS 4. */
    public const THRESHOLD_RULES = [949110, 949111, 959100, 959101];

    /** Rule families of scanners, protocol violations and restricted files: 913, 920, 921, 930. */
    public const SCAN_FAMILIES = [913, 920, 921, 930];

    /** Bounds of the persisted state. */
    private const MAX_CLIENTS = 20000;

    private const MAX_MARKS = 64;

    /** Settings of `/etc/ispconfig-waf/ban.local.json`; a missing, unsafe or invalid file gives the defaults. */
    public static function settings(?string $file = '/etc/ispconfig-waf/ban.local.json'): array
    {
        $settings = self::DEFAULTS;
        $text = $file !== null ? self::rootFile($file) : null;
        $data = $text !== null ? json_decode($text, true) : null;
        if (! is_array($data)) {
            return $settings;
        }
        if (is_bool($data['enabled'] ?? null)) {
            $settings['enabled'] = $data['enabled'];
        }
        foreach (['window' => [60, 86400], 'attack_requests' => [1, 10000], 'scan_paths' => [1, 1000]] as $key => [$min, $max]) {
            if (is_int($data[$key] ?? null) && $data[$key] >= $min && $data[$key] <= $max) {
                $settings[$key] = $data[$key];
            }
        }

        return $settings;
    }

    /** Addresses and blocks of `/etc/ispconfig-waf/ban-ignore.conf`, one per line, `#` comments. */
    public static function ignoreFile(string $file = '/etc/ispconfig-waf/ban-ignore.conf'): array
    {
        $text = self::rootFile($file);
        $blocks = [];
        foreach (explode("\n", (string) $text) as $line) {
            $line = trim(explode('#', $line, 2)[0]);
            if ($line !== '' && self::block($line) !== null) {
                $blocks[] = strtolower($line);
            }
        }

        return $blocks;
    }

    /** [network bytes, prefix length] of an address or CIDR block, or null. */
    public static function block(string $value): ?array
    {
        $parts = explode('/', $value);
        if (count($parts) > 2) {
            return null;
        }
        $address = @inet_pton($parts[0]);
        if ($address === false || ! filter_var($parts[0], FILTER_VALIDATE_IP)) {
            return null;
        }
        $bits = strlen($address) * 8;
        if (isset($parts[1]) && (! ctype_digit($parts[1]) || (int) $parts[1] > $bits)) {
            return null;
        }

        return [$address, isset($parts[1]) ? (int) $parts[1] : $bits];
    }

    /** One spelling per address (IPv6 compressed and lower case); invalid input is returned unchanged. */
    public static function canonical(string $ip): string
    {
        $address = filter_var($ip, FILTER_VALIDATE_IP) ? @inet_pton($ip) : false;

        return $address === false ? $ip : (string) inet_ntop($address);
    }

    /** Whether $ip lies in the address or CIDR block $value (IPv4 and IPv6, never across families). */
    public static function contains(string $value, string $ip): bool
    {
        $block = self::block($value);
        $address = filter_var($ip, FILTER_VALIDATE_IP) ? @inet_pton($ip) : false;
        if ($block === null || $address === false || strlen($address) !== strlen($block[0])) {
            return false;
        }
        [$network, $prefix] = $block;
        $bytes = intdiv($prefix, 8);
        if (substr($address, 0, $bytes) !== substr($network, 0, $bytes)) {
            return false;
        }
        $rest = $prefix % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rest)) & 0xFF;

        return (ord($address[$bytes]) & $mask) === (ord($network[$bytes]) & $mask);
    }

    /** Never banned: invalid, loopback, private or reserved addresses, and the given blocks (allowlists, ignore file). */
    public static function ignored(string $ip, array $blocks): bool
    {
        if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return true;
        }
        foreach ($blocks as $block) {
            if (self::contains((string) $block, $ip)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The requests of collected rule events: one per `request_key`, with its client, path, time and what counts for
     * the ban rules. Events without a valid client address are left out.
     *
     * @param  array<int, array<string, mixed>>  $events
     * @return array<string, array{client_ip: string, path: string, occurred_at: int, over_threshold: bool, scan: bool}>
     */
    public static function requests(array $events): array
    {
        $requests = [];
        foreach ($events as $event) {
            $key = (string) ($event['request_key'] ?? '');
            $ip = (string) ($event['client_ip'] ?? '');
            if ($key === '' || ! filter_var($ip, FILTER_VALIDATE_IP)) {
                continue;
            }
            $rule = (int) ($event['rule_id'] ?? 0);
            $request = $requests[$key] ?? ['client_ip' => $ip, 'path' => (string) ($event['path'] ?? '/'),
                'occurred_at' => (int) ($event['occurred_at'] ?? 0), 'over_threshold' => false, 'scan' => false];
            $request['over_threshold'] = $request['over_threshold'] || in_array($rule, self::THRESHOLD_RULES, true);
            $request['scan'] = $request['scan'] || in_array(intdiv($rule, 1000), self::SCAN_FAMILIES, true);
            $requests[$key] = $request;
        }

        return $requests;
    }

    /** Count one new request of a website in `detection` or `enforcing` mode. */
    public static function observe(array &$state, array $request, string $mode): void
    {
        $ip = self::canonical($request['client_ip']);
        $at = (int) $request['occurred_at'];
        $client = $state['clients'][$ip] ?? ['attack' => [], 'scan' => []];
        if ($request['over_threshold'] && $mode === 'enforcing') {
            $client['attack'][] = $at;
            $client['attack'] = array_slice($client['attack'], -self::MAX_MARKS);
        }
        if ($request['scan']) {
            $path = substr(hash('sha256', $request['path']), 0, 16);
            $last = max($at, (int) ($client['scan'][$path] ?? 0));
            unset($client['scan'][$path]);
            $client['scan'][$path] = $last;
            if (count($client['scan']) > self::MAX_MARKS) {
                $client['scan'] = array_slice($client['scan'], -self::MAX_MARKS, null, true);
            }
        }
        if ($client['attack'] !== [] || $client['scan'] !== []) {
            unset($state['clients'][$ip]);
            $state['clients'][$ip] = $client;
        }
    }

    /**
     * Clients to ban now, as [client_ip, reason, count]: `attack`, `scan`, or `repeat` for the third ban within a day.
     * A banned client starts counting again from zero; marks outside the window and old ban history are dropped.
     *
     * @return array<int, array{0: string, 1: string, 2: int}>
     */
    public static function decide(array &$state, array $settings, array $ignored, int $now): array
    {
        $since = $now - (int) $settings['window'];
        $bans = [];
        foreach ($state['clients'] ?? [] as $ip => $client) {
            $client['attack'] = array_values(array_filter($client['attack'], fn ($at) => $at > $since && $at <= $now + 300));
            $client['scan'] = array_filter($client['scan'], fn ($at) => $at > $since && $at <= $now + 300);
            $ip = (string) $ip;
            $reason = null;
            if (count($client['attack']) >= $settings['attack_requests']) {
                [$reason, $count] = ['attack', count($client['attack'])];
            } elseif (count($client['scan']) >= $settings['scan_paths']) {
                [$reason, $count] = ['scan', count($client['scan'])];
            }
            if ($reason !== null && $settings['enabled'] && ! self::ignored($ip, $ignored)) {
                $history = array_values(array_filter($state['banned'][$ip] ?? [], fn ($at) => $at > $now - self::REPEAT_WINDOW));
                $history[] = $now;
                $state['banned'][$ip] = $history;
                $bans[] = [$ip, count($history) >= self::REPEAT_BANS ? 'repeat' : $reason, $count];
                $client = ['attack' => [], 'scan' => []];
            }
            if ($client['attack'] === [] && $client['scan'] === []) {
                unset($state['clients'][$ip]);
            } else {
                $state['clients'][$ip] = $client;
            }
        }
        foreach ($state['banned'] ?? [] as $ip => $history) {
            $history = array_values(array_filter($history, fn ($at) => $at > $now - self::REPEAT_WINDOW));
            if ($history === []) {
                unset($state['banned'][$ip]);
            } else {
                $state['banned'][$ip] = array_slice($history, -self::REPEAT_BANS);
            }
        }
        foreach (['clients', 'banned'] as $key) {
            if (count($state[$key] ?? []) > self::MAX_CLIENTS) {
                $state[$key] = array_slice($state[$key], -self::MAX_CLIENTS, null, true);
            }
        }

        return $bans;
    }

    /** One line of the ban log, read by the fail2ban filters in waf-server/fail2ban. */
    public static function line(string $ip, string $reason, int $count, int $now): string
    {
        return gmdate('Y-m-d\TH:i:s', $now).'+0000 ispconfig-waf ban '.$ip.' reason='.$reason.' count='.$count."\n";
    }

    /** Banned addresses in the output of `fail2ban-client status JAIL`. */
    public static function banned(string $status): array
    {
        if (! preg_match('/Banned IP list:[ \t]*([^\n]*)/', $status, $match)) {
            return [];
        }

        return array_values(array_filter(preg_split('/[\s,]+/', trim($match[1])) ?: [], fn ($ip) => (bool) filter_var($ip, FILTER_VALIDATE_IP)));
    }

    /** A root-owned regular file that only root may change, or null. */
    private static function rootFile(string $file): ?string
    {
        $stat = @lstat($file);
        if (! $stat || is_link($file) || $stat['uid'] !== 0 || ($stat['mode'] & 0022) || ($stat['mode'] & 0170000) !== 0100000 || $stat['size'] > 65536) {
            return null;
        }
        $text = file_get_contents($file);

        return $text === false ? null : $text;
    }
}
