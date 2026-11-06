<?php

namespace IspconfigRestHosting\Tests\Unit;

use IspconfigRestHosting\Support\WebWafBans;
use PHPUnit\Framework\TestCase;

final class WebWafBansTest extends TestCase
{
    private const NOW = 1793952000;

    /** One request of a client: rule events with the same request_key, as WebWafAudit::events() returns them. */
    private function request(string $ip, string $path, array $rules, int $at = self::NOW, ?string $key = null): array
    {
        $key ??= hash('sha256', $ip.$path.$at.implode(',', $rules).random_bytes(4));

        return array_map(fn (int $rule): array => ['request_key' => $key, 'client_ip' => $ip, 'path' => $path, 'occurred_at' => $at, 'rule_id' => $rule], $rules);
    }

    private function feed(array &$state, array $events, string $mode = 'enforcing'): void
    {
        foreach (WebWafBans::requests($events) as $request) {
            WebWafBans::observe($state, $request, $mode);
        }
    }

    public function test_addresses_and_blocks_match_within_their_family(): void
    {
        $this->assertTrue(WebWafBans::contains('203.0.113.0/24', '203.0.113.77'));
        $this->assertFalse(WebWafBans::contains('203.0.113.0/25', '203.0.113.200'));
        $this->assertTrue(WebWafBans::contains('203.0.113.7', '203.0.113.7'));
        $this->assertTrue(WebWafBans::contains('0.0.0.0/0', '198.51.100.1'));
        $this->assertTrue(WebWafBans::contains('2001:db8::/32', '2001:0DB8:0:1::5'));
        $this->assertTrue(WebWafBans::contains('2001:db8::1', '2001:0db8:0000::1'));
        $this->assertFalse(WebWafBans::contains('::/0', '198.51.100.1'), 'IPv6 blocks never match IPv4 clients');
        $this->assertTrue(WebWafBans::contains('203.0.113.0/23', '203.0.112.9'));
        foreach (['203.0.113.0/33', '2001:db8::/129', '1.2.3', '1.2.3.4/x', '1.2.3.4/24/1', ''] as $invalid) {
            $this->assertNull(WebWafBans::block($invalid), $invalid);
            $this->assertFalse(WebWafBans::contains($invalid, '1.2.3.4'), $invalid);
        }
        $this->assertSame('2001:db8::1', WebWafBans::canonical('2001:0DB8:0000::1'));
        $this->assertSame('not-an-ip', WebWafBans::canonical('not-an-ip'));
    }

    public function test_private_reserved_and_allowlisted_clients_are_never_banned(): void
    {
        foreach (['127.0.0.1', '10.0.10.21', '192.168.1.5', '172.16.0.1', '::1', 'fd00::1', '0.0.0.0', 'garbage'] as $ip) {
            $this->assertTrue(WebWafBans::ignored($ip, []), $ip);
        }
        $this->assertFalse(WebWafBans::ignored('203.0.113.9', []));
        $this->assertTrue(WebWafBans::ignored('203.0.113.9', ['203.0.113.0/24']));
        $this->assertFalse(WebWafBans::ignored('2a01:4f8:1::9', []));
        $this->assertTrue(WebWafBans::ignored('2a01:4f8:1::9', ['2a01:4f8::/32']));
    }

    public function test_requests_group_rule_events_and_classify_threshold_and_scan_rules(): void
    {
        $events = [...$this->request('203.0.113.1', '/', [942100, 949110, 980170], key: 'a'),
            ...$this->request('203.0.113.1', '/.env', [930130, 980170], key: 'b'),
            ...$this->request('203.0.113.1', '/q', [941100, 980170], key: 'c'),
            ...$this->request('203.0.113.1', '/out', [951120, 959100], key: 'd'),
            ...$this->request('', '/', [920350], key: 'e')];
        $requests = WebWafBans::requests($events);
        $this->assertSame(['a', 'b', 'c', 'd'], array_keys($requests));
        $this->assertTrue($requests['a']['over_threshold']);
        $this->assertFalse($requests['a']['scan']);
        $this->assertTrue($requests['b']['scan']);
        $this->assertFalse($requests['c']['over_threshold'] || $requests['c']['scan'], 'injection rules alone do not count');
        $this->assertTrue($requests['d']['over_threshold'], 'outbound threshold counts');
    }

    public function test_attack_needs_twenty_threshold_requests_to_enforcing_websites_within_the_window(): void
    {
        $state = [];
        for ($i = 0; $i < 19; $i++) {
            $this->feed($state, $this->request('203.0.113.5', '/', [942100, 949110], self::NOW - 500 + $i));
        }
        $this->feed($state, $this->request('203.0.113.5', '/', [942100, 949110]), 'detection');
        $this->assertSame([], WebWafBans::decide($state, WebWafBans::DEFAULTS, [], self::NOW), 'detection websites do not count for attacks');
        $this->feed($state, $this->request('203.0.113.5', '/', [942100, 949110]));
        $this->assertSame([['203.0.113.5', 'attack', 20]], WebWafBans::decide($state, WebWafBans::DEFAULTS, [], self::NOW));
        $this->assertSame([], WebWafBans::decide($state, WebWafBans::DEFAULTS, [], self::NOW + 1), 'a banned client starts from zero');

        $state = [];
        for ($i = 0; $i < 20; $i++) {
            $this->feed($state, $this->request('203.0.113.6', '/', [949110], self::NOW - 700 + $i * 10));
        }
        $this->assertSame([], WebWafBans::decide($state, WebWafBans::DEFAULTS, [], self::NOW), 'requests outside the window expire');
    }

    public function test_scan_needs_fifteen_distinct_paths_also_on_detection_websites(): void
    {
        $state = [];
        for ($i = 0; $i < 30; $i++) {
            $this->feed($state, $this->request('198.51.100.9', '/same', [920350]), 'detection');
        }
        for ($i = 0; $i < 13; $i++) {
            $this->feed($state, $this->request('198.51.100.9', '/probe'.$i, [930130]), 'detection');
        }
        for ($i = 0; $i < 20; $i++) {
            $this->feed($state, $this->request('198.51.100.9', '/xss'.$i, [941100, 980170]), 'detection');
        }
        $this->assertSame([], WebWafBans::decide($state, WebWafBans::DEFAULTS, [], self::NOW), 'one repeated path and injection rules do not make a scan');
        $this->feed($state, $this->request('198.51.100.9', '/.git/config', [930130]), 'detection');
        $this->assertSame([['198.51.100.9', 'scan', 15]], WebWafBans::decide($state, WebWafBans::DEFAULTS, [], self::NOW));
    }

    public function test_third_ban_within_a_day_is_a_repeat_and_ignored_or_disabled_bans_none(): void
    {
        $state = [];
        $bans = [];
        foreach ([0, 4000, 8000] as $offset) {
            for ($i = 0; $i < 20; $i++) {
                $this->feed($state, $this->request('203.0.113.8', '/', [949110], self::NOW + $offset));
            }
            $bans[] = WebWafBans::decide($state, WebWafBans::DEFAULTS, [], self::NOW + $offset)[0][1];
        }
        $this->assertSame(['attack', 'attack', 'repeat'], $bans);

        for ($i = 0; $i < 20; $i++) {
            $this->feed($state, $this->request('203.0.113.9', '/', [949110]));
            $this->feed($state, $this->request('203.0.113.10', '/', [949110]));
        }
        $this->assertSame([['203.0.113.10', 'attack', 20]], WebWafBans::decide($state, WebWafBans::DEFAULTS, ['203.0.113.9/32'], self::NOW));
        for ($i = 0; $i < 20; $i++) {
            $this->feed($state, $this->request('203.0.113.11', '/', [949110]));
        }
        $this->assertSame([], WebWafBans::decide($state, ['enabled' => false] + WebWafBans::DEFAULTS, [], self::NOW));
    }

    public function test_production_traffic_of_2026_11_06_bans_the_three_attackers_only(): void
    {
        $state = [];
        $start = self::NOW - 590;
        // 93.123.109.178: SQL injection on /, 74 blocked requests within 2.5 minutes.
        for ($i = 0; $i < 74; $i++) {
            $this->feed($state, $this->request('93.123.109.178', '/', [942100, 942190, 949110, 980170], $start + intdiv($i * 146, 74)));
        }
        // 34.174.190.229: secret files on 245 paths in 42 seconds, none over the threshold.
        for ($i = 0; $i < 245; $i++) {
            $this->feed($state, $this->request('34.174.190.229', '/.env'.$i, [[920440, 920500, 930130][$i % 3], 980170], $start + intdiv($i * 42, 245)));
        }
        // 45.148.10.59: 18 auth endpoints with malformed charsets, about 325 requests below the threshold.
        for ($i = 0; $i < 325; $i++) {
            $this->feed($state, $this->request('45.148.10.59', '/auth/'.($i % 18), [920480, 920530, 980170], $start + $i));
        }
        // The rest: a few probes or false positives each.
        foreach (['45.148.10.244' => [920450, 949110], '45.91.64.10' => [920280, 920350], '51.83.249.216' => [942100, 949110], '43.153.87.54' => [920350]] as $ip => $rules) {
            for ($i = 0; $i < 4; $i++) {
                $this->feed($state, $this->request($ip, $i % 2 ? '/' : '/x'.$i, [...$rules, 980170], $start + $i));
            }
        }
        $bans = WebWafBans::decide($state, WebWafBans::DEFAULTS, [], self::NOW);
        sort($bans);
        $this->assertSame([['34.174.190.229', 'scan', 64], ['45.148.10.59', 'scan', 18], ['93.123.109.178', 'attack', 64]], $bans);
    }

    public function test_ban_line_matches_the_shipped_jails_and_status_parsing(): void
    {
        $this->assertSame("2026-11-06T10:40:00+0000 ispconfig-waf ban 203.0.113.5 reason=attack count=20\n", WebWafBans::line('203.0.113.5', 'attack', 20, 1793961600));
        $jails = [];
        $section = '';
        foreach (file(dirname(__DIR__, 2).'/waf-server/fail2ban/ispconfig-waf.local', FILE_IGNORE_NEW_LINES) as $line) {
            if (preg_match('/^\[([a-z-]+)\]$/', $line, $match)) {
                $section = $match[1];
            } elseif (preg_match('/^([a-z_]+) = (.*)$/', $line, $match)) {
                $jails[$section][$match[1]] = $match[2];
            }
        }
        foreach (WebWafBans::JAILS as $jail => $bantime) {
            $this->assertSame((string) $bantime, $jails[$jail]['bantime'], $jail);
            $this->assertSame('/var/log/ispconfig-waf/bans.log', $jails[$jail]['logpath']);
            $this->assertSame('http,https', $jails[$jail]['port']);
        }
        $status = "Status for the jail: ispconfig-waf\n|- Filter\n|  |- Currently failed:\t0\n`- Actions\n   |- Currently banned:\t2\n   |- Total banned:\t5\n   `- Banned IP list:\t203.0.113.5 2001:db8::7\n";
        $this->assertSame(['203.0.113.5', '2001:db8::7'], WebWafBans::banned($status));
        $this->assertSame([], WebWafBans::banned("   `- Banned IP list:\t\n"));
        $this->assertSame([], WebWafBans::banned('ERROR: no jail'));
    }

    public function test_settings_ignore_files_not_owned_by_root(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'ban');
        file_put_contents($file, json_encode(['enabled' => false, 'attack_requests' => 5]));
        $expected = posix_geteuid() === 0 ? array_replace(WebWafBans::DEFAULTS, ['enabled' => false, 'attack_requests' => 5]) : WebWafBans::DEFAULTS;
        $this->assertSame($expected, WebWafBans::settings($file));
        $this->assertSame(WebWafBans::DEFAULTS, WebWafBans::settings('/nonexistent/ban.local.json'));
        unlink($file);
    }
}
