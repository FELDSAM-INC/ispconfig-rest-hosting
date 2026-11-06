<?php

namespace IspconfigRestHosting\Tests\Feature;

use Illuminate\Support\Facades\DB;
use IspconfigRestHosting\Support\WebWafPolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\SitesApiTestCase;
use Tests\Support\TenantFixtures;
use Tests\Support\TenantSchema;

final class WebWafApiTest extends SitesApiTestCase
{
    use TenantFixtures;

    private function worker(int $server = 1, bool $atomic = false): void
    {
        DB::table('api_web_waf_workers')->insert(['server_id' => $server, 'heartbeat' => time(), 'engine' => $server === 1 ? 'apache' : 'nginx', 'rules_version' => '3.3.7', 'atomic_available' => $atomic, 'application_profiles' => json_encode(['wordpress'])]);
    }

    public function test_client_settings_are_scoped_datalogged_and_preserve_unrelated_directives(): void
    {
        TenantSchema::create();
        $this->seedTenants();
        $this->worker();
        $id = $this->seedVhost($this->ownedBy('clientA', ['apache_directives' => "Header set X-Test value\n"]));
        $url = '/api/v1/sites/web-domains/'.$id.'/waf';
        $headers = $this->tenantHeaders('clientA');
        $this->getJson($url, $headers)->assertOk()->assertJsonPath('available', true)->assertJsonPath('settings.enabled', false);
        $this->getJson('/api/v1/sites/web-domains/'.$id, $headers)->assertOk()->assertJsonPath('waf_mode', 'off');
        $this->putJson($url, ['enabled' => true, 'exclusions' => [['rule_id' => 942100, 'path' => '/allowed', 'parameter' => 'q']], 'ip_allowlist' => ['192.0.2.1']], $headers)->assertOk()->assertJsonPath('settings.mode', 'detection');
        $raw = DB::table('web_domain')->where('domain_id', $id)->value('apache_directives');
        $this->assertStringContainsString('Header set X-Test value', $raw);
        $this->assertStringContainsString('SecRuleEngine DetectionOnly', $raw);
        $this->assertStringContainsString('ctl:ruleRemoveTargetById=942100;ARGS:q', $raw);
        $this->assertCount(1, $this->datalogRows('web_domain'));
        $this->putJson($url, ['enabled' => true], $headers)->assertOk();
        $this->assertCount(1, $this->datalogRows('web_domain'));
        $this->getJson('/api/v1/sites/web-domains/'.$id, $headers)->assertOk()->assertJsonPath('waf_mode', 'detection');
        $this->putJson($url, ['mode' => 'enforcing'], $headers)->assertOk()->assertJsonPath('settings.exclusions.0.rule_id', 942100);
        $this->assertCount(2, $this->datalogRows('web_domain'));
        $this->getJson('/api/v1/sites/web-domains', $headers)->assertOk()->assertJsonPath('data.0.waf_mode', 'enforcing');
        $this->getJson($url, $this->tenantHeaders('clientB'))->assertNotFound();
        $this->putJson($url, ['enabled' => false], $this->tenantHeaders('clientB'))->assertNotFound();
        $this->getJson($url)->assertUnauthorized();
        $this->putJson($url, ['enabled' => false])->assertUnauthorized();
    }

    public function test_vhost_nginx_and_licensed_additional_rules_and_offline_disable(): void
    {
        $this->worker(2, true);
        $id = $this->seedVhost(['server_id' => 2, 'type' => 'vhostsubdomain']);
        $url = '/api/v1/sites/web-domains/'.$id.'/waf';
        $this->putJson($url, ['enabled' => true, 'atomic' => true], $this->authHeaders())->assertOk();
        $raw = DB::table('web_domain')->where('domain_id', $id)->value('nginx_directives');
        $this->assertStringContainsString('Include /etc/ispconfig-waf/owasp.conf', $raw);
        $this->assertStringContainsString('Include /etc/ispconfig-waf/atomic.conf', $raw);
        $this->assertStringNotContainsString('SecRemoteRules', $raw);
        DB::table('api_web_waf_workers')->update(['heartbeat' => time() - 200]);
        $this->putJson($url, ['enabled' => true], $this->authHeaders())->assertUnprocessable();
        $this->putJson($url, ['enabled' => false], $this->authHeaders())->assertOk();
        $this->assertStringNotContainsString('modsecurity on', DB::table('web_domain')->where('domain_id', $id)->value('nginx_directives'));
    }

    public function test_unlicensed_atomic_is_rejected_without_datalog(): void
    {
        $this->worker();
        $id = $this->seedVhost();
        $this->putJson('/api/v1/sites/web-domains/'.$id.'/waf', ['enabled' => true, 'atomic' => true], $this->authHeaders())->assertUnprocessable();
        $this->assertCount(0, $this->datalogRows('web_domain'));
    }

    #[DataProvider('invalid')]
    public function test_invalid_rules_cannot_change_configuration(array $body): void
    {
        $this->worker();
        $id = $this->seedVhost();
        $this->putJson('/api/v1/sites/web-domains/'.$id.'/waf', $body, $this->authHeaders())->assertUnprocessable();
        $this->assertCount(0, $this->datalogRows('web_domain'));
    }

    public static function invalid(): array
    {
        return array_map(fn ($body) => [$body], [['mode' => 'Off'], ['enabled' => 'yes'], ['enabled' => null], ['license_key' => 'secret'], ['raw' => 'SecRuleEngine Off'],
            ['application_profile' => 'wordpress,ctl:ruleEngine=Off'], ['application_profile' => ['wordpress']], ['application_profile' => null], ['application_profile' => 'joomla'],
            ['exclusions' => [['rule_id' => 1, 'path' => "/x\nSecRuleEngine Off"]]], ['exclusions' => [['rule_id' => 1, 'path' => "/x' ; }"]]],
            ['exclusions' => [['rule_id' => 1, 'parameter' => 'q;ctl:ruleEngine=Off']]], ['exclusions' => [['rule_id' => '1-999999']]],
            ['exclusions' => [['rule_id' => 0]]], ['exclusions' => [['rule_id' => 1, 'unexpected' => 'x']]],
            ['ip_allowlist' => ['0.0.0.0/33']], ['ip_allowlist' => ['::/129']], ['ip_allowlist' => ['192.0.2.1"']]]);
    }

    public function test_events_are_bound_to_owner_identity_and_filterable(): void
    {
        TenantSchema::create();
        $this->seedTenants();
        $id = $this->seedVhost($this->ownedBy('clientA'));
        $site = (array) DB::table('web_domain')->where('domain_id', $id)->first();
        foreach (['correct', 'old-owner'] as $which) {
            DB::table('api_web_waf_events')->insert(['event_key' => hash('sha256', $which), 'server_id' => 1, 'website_id' => $id,
                'identity' => $which === 'correct' ? WebWafPolicy::identity($site) : '1-old-owner', 'occurred_at' => time(), 'rule_id' => 942100, 'outcome' => 'detected',
                'client_ip' => '192.0.2.1', 'method' => 'GET', 'path' => '/test', 'parameter' => 'q', 'message' => 'SQLi detected', 'severity' => '2', 'source' => 'owasp']);
        }
        $url = '/api/v1/sites/web-domains/'.$id.'/waf/events';
        $headers = $this->tenantHeaders('clientA');
        $this->getJson($url, $headers)->assertOk()->assertJsonPath('meta.total', 1)->assertJsonPath('data.0.rule_id', 942100)->assertJsonMissingPath('data.0.identity');
        $this->getJson($url.'?outcome=blocked', $headers)->assertJsonPath('meta.total', 0);
        $this->getJson($url.'?limit=101', $headers)->assertUnprocessable();
        $this->getJson($url, $this->tenantHeaders('clientB'))->assertNotFound();
        $this->getJson($url)->assertUnauthorized();
    }

    private function event(int $website, string $identity, string $ip, string $key, int $rule = 942100): void
    {
        DB::table('api_web_waf_events')->insert(['event_key' => hash('sha256', $key), 'server_id' => 1, 'website_id' => $website,
            'identity' => $identity, 'occurred_at' => time(), 'rule_id' => $rule, 'outcome' => 'blocked',
            'client_ip' => $ip, 'method' => 'GET', 'path' => '/', 'parameter' => '', 'message' => 'SQLi detected', 'severity' => '2', 'source' => 'owasp']);
    }

    private function ban(string $ip, int $expires, string $reason = 'attack', int $server = 1): void
    {
        DB::table('api_web_waf_bans')->insert(['server_id' => $server, 'client_ip' => $ip, 'jail' => 'ispconfig-waf', 'reason' => $reason,
            'banned_at' => time() - 60, 'expires_at' => $expires]);
    }

    public function test_events_filter_by_client_address_block_and_current_ban(): void
    {
        TenantSchema::create();
        $this->seedTenants();
        $id = $this->seedVhost($this->ownedBy('clientA'));
        $identity = WebWafPolicy::identity((array) DB::table('web_domain')->where('domain_id', $id)->first());
        foreach (['203.0.113.5', '203.0.113.5', '203.0.113.77', '198.51.100.1', '2001:db8::7'] as $n => $ip) {
            $this->event($id, $identity, $ip, 'filter-'.$n);
        }
        $this->ban('203.0.113.5', time() + 3600);
        $this->ban('198.51.100.1', time() - 1);
        $this->ban('2001:db8::7', time() + 3600, 'scan', 2);
        $url = '/api/v1/sites/web-domains/'.$id.'/waf/events';
        $headers = $this->tenantHeaders('clientA');
        $this->getJson($url.'?client_ip=203.0.113.0/24', $headers)->assertOk()->assertJsonPath('meta.total', 3);
        $this->getJson($url.'?client_ip=2001:0DB8::7', $headers)->assertOk()->assertJsonPath('meta.total', 1)->assertJsonPath('data.0.client_ip', '2001:db8::7')
            ->assertJsonPath('data.0.client_banned', false);
        $banned = $this->getJson($url.'?banned=true', $headers)->assertOk()->assertJsonPath('meta.total', 2);
        $this->assertSame([true, true], array_column($banned->json('data'), 'client_banned'));
        $this->assertSame(['203.0.113.5'], array_values(array_unique(array_column($banned->json('data'), 'client_ip'))));
        $this->getJson($url.'?banned=false&client_ip=198.51.100.0/24', $headers)->assertOk()->assertJsonPath('meta.total', 1)->assertJsonPath('data.0.client_banned', false);
        $this->getJson($url.'?banned=0&limit=2&offset=1', $headers)->assertOk()->assertJsonPath('meta.total', 3)->assertJsonCount(2, 'data');
        $this->getJson($url, $headers)->assertOk()->assertJsonPath('meta.total', 5);
        foreach (['client_ip=203.0.113.0/33', 'client_ip=example.com', 'client_ip=1.2.3.4/24/1', 'banned=maybe'] as $invalid) {
            $this->getJson($url.'?'.$invalid, $headers)->assertUnprocessable();
        }
    }

    public function test_clients_list_totals_and_bans_of_the_owners_website_only(): void
    {
        TenantSchema::create();
        $this->seedTenants();
        $id = $this->seedVhost($this->ownedBy('clientA'));
        $other = $this->seedVhost($this->ownedBy('clientA', ['domain' => 'other.test']));
        $identity = WebWafPolicy::identity((array) DB::table('web_domain')->where('domain_id', $id)->first());
        $now = time();
        $client = fn (int $website, string $identity, string $ip, int $requests, int $over) => DB::table('api_web_waf_clients')->insert(['server_id' => 1,
            'website_id' => $website, 'identity' => $identity, 'client_ip' => $ip, 'events' => $requests * 3, 'requests' => $requests,
            'over_threshold' => $over, 'first_seen' => $now - 600, 'last_seen' => $now - 60]);
        $client($id, $identity, '198.18.93.178', 74, 74);
        $client($id, $identity, '198.18.34.229', 170, 0);
        $client($id, $identity, '198.51.100.1', 1, 1);
        $client($id, '1-old-owner', '203.0.113.200', 900, 0);
        $client($other, WebWafPolicy::identity((array) DB::table('web_domain')->where('domain_id', $other)->first()), '203.0.113.201', 900, 0);
        $this->ban('198.18.93.178', $now + 3600);
        $this->ban('198.18.34.229', $now + 604800, 'repeat');
        $url = '/api/v1/sites/web-domains/'.$id.'/waf/clients';
        $headers = $this->tenantHeaders('clientA');
        $response = $this->getJson($url, $headers)->assertOk()->assertHeader('Cache-Control', 'no-store, private')->assertJsonPath('meta.total', 3);
        $this->assertSame(['198.18.34.229', '198.18.93.178', '198.51.100.1'], array_column($response->json('data'), 'client_ip'));
        $response->assertJsonPath('data.0.ban.reason', 'repeat')->assertJsonPath('data.1.ban.reason', 'attack')->assertJsonPath('data.1.over_threshold', 74)
            ->assertJsonPath('data.1.events', 222)->assertJsonPath('data.2.ban', null)->assertJsonPath('data.1.ban.expires_at', gmdate('Y-m-d\TH:i:s\Z', $now + 3600));
        $this->getJson($url.'?client_ip=198.18.93.0/24', $headers)->assertOk()->assertJsonPath('meta.total', 1);
        $this->getJson($url.'?banned=true&limit=1', $headers)->assertOk()->assertJsonPath('meta.total', 2)->assertJsonCount(1, 'data');
        $this->getJson($url.'?limit=101', $headers)->assertUnprocessable();
        $this->getJson($url, $this->tenantHeaders('clientB'))->assertNotFound();
        $this->getJson($url)->assertUnauthorized();
    }

    public function test_locked_client_cannot_change_waf(): void
    {
        TenantSchema::create();
        $this->seedTenants();
        $this->worker();
        $id = $this->seedVhost($this->ownedBy('clientA'));
        $site = DB::table('web_domain')->where('domain_id', $id)->first();
        $client = DB::table('sys_group')->where('groupid', $site->sys_groupid)->value('client_id');
        DB::table('client')->where('client_id', $client)->update(['locked' => 'y']);
        $this->putJson('/api/v1/sites/web-domains/'.$id.'/waf', ['enabled' => true], $this->tenantHeaders('clientA'))->assertForbidden();
        $this->assertCount(0, $this->datalogRows('web_domain'));
    }

    public function test_revision_prevents_lost_updates_and_worker_outage_keeps_disable_available(): void
    {
        $this->worker();
        $id = $this->seedVhost();
        $url = '/api/v1/sites/web-domains/'.$id.'/waf';
        $revision = $this->getJson($url, $this->authHeaders())->json('revision');
        $this->putJson($url, ['enabled' => true, 'expected_revision' => $revision], $this->authHeaders())->assertOk();
        $this->putJson($url, ['mode' => 'enforcing', 'expected_revision' => $revision], $this->authHeaders())->assertConflict();
        DB::table('api_web_waf_workers')->delete();
        $this->getJson('/api/v1/sites/web-domains/'.$id, $this->authHeaders())->assertJsonPath('waf_available', true);
        $this->putJson($url, ['enabled' => false], $this->authHeaders())->assertOk();
    }

    public function test_rename_regenerates_identity_and_log_path(): void
    {
        $this->worker();
        $id = $this->seedVhost();
        $url = '/api/v1/sites/web-domains/'.$id;
        $this->putJson($url.'/waf', ['enabled' => true], $this->authHeaders())->assertOk();
        $old = (array) DB::table('web_domain')->where('domain_id', $id)->first();
        $this->putJson($url, ['domain' => 'renamed.example.test'], $this->authHeaders())->assertOk();
        $new = (array) DB::table('web_domain')->where('domain_id', $id)->first();
        $this->assertStringNotContainsString(WebWafPolicy::identity($old), $new['apache_directives']);
        $this->assertStringContainsString(WebWafPolicy::identity($new), $new['apache_directives']);
        $this->getJson($url.'/waf', $this->authHeaders())->assertOk()->assertJsonPath('settings.enabled', true);
    }

    public function test_read_only_client_and_corrupted_configuration_are_rejected(): void
    {
        TenantSchema::create();
        $this->seedTenants();
        $this->worker();
        $id = $this->seedVhost($this->ownedBy('clientA', ['sys_perm_user' => 'r', 'sys_perm_group' => 'r']));
        $url = '/api/v1/sites/web-domains/'.$id.'/waf';
        $this->putJson($url, ['enabled' => true], $this->tenantHeaders('clientA'))->assertForbidden();
        DB::table('web_domain')->where('domain_id', $id)->update(['apache_directives' => WebWafPolicy::BEGIN.' invalid']);
        $this->putJson($url, ['enabled' => true], $this->authHeaders())->assertConflict();
        $this->getJson('/api/v1/sites/web-domains/'.$id, $this->authHeaders())->assertOk()->assertJsonPath('waf_mode', null);
        $this->assertCount(0, $this->datalogRows('web_domain'));
    }

    public function test_account_transfer_discards_previous_owner_exceptions(): void
    {
        TenantSchema::create();
        $this->seedTenants();
        $this->worker();
        $id = $this->seedVhost($this->ownedBy('clientA'));
        $url = '/api/v1/sites/web-domains/'.$id;
        $this->putJson($url.'/waf', ['enabled' => true, 'application_profile' => 'wordpress', 'exclusions' => [['rule_id' => 942100]], 'ip_allowlist' => ['192.0.2.1']], $this->authHeaders())->assertOk();
        $newOwner = $this->ownedBy('clientB');
        $this->putJson($url, ['sys_groupid' => $newOwner['sys_groupid']], $this->authHeaders())->assertOk();
        $this->getJson($url.'/waf', $this->tenantHeaders('clientB'))->assertOk()->assertJsonPath('settings.enabled', false)->assertJsonPath('settings.exclusions', [])->assertJsonPath('settings.ip_allowlist', [])->assertJsonPath('settings.application_profile', 'none');

    }

    public function test_profile_is_server_scoped_and_partial_updates_preserve_exceptions(): void
    {
        $this->worker();
        $this->worker(2);
        DB::table('api_web_waf_workers')->where('server_id', 2)->update(['application_profiles' => '["nextcloud","unknown","nextcloud"]']);
        $id = $this->seedVhost();
        $other = $this->seedVhost(['server_id' => 2]);
        $url = '/api/v1/sites/web-domains/'.$id.'/waf';
        $otherUrl = '/api/v1/sites/web-domains/'.$other.'/waf';
        $headers = $this->authHeaders();
        $this->getJson($url, $headers)->assertOk()->assertJsonPath('application_profiles', ['none', 'wordpress'])->assertJsonPath('settings.application_profile', 'none');
        $this->getJson($otherUrl, $headers)->assertOk()->assertJsonPath('application_profiles', ['none', 'nextcloud']);
        $this->putJson($otherUrl, ['application_profile' => 'wordpress'], $headers)->assertUnprocessable();
        $this->putJson($url, ['application_profile' => 'wordpress', 'enabled' => true, 'exclusions' => [['rule_id' => 942100, 'path' => '/search', 'parameter' => 'q']]], $headers)
            ->assertOk()->assertJsonPath('settings.application_profile', 'wordpress');
        $raw = DB::table('web_domain')->where('domain_id', $id)->value('apache_directives');
        $this->assertStringContainsString('setvar:tx.ispcp_application_profile=wordpress', $raw);
        $this->putJson($url, ['mode' => 'enforcing'], $headers)->assertOk()->assertJsonPath('settings.application_profile', 'wordpress');
        $this->putJson($url, ['application_profile' => 'none'], $headers)->assertOk()->assertJsonPath('settings.exclusions.0.rule_id', 942100);
        $this->getJson($otherUrl, $headers)->assertJsonPath('settings.enabled', false)->assertJsonPath('settings.application_profile', 'none');
    }

    public function test_removed_profile_cannot_be_enabled_but_can_be_retained_when_disabling(): void
    {
        $this->worker();
        $id = $this->seedVhost();
        $url = '/api/v1/sites/web-domains/'.$id.'/waf';
        $headers = $this->authHeaders();
        $this->putJson($url, ['application_profile' => 'wordpress', 'enabled' => true], $headers)->assertOk();
        DB::table('api_web_waf_workers')->update(['application_profiles' => '[]']);
        $this->putJson($url, ['mode' => 'enforcing'], $headers)->assertUnprocessable();
        $this->assertCount(1, $this->datalogRows('web_domain'));
        $this->putJson($url, ['enabled' => false], $headers)->assertOk()->assertJsonPath('settings.application_profile', 'wordpress');
        $this->putJson($url, ['enabled' => true, 'application_profile' => 'none'], $headers)->assertOk();
        DB::table('api_web_waf_workers')->update(['heartbeat' => time() - 200]);
        $this->putJson($url, ['enabled' => false], $headers)->assertOk();
        $this->getJson($url, $headers)->assertJsonPath('application_profiles', ['none']);
    }

    public function test_old_workers_and_pre_profile_configuration_remain_compatible(): void
    {
        $this->worker();
        DB::table('api_web_waf_workers')->update(['application_profiles' => null]);
        $id = $this->seedVhost();
        $site = (array) DB::table('web_domain')->where('domain_id', $id)->first();
        $oldSettings = WebWafPolicy::DEFAULTS;
        unset($oldSettings['application_profile']);
        $marker = WebWafPolicy::BEGIN.' '.base64_encode(json_encode(['identity' => WebWafPolicy::identity($site), 'settings' => $oldSettings]))."\n".WebWafPolicy::END."\n";
        DB::table('web_domain')->where('domain_id', $id)->update(['apache_directives' => $marker]);
        $url = '/api/v1/sites/web-domains/'.$id.'/waf';
        $this->getJson($url, $this->authHeaders())->assertOk()->assertJsonPath('application_profiles', ['none'])->assertJsonPath('settings.application_profile', 'none');
        $this->putJson($url, ['application_profile' => 'wordpress'], $this->authHeaders())->assertUnprocessable();
        $this->putJson($url, ['enabled' => true], $this->authHeaders())->assertOk();
    }

    public function test_ispconfig_crlf_save_preserves_waf_settings_and_can_be_updated(): void
    {
        $this->worker();
        $id = $this->seedVhost(['apache_directives' => "Header set X-Test value\n"]);
        $url = '/api/v1/sites/web-domains/'.$id.'/waf';
        $settings = ['enabled' => true, 'application_profile' => 'wordpress', 'exclusions' => [['rule_id' => 942100, 'path' => '/search', 'parameter' => 'q']]];
        $this->putJson($url, $settings, $this->authHeaders())->assertOk();
        $raw = DB::table('web_domain')->where('domain_id', $id)->value('apache_directives');
        // Browser textarea submission through ISPConfig changes LF into CRLF.
        DB::table('web_domain')->where('domain_id', $id)->update(['apache_directives' => str_replace("\n", "\r\n", $raw)]);
        $this->getJson($url, $this->authHeaders())->assertOk()->assertJsonPath('settings.application_profile', 'wordpress')
            ->assertJsonPath('settings.exclusions.0.rule_id', 942100);
        $this->putJson($url, ['mode' => 'enforcing'], $this->authHeaders())->assertOk()->assertJsonPath('settings.application_profile', 'wordpress');
        $after = DB::table('web_domain')->where('domain_id', $id)->value('apache_directives');
        $this->assertStringContainsString("Header set X-Test value\r\n", $after);
        $this->assertSame(1, substr_count($after, WebWafPolicy::BEGIN));
        $this->assertCount(2, $this->datalogRows('web_domain'));
    }

    public function test_old_placeholder_messages_get_a_fallback_without_losing_new_numeric_scores(): void
    {
        $id = $this->seedVhost();
        $site = (array) DB::table('web_domain')->where('domain_id', $id)->first();
        $messages = ['Inbound Anomaly Score Exceeded (Total Score: [value])', 'Inbound anomaly score exceeded (total: 5)'];
        foreach ($messages as $message) {
            DB::table('api_web_waf_events')->insert(['event_key' => hash('sha256', $message), 'server_id' => 1, 'website_id' => $id,
                'identity' => WebWafPolicy::identity($site), 'occurred_at' => time(), 'rule_id' => 949110, 'outcome' => 'detected',
                'client_ip' => '127.0.0.1', 'method' => 'GET', 'path' => '/test', 'message' => $message, 'source' => 'owasp']);
        }
        $this->getJson('/api/v1/sites/web-domains/'.$id.'/waf/events', $this->authHeaders())->assertOk()
            ->assertJsonPath('data.0.message', 'Inbound anomaly score exceeded (total: 5)')
            ->assertJsonPath('data.1.message', 'Inbound anomaly score exceeded');
    }
}
