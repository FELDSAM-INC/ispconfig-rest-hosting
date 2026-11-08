<?php

namespace IspconfigRestHosting\Tests\Feature;

use App\Services\TlsCertificateProbe;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use IspconfigRestHosting\Support\DnsLookup;
use Tests\Support\SitesApiTestCase;
use Tests\Support\TenantFixtures;
use Tests\Support\TenantSchema;

final class LetsEncryptWaitApiTest extends SitesApiTestCase
{
    use TenantFixtures;

    private const SERVER = '198.51.100.10';

    private const OLD = '192.0.2.77';

    private FakeDns $dns;

    private FakeProbe $probe;

    protected function setUp(): void
    {
        parent::setUp();
        TenantSchema::create();
        $this->seedTenants();
        if (! Schema::hasColumn('server', 'updated')) {
            Schema::table('server', fn (Blueprint $table) => $table->unsignedBigInteger('updated')->default(0));
        }
        if (! Schema::hasTable('server_ip')) {
            Schema::create('server_ip', function (Blueprint $table): void {
                $table->increments('server_ip_id');
                $table->unsignedInteger('server_id');
                $table->unsignedInteger('client_id')->default(0);
                $table->string('ip_type', 4)->default('IPv4');
                $table->string('ip_address', 39);
            });
        }
        DB::table('server_ip')->insert([['server_id' => 1, 'ip_type' => 'IPv4', 'ip_address' => self::SERVER], ['server_id' => 1, 'ip_type' => 'IPv4', 'ip_address' => '10.0.0.2']]);
        DB::table('client')->where('client_id', $this->tenant('clientA')['client_id'])->update(['limit_ssl' => 'y', 'limit_ssl_letsencrypt' => 'y']);
        $this->dns = new FakeDns;
        $this->probe = new FakeProbe;
        $this->app->instance(DnsLookup::class, $this->dns);
        $this->app->instance(TlsCertificateProbe::class, $this->probe);
    }

    private function site(array $attrs = []): int
    {
        return $this->seedVhost($this->ownedBy('clientA', $attrs + ['domain' => 'example.com', 'subdomain' => 'www', 'ip_address' => '*']));
    }

    private function url(int $id): string
    {
        return '/api/v1/sites/web-domains/'.$id.'/ssl/letsencrypt-wait';
    }

    /** The scheduler's next run with every wait due. */
    private function tick(): void
    {
        DB::table('api_letsencrypt_waits')->update(['next_check_at' => 0]);
        Artisan::call('letsencrypt:wait');
    }

    /** ISPConfig processed the journal of server 1. */
    private function processed(): void
    {
        DB::table('server')->where('server_id', 1)->update(['updated' => (int) DB::table('sys_datalog')->max('datalog_id')]);
    }

    private function wait(int $id): ?object
    {
        return DB::table('api_letsencrypt_waits')->where('website_id', $id)->first();
    }

    public function test_waits_for_dns_then_enables_lets_encrypt_redirects_and_adds_www_later(): void
    {
        $id = $this->site();
        $headers = $this->tenantHeaders('clientA');
        $this->getJson($this->url($id), $headers)->assertOk()->assertJsonPath('state', 'none')->assertJsonPath('names', []);
        $this->getJson('/api/v1/sites/web-domains/'.$id, $headers)->assertOk()->assertJsonPath('letsencrypt_wait', null);

        $this->dns->set('example.com', [self::OLD]);
        $this->dns->set('www.example.com', [self::OLD]);
        $this->putJson($this->url($id), ['redirect_https' => true], $headers)->assertOk()
            ->assertJsonPath('state', 'waiting')->assertJsonPath('redirect_https', true)->assertJsonPath('expected_addresses', [self::SERVER])
            ->assertJsonPath('names.0', ['name' => 'example.com', 'required' => true, 'points' => false, 'status' => 'elsewhere', 'addresses' => [self::OLD], 'certified' => false])
            ->assertJsonPath('names.1.name', 'www.example.com')->assertJsonPath('names.1.required', false);
        $this->assertCount(0, $this->datalogRows('web_domain'));
        $this->getJson('/api/v1/sites/web-domains/'.$id, $headers)->assertJsonPath('letsencrypt_wait', 'waiting');
        $this->assertSame(['1.1.1.1', '8.8.8.8', '9.9.9.9'], $this->dns->resolvers);

        // Not due yet: nothing is asked.
        $this->dns->set('example.com', [self::SERVER]);
        $asked = $this->dns->calls;
        Artisan::call('letsencrypt:wait');
        $this->assertSame($asked, $this->dns->calls);

        $this->tick();
        $wait = $this->wait($id);
        $this->assertSame('issuing', $wait->state);
        $rows = $this->datalogRows('web_domain');
        $this->assertCount(1, $rows);
        $this->assertSame('clienta', $rows[0]->user);
        $data = unserialize($rows[0]->data);
        $this->assertSame(['y', 'y', 'n'], [$data['new']['ssl'], $data['new']['ssl_letsencrypt'], $data['new']['rewrite_to_https']]);
        $this->assertSame((int) $rows[0]->datalog_id, (int) $wait->datalog_id);

        // Not processed yet: still issuing, nothing written.
        $this->tick();
        $this->assertSame('issuing', $this->wait($id)->state);
        $this->assertCount(1, $this->datalogRows('web_domain'));

        // ISPConfig left www out; the redirect follows the certificate.
        $this->processed();
        $this->probe->names = ['example.com'];
        $this->tick();
        $this->assertSame('extending', $this->wait($id)->state);
        $this->assertSame(['web1:example.com'], $this->probe->asked);
        $rows = $this->datalogRows('web_domain');
        $this->assertCount(2, $rows);
        $this->assertSame('y', unserialize($rows[1]->data)['new']['rewrite_to_https']);
        $this->getJson($this->url($id), $headers)->assertJsonPath('names.0.certified', true)->assertJsonPath('names.1.certified', false);

        // www still elsewhere: nothing to renew.
        $this->tick();
        $this->assertCount(2, $this->datalogRows('web_domain'));

        $this->dns->set('www.example.com', [self::SERVER]);
        $this->tick();
        $this->assertSame('issuing', $this->wait($id)->state);
        $rows = $this->datalogRows('web_domain');
        $this->assertCount(3, $rows, 'renewal: a forced no-change entry');
        $this->processed();
        $this->probe->names = ['example.com', 'www.example.com'];
        $this->tick();
        $this->getJson($this->url($id), $headers)->assertJsonPath('state', 'completed')->assertJsonPath('names.1.certified', true)->assertJsonPath('next_check_at', null);
        $this->assertCount(3, $this->datalogRows('web_domain'), 'the redirect is not written twice');
    }

    public function test_a_restarted_wait_keeps_a_certificate_that_has_the_preferred_name(): void
    {
        $id = $this->site(['ssl' => 'y', 'ssl_letsencrypt' => 'y']);
        $this->probe->names = ['example.com'];
        $this->dns->set('example.com', [self::SERVER]);
        $this->dns->set('www.example.com', [self::OLD]);
        $this->putJson($this->url($id), ['redirect_https' => true], $this->tenantHeaders('clientA'))->assertOk()
            ->assertJsonPath('state', 'extending')->assertJsonPath('names.0.certified', true);
        $rows = $this->datalogRows('web_domain');
        $this->assertCount(1, $rows, 'only the redirect, no renewal');
        $this->assertSame('y', unserialize($rows[0]->data)['new']['rewrite_to_https']);
    }

    public function test_a_website_redirecting_to_www_waits_for_www(): void
    {
        $id = $this->site(['seo_redirect' => 'non_www_to_www']);
        $this->dns->set('example.com', [self::SERVER]);
        $this->dns->set('www.example.com', [self::OLD]);
        $this->putJson($this->url($id), [], $this->tenantHeaders('clientA'))->assertOk()->assertJsonPath('state', 'waiting')
            ->assertJsonPath('names.0.required', false)->assertJsonPath('names.0.points', true)->assertJsonPath('names.1.required', true);
        $this->dns->set('www.example.com', [self::SERVER]);
        $this->tick();
        $this->assertSame('issuing', $this->wait($id)->state);
    }

    public function test_a_domain_already_pointing_is_enabled_in_the_same_request(): void
    {
        $id = $this->site(['subdomain' => 'none']);
        $this->dns->set('example.com', [self::SERVER]);
        $this->putJson($this->url($id), [], $this->tenantHeaders('clientA'))->assertOk()->assertJsonPath('state', 'issuing')
            ->assertHeader('X-Change-Set-Id');
        $this->assertCount(1, $this->datalogRows('web_domain'));
    }

    public function test_addresses_must_all_belong_to_the_server_and_enough_resolvers_must_agree(): void
    {
        $id = $this->site(['subdomain' => 'none']);
        $headers = $this->tenantHeaders('clientA');
        foreach ([
            'IPv6 elsewhere' => [[self::SERVER], ['2001:db8::1'], [], 'elsewhere'],
            'second address elsewhere' => [[self::SERVER, self::OLD], [], [], 'elsewhere'],
            'one resolver disagrees' => [[self::SERVER], [], ['9.9.9.9' => [self::OLD]], 'elsewhere'],
            'no records' => [[], [], [], 'unresolved'],
            'two resolvers silent' => [[self::SERVER], [], ['8.8.8.8' => 'timeout', '9.9.9.9' => 'servfail'], 'unknown'],
        ] as $case => [$a, $aaaa, $overrides, $status]) {
            $this->dns->set('example.com', $a, $aaaa, $overrides);
            $this->putJson($this->url($id), [], $headers)->assertOk()->assertJsonPath('state', 'waiting', $case)->assertJsonPath('names.0.status', $status);
        }
        // One silent resolver of three is enough with the other two agreeing.
        $this->dns->set('example.com', [self::SERVER], [], ['9.9.9.9' => 'timeout']);
        $this->putJson($this->url($id), [], $headers)->assertOk()->assertJsonPath('state', 'issuing');
    }

    public function test_the_websites_own_address_and_configured_server_addresses_are_expected(): void
    {
        $id = $this->site(['subdomain' => 'none', 'ip_address' => '198.51.100.20']);
        $this->dns->set('example.com', [self::SERVER]);
        $this->putJson($this->url($id), [], $this->tenantHeaders('clientA'))->assertJsonPath('expected_addresses', ['198.51.100.20'])->assertJsonPath('state', 'waiting');

        config(['letsencrypt_wait.server_addresses' => ['1' => ['203.0.113.5', '2001:db8::5', '10.1.1.1']]]);
        $other = $this->site(['domain' => 'other.example', 'subdomain' => 'none']);
        $this->putJson($this->url($other), [], $this->tenantHeaders('clientA'))->assertJsonPath('expected_addresses', ['203.0.113.5', '2001:db8::5']);

        config(['letsencrypt_wait.server_addresses' => ['1' => ['10.1.1.1']]]);
        $this->putJson($this->url($other), [], $this->tenantHeaders('clientA'))->assertConflict();
    }

    public function test_failed_issuance_is_retried_then_given_up(): void
    {
        $id = $this->site(['subdomain' => 'none']);
        $this->dns->set('example.com', [self::SERVER]);
        $this->putJson($this->url($id), [], $this->tenantHeaders('clientA'))->assertJsonPath('state', 'issuing');
        for ($attempt = 1; $attempt <= 5; $attempt++) {
            // ISPConfig could not verify the domain and switched Let's Encrypt off without a journal entry.
            $this->processed();
            DB::table('web_domain')->where('domain_id', $id)->update(['ssl' => 'n', 'ssl_letsencrypt' => 'n']);
            $this->tick();
            $wait = $this->wait($id);
            $this->assertSame($attempt, (int) $wait->failures);
            $this->assertSame('issuance_failed', $wait->reason);
            if ($attempt < 5) {
                $this->assertSame('waiting', $wait->state);
                $this->assertGreaterThan(time() + 800, (int) $wait->next_check_at);
                $this->tick();
                $this->assertSame('issuing', $this->wait($id)->state);
            }
        }
        $this->assertSame('failed', $this->wait($id)->state);
        $this->assertCount(5, $this->datalogRows('web_domain'));
    }

    public function test_an_unprocessed_request_counts_as_a_failure_after_the_timeout(): void
    {
        $id = $this->site(['subdomain' => 'none']);
        $this->dns->set('example.com', [self::SERVER]);
        $this->putJson($this->url($id), [], $this->tenantHeaders('clientA'));
        DB::table('api_letsencrypt_waits')->update(['issuing_since' => time() - 1801]);
        $this->tick();
        $this->assertSame(['waiting', 'stalled'], [$this->wait($id)->state, $this->wait($id)->reason]);
    }

    public function test_the_wait_expires(): void
    {
        $id = $this->site();
        $this->dns->set('example.com', [self::OLD]);
        $this->putJson($this->url($id), [], $this->tenantHeaders('clientA'));
        DB::table('api_letsencrypt_waits')->update(['expires_at' => time() - 1]);
        $this->tick();
        $this->getJson($this->url($id), $this->tenantHeaders('clientA'))->assertJsonPath('state', 'expired')->assertJsonPath('reason', 'not_pointing');
        $this->assertCount(0, $this->datalogRows('web_domain'));
    }

    public function test_manual_ssl_changes_renames_and_deletion_end_the_wait(): void
    {
        $headers = $this->tenantHeaders('clientA');
        $this->dns->set('example.com', [self::OLD]);
        $id = $this->site();
        $this->putJson($this->url($id), [], $headers)->assertOk();
        // Other settings keep it.
        $this->putJson('/api/v1/sites/web-domains/'.$id, ['php' => 'php-fpm'], $headers)->assertOk();
        $this->assertNotNull($this->wait($id));
        $this->putJson('/api/v1/sites/web-domains/'.$id, ['ssl' => true], $headers)->assertOk();
        $this->assertNull($this->wait($id));

        $this->putJson($this->url($id), [], $headers)->assertOk();
        DB::table('web_domain')->where('domain_id', $id)->update(['domain' => 'renamed.example']);
        $this->tick();
        $this->assertNull($this->wait($id));

        $this->putJson($this->url($id), [], $headers)->assertOk();
        $this->deleteJson($this->url($id), [], $headers)->assertNoContent();
        $this->assertNull($this->wait($id));
        $this->putJson($this->url($id), [], $headers)->assertOk();
        $this->deleteJson('/api/v1/sites/web-domains/'.$id, [], $headers)->assertSuccessful();
        $this->assertNull($this->wait($id));
    }

    public function test_permissions_plan_and_account_state(): void
    {
        $id = $this->site();
        $this->dns->set('example.com', [self::OLD]);
        $this->getJson($this->url($id), $this->tenantHeaders('clientB'))->assertNotFound();
        $this->putJson($this->url($id), [], $this->tenantHeaders('clientB'))->assertNotFound();
        $this->deleteJson($this->url($id), [], $this->tenantHeaders('clientB'))->assertNotFound();
        $this->putJson($this->url($id))->assertUnauthorized();
        $this->putJson($this->url($id), ['redirect_https' => 'yes'], $this->tenantHeaders('clientA'))->assertUnprocessable();

        $client = $this->tenant('clientA')['client_id'];
        DB::table('client')->where('client_id', $client)->update(['limit_ssl_letsencrypt' => 'n']);
        $this->putJson($this->url($id), [], $this->tenantHeaders('clientA'))->assertForbidden();
        DB::table('client')->where('client_id', $client)->update(['limit_ssl_letsencrypt' => 'y', 'locked' => 'y']);
        $this->putJson($this->url($id), [], $this->tenantHeaders('clientA'))->assertForbidden();
        $this->deleteJson($this->url($id), [], $this->tenantHeaders('clientA'))->assertForbidden();
        DB::table('client')->where('client_id', $client)->update(['locked' => 'n']);

        // The plan is checked again when the request is made.
        $this->putJson($this->url($id), [], $this->tenantHeaders('clientA'))->assertOk();
        DB::table('client')->where('client_id', $client)->update(['limit_ssl_letsencrypt' => 'n']);
        $this->dns->set('example.com', [self::SERVER]);
        $this->tick();
        $this->assertSame(['failed', 'not_in_plan'], [$this->wait($id)->state, $this->wait($id)->reason]);
        $this->assertCount(0, $this->datalogRows('web_domain'));

        DB::table('web_domain')->where('domain_id', $id)->update(['active' => 'n']);
        $this->putJson($this->url($id), [], $this->authHeaders())->assertConflict();
        $alias = $this->site(['domain' => 'alias.example', 'type' => 'alias', 'parent_domain_id' => $id]);
        $this->putJson($this->url($alias), [], $this->authHeaders())->assertNotFound();
    }

    public function test_the_api_scheduler_runs_the_waits_every_minute(): void
    {
        $events = array_values(array_filter(app(Schedule::class)->events(), fn ($event) => str_contains((string) $event->command, 'letsencrypt:wait')));
        $this->assertCount(1, $events);
        $this->assertSame('* * * * *', $events[0]->expression);
        $this->assertTrue($events[0]->withoutOverlapping);
    }

    public function test_names_follow_ispconfig_subdomains_aliases_and_exclusions(): void
    {
        $id = $this->site();
        foreach ([['shop.example.com', 'subdomain', 'none', 'n'], ['alias.example', 'alias', 'www', 'n'], ['skip.example', 'alias', 'none', 'y'], ['off.example', 'alias', 'none', 'n', 'n']] as $row) {
            $this->site(['domain' => $row[0], 'type' => $row[1], 'subdomain' => $row[2], 'ssl_letsencrypt_exclude' => $row[3], 'active' => $row[4] ?? 'y', 'parent_domain_id' => $id]);
        }
        $this->dns->set('example.com', [self::OLD]);
        $this->putJson($this->url($id), [], $this->tenantHeaders('clientA'))->assertOk()
            ->assertJsonPath('names.*.name', ['example.com', 'www.example.com', 'shop.example.com', 'alias.example', 'www.alias.example']);
    }
}

/** Answers from a table: name => [A, AAAA], with per-resolver overrides of A. */
final class FakeDns extends DnsLookup
{
    public array $records = [];

    public array $resolvers = [];

    public int $calls = 0;

    public function set(string $name, array $a, array $aaaa = [], array $overrides = []): void
    {
        $this->records[$name] = [$a, $aaaa, $overrides];
    }

    public function lookup(array $names, array $resolvers, float $timeout = 2.5): array
    {
        $this->calls++;
        $this->resolvers = $resolvers;
        $result = [];
        foreach ($resolvers as $resolver) {
            foreach ($names as $name) {
                [$a, $aaaa, $overrides] = $this->records[$name] ?? ['nxdomain', 'nxdomain', []];
                $a = $overrides[$resolver] ?? $a;
                $result[$resolver][$name] = ['A' => $a, 'AAAA' => is_string($a) ? $a : $aaaa];
            }
        }

        return $result;
    }
}

/** The certificate the web server presents: self-signed with the given names. */
final class FakeProbe extends TlsCertificateProbe
{
    public array $names = [];

    public array $asked = [];

    public function fetch(string $host, string $serverName, int $port = 443, float $timeout = 3.0): ?string
    {
        $this->asked[] = $host.':'.$serverName;
        if ($this->names === []) {
            return null;
        }
        $config = tempnam(sys_get_temp_dir(), 'san');
        file_put_contents($config, "[req]\ndistinguished_name=dn\n[dn]\n[san]\nsubjectAltName=".implode(',', array_map(fn ($n) => 'DNS:'.$n, $this->names))."\n");
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $options = ['config' => $config, 'digest_alg' => 'sha256', 'x509_extensions' => 'san', 'req_extensions' => 'san'];
        $csr = openssl_csr_new(['commonName' => $this->names[0]], $key, $options);
        openssl_x509_export(openssl_csr_sign($csr, null, $key, 90, $options), $pem);
        unlink($config);

        return $pem;
    }
}
