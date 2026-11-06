<?php

namespace IspconfigRestHosting\Tests\Feature;

use Illuminate\Support\Facades\DB;
use Symfony\Component\Process\Process;
use Tests\Support\UsageApiTestCase;

/** Exercises the migration quota calculation against actual API responses and enforcement. */
class MigrationProvisioningTest extends UsageApiTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->assignServers('clientB', ['web' => [1], 'db' => [1]]);
        $this->setClientLimit('clientB', 'limit_web_domain', 1);
        $this->setClientLimit('clientB', 'limit_web_quota', 5120);
        DB::table('client')->where('client_id', $this->tenant('clientB')['client_id'])->update(['canceled' => 'y']);
        DB::table('sys_user')->where('userid', $this->tenant('clientB')['userid'])->update(['active' => 0]);
        DB::table('server')->where('server_id', 1)->update(['config' => implode("\n", [
            '[web]', 'server_type=apache', 'website_path=/var/www/clients/client[client_id]/web[website_id]',
            'php_open_basedir=[website_path]/web:[website_path]/tmp', 'htaccess_allow_override=All',
            'enable_sni=y', 'php_fpm_default_chroot=n', '[server]', 'ip_address=10.0.0.1',
        ])]);
        DB::table('sys_ini')->insert(['sysini_id' => 1, 'config' => "[sites]\ndefault_remote_dbserver=\n"]);
    }

    private function migrationQuota(): int
    {
        $clientId = $this->tenant('clientB')['client_id'];
        $summary = $this->getJson('/api/v1/usage/summary?client_id='.$clientId, $this->tenantHeaders('admin'))->assertOk()->json();
        $code = <<<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location('migration', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(module.available_disk_mb(json.load(sys.stdin), int(sys.argv[2])))
PY;
        $process = new Process(['python3', '-c', $code, dirname(__DIR__, 2).'/site-migration/migrate.py', (string) $clientId]);
        $process->setInput(json_encode($summary, JSON_THROW_ON_ERROR));
        $process->mustRun();

        return (int) trim($process->getOutput());
    }

    private function payload(int $quota): array
    {
        return [
            'domain' => 'migration.test', 'type' => 'vhost', 'client_id' => $this->tenant('clientB')['client_id'],
            'server_id' => 1, 'ip_address' => '*', 'php' => 'php-fpm', 'active' => true,
            'subdomain' => 'www', 'ssl' => false, 'ssl_letsencrypt' => false, 'rewrite_to_https' => false,
            'hd_quota' => $quota, 'traffic_quota' => -1,
        ];
    }

    public function test_client_key_rejects_legacy_10_gb_and_accepts_calculated_5_gb_with_panel_login_disabled(): void
    {
        $clientId = $this->tenant('clientB')['client_id'];
        $key = $this->postJson('/api/v1/system/api-keys', ['name' => 'migration-test', 'client_id' => $clientId],
            $this->tenantHeaders('admin'))->assertCreated()->json('key');
        $headers = ['X-API-Key' => $key];
        $this->postJson('/api/v1/sites/web-domains', $this->payload(10240), $headers)->assertForbidden()
            ->assertJsonPath('limit.name', 'limit_web_quota')->assertJsonPath('limit.max', 5120);
        $this->assertSame(0, DB::table('web_domain')->count());
        $quota = $this->migrationQuota();
        $this->assertSame(5120, $quota);
        $this->postJson('/api/v1/sites/web-domains', $this->payload($quota), $headers)->assertCreated()
            ->assertJsonPath('hd_quota', 5120)->assertJsonPath('system_group', 'client'.$clientId);
        $this->assertGreaterThan(0, DB::table('sys_datalog')->where('dbtable', 'web_domain')->count());
    }

    public function test_existing_website_allocation_reduces_the_new_website_quota(): void
    {
        $this->setClientLimit('clientB', 'limit_web_domain', 2);
        $this->site('clientB', 'existing.test', ['hd_quota' => 1024]);
        $quota = $this->migrationQuota();
        $this->assertSame(4096, $quota);
        $this->postJson('/api/v1/sites/web-domains', $this->payload($quota), $this->tenantHeaders('clientB'))->assertCreated()
            ->assertJsonPath('hd_quota', 4096);
    }
}
