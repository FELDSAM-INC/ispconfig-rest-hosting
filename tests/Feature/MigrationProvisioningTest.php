<?php

namespace IspconfigRestHosting\Tests\Feature;

use Illuminate\Support\Facades\DB;
use Symfony\Component\Process\Process;
use Tests\Support\UsageApiTestCase;

/**
 * Exercises the migration's provisioning against the actual API controllers, client keys and limit
 * enforcement: tests/Migration/api_bridge.py runs the shipped Migration.preflight()/provision() and
 * this test answers each of its REST calls through the Laravel kernel.
 */
class MigrationProvisioningTest extends UsageApiTestCase
{
    private const MB = 1048576;

    protected function setUp(): void
    {
        parent::setUp();
        $this->assignServers('clientB', ['web' => [1], 'db' => [1]]);
        // Production client 6 (vestkyn1): 1 website, 5 GB disk, 1 GB databases, unlimited traffic.
        $this->setClientLimit('clientB', 'limit_web_domain', 1);
        $this->setClientLimit('clientB', 'limit_web_quota', 5120);
        $this->setClientLimit('clientB', 'limit_database_quota', 1024);
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

    /**
     * Source inventory as produced by source-inventory.php (string columns), here migrated-shop.test.
     *
     * @param  array<string, int>  $databases  name => source size in bytes
     */
    private function migration(array $databases, array $extra = []): array
    {
        $rows = [];
        $id = 10;
        foreach (array_keys($databases) as $name) {
            $rows[] = ['database_id' => (string) $id++, 'server_id' => '2', 'database_name' => $name,
                'database_charset' => 'utf8', 'type' => 'mysql', 'active' => 'y', 'database_user' => $name];
        }

        return $extra + [
            'domain' => 'migrated-shop.test',
            'client_id' => $this->tenant('clientB')['client_id'],
            'config' => [
                'source' => ['panel_ssh' => 'root@old-web.example.net', 'web_ssh' => 'root@old-web.example.net',
                    'db_via_web' => ['host' => 'old-db.example.net', 'port' => 3306]],
                'target' => ['api_url' => 'https://panel.test:8090/api/v1', 'api_key_file' => '/unused',
                    'web_ssh' => 'root@web0.target.test', 'web_transport' => 'local', 'web_server_id' => 1,
                    'db_ssh' => 'root@db0.target.test', 'db_server_id' => 1, 'db_host' => 'db0.target.test',
                    'db_remote_ips' => '10.20.30.21,10.20.30.20', 'hd_quota_mb' => 10240, 'traffic_quota_mb' => -1],
            ],
            'inventory' => [
                'site' => ['domain_id' => '194', 'server_id' => '1', 'domain' => 'migrated-shop.test', 'type' => 'vhost',
                    'document_root' => '/var/www/clients/client57/web194', 'system_user' => 'web194',
                    'system_group' => 'client57', 'php' => 'fast-cgi', 'server_php_id' => '0', 'subdomain' => 'www',
                    'hd_quota' => '-1', 'traffic_quota' => '-1', 'active' => 'y'],
                'databases' => $rows,
                'children' => [['domain_id' => '195', 'domain' => 'migrated-alias.test', 'type' => 'alias',
                    'subdomain' => 'www', 'redirect_type' => '', 'redirect_path' => '', 'active' => 'y']],
                'servers' => [],
            ],
            'source_size' => ['web_bytes' => 800 * self::MB, 'databases' => $databases],
        ];
    }

    /**
     * Runs the bridge and answers its REST calls with the real API.
     *
     * @return array{0: array<string, mixed>, 1: array<int, array<string, mixed>>}
     */
    private function runMigration(array $request): array
    {
        $log = tempnam(sys_get_temp_dir(), 'migration-bridge-');
        $process = proc_open(['python3', dirname(__DIR__).'/Migration/api_bridge.py'],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', $log, 'a']], $pipes);
        $this->assertIsResource($process);
        fwrite($pipes[0], json_encode($request, JSON_THROW_ON_ERROR)."\n");
        fflush($pipes[0]);
        $calls = [];
        $result = null;
        while (($line = fgets($pipes[1])) !== false) {
            $message = json_decode($line, true, 512, JSON_THROW_ON_ERROR);
            if (array_key_exists('done', $message)) {
                $result = $message['done'];
                break;
            }
            $headers = $message['key'] === null ? $this->tenantHeaders('admin') : ['X-API-Key' => $message['key']];
            $response = $this->json($message['method'], '/api/v1'.$message['path'], $message['payload'] ?? [], $headers);
            $calls[] = $message + ['status' => $response->status()];
            fwrite($pipes[0], json_encode(['status' => $response->status(), 'body' => $response->json()], JSON_THROW_ON_ERROR)."\n");
            fflush($pipes[0]);
        }
        fclose($pipes[0]);
        fclose($pipes[1]);
        $exit = proc_close($process);
        $stderr = (string) file_get_contents($log);
        unlink($log);
        $this->assertSame(0, $exit, $stderr);
        $this->assertIsArray($result, $stderr);

        return [$result, $calls];
    }

    private function writes(array $calls): array
    {
        return array_values(array_map(fn (array $call): string => $call['method'].' '.$call['path'].' '.$call['status'],
            array_filter($calls, fn (array $call): bool => $call['method'] !== 'GET')));
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

    public function test_production_database_quota_failure_resumes_and_creates_the_database(): void
    {
        // hosting 1.2.3 omitted database_quota: the API treats that as unlimited and refuses it.
        [$failed, $calls] = $this->runMigration($this->migration(['c57shop' => 40 * self::MB], ['legacy_database_payload' => true]));
        $this->assertFalse($failed['ok']);
        $this->assertSame('REST POST /sites/databases returned HTTP 403: quota-exceeded: limit_database_quota (client); max=1024; used=0; requested=unlimited', $failed['error']);
        $this->assertSame(1, DB::table('web_domain')->where('type', 'vhost')->count());
        $this->assertSame(1, DB::table('web_database_user')->count());
        $this->assertSame(0, DB::table('web_database')->count());
        $this->assertArrayNotHasKey('db:c57shop', $failed['state']['objects']);
        $this->assertFalse((bool) DB::table('api_keys')->where('name', 'like', 'migration-%')->value('active'));

        // Retrying with this release reuses the website, alias and user and creates the database.
        [$result, $calls] = $this->runMigration($this->migration(['c57shop' => 40 * self::MB], ['state' => $failed['state']]));
        $this->assertTrue($result['ok'], $result['error'] ?? '');
        $this->assertSame([
            'PUT /system/api-keys/'.$result['state']['client_key']['id'].' 200',
            'POST /sites/databases 201',
            'PUT /system/api-keys/'.$result['state']['client_key']['id'].' 200',
        ], $this->writes($calls));
        $this->assertSame(1024, (int) DB::table('web_database')->value('database_quota'));
        $this->assertSame(1, DB::table('web_domain')->where('type', 'vhost')->count());
        $this->assertSame(1, DB::table('web_domain')->where('type', 'alias')->count());
        $this->assertSame(1024, $result['state']['quotas']['databases_mb']['c57shop']);
        $this->assertNotEmpty($result['state']['databases']['c57shop']['name']);
        $this->assertFalse((bool) DB::table('api_keys')->where('name', 'like', 'migration-%')->value('active'));
    }

    public function test_full_provisioning_follows_every_client_quota(): void
    {
        $this->setClientLimit('clientB', 'limit_traffic_quota', 20480);
        $this->setClientLimit('clientB', 'limit_database', 2);
        $this->setClientLimit('clientB', 'limit_database_user', 2);
        $this->setClientLimit('clientB', 'limit_web_aliasdomain', 1);
        [$result, $calls] = $this->runMigration($this->migration(['app' => 100 * self::MB, 'shop' => 300 * self::MB]));
        $this->assertTrue($result['ok'], $result['error'] ?? '');
        $site = DB::table('web_domain')->where('type', 'vhost')->first();
        $this->assertSame([5120, 20480], [(int) $site->hd_quota, (int) $site->traffic_quota]);
        $this->assertSame('migrated-alias.test', DB::table('web_domain')->where('type', 'alias')->value('domain'));
        // 1024 MB split by source size 100:300.
        $this->assertSame([256, 768], DB::table('web_database')->orderBy('database_id')->pluck('database_quota')->map(fn ($v) => (int) $v)->all());
        $this->assertSame(['app' => 256, 'shop' => 768], $result['state']['quotas']['databases_mb']);
        foreach ($calls as $call) {
            if ($call['method'] === 'POST' && $call['path'] !== '/system/api-keys') {
                $this->assertNotNull($call['key'], 'Resources are created with the client-bound key');
            }
        }
    }

    public function test_unlimited_client_quotas_create_unlimited_objects(): void
    {
        $this->setClientLimit('clientB', 'limit_web_quota', -1);
        $this->setClientLimit('clientB', 'limit_database_quota', -1);
        [$result] = $this->runMigration($this->migration(['c57shop' => 40 * self::MB]));
        $this->assertTrue($result['ok'], $result['error'] ?? '');
        $this->assertSame(-1, (int) DB::table('web_domain')->where('type', 'vhost')->value('hd_quota'));
        $this->assertSame(-1, (int) DB::table('web_database')->value('database_quota'));
    }

    private function phpVersions(): array
    {
        $ids = [];
        foreach ([['PHP 5.6', '5.6', 'y', 0], ['PHP 8.3', '8.3', 'y', 0], ['PHP 7.4', '7.4', 'n', 0], ['PHP 8.1', '8.1', 'y', 999]] as [$name, $version, $active, $client]) {
            $ids[$version] = (int) DB::table('server_php')->insertGetId([
                'server_id' => 1, 'client_id' => $client, 'name' => $name, 'active' => $active,
                'php_fpm_init_script' => 'php'.$version.'-fpm', 'php_fpm_ini_dir' => '/etc/php/'.$version.'/fpm',
                'php_fpm_pool_dir' => '/etc/php/'.$version.'/fpm/pool.d', 'php_fpm_socket_dir' => '/run/php',
                'php_cli_binary' => '/usr/bin/php'.$version,
            ], 'server_php_id');
        }

        return $ids;
    }

    public function test_php_option_selects_the_destination_servers_php_version(): void
    {
        $ids = $this->phpVersions();
        [$result, $calls] = $this->runMigration($this->migration(['c57shop' => 40 * self::MB], ['php' => '5.6']));
        $this->assertTrue($result['ok'], $result['error'] ?? '');
        $this->assertSame(['version' => '5.6', 'server_php_id' => $ids['5.6']], $result['state']['php']);
        $this->assertSame($ids['5.6'], (int) DB::table('web_domain')->where('type', 'vhost')->value('server_php_id'));
        $this->assertSame('php-fpm', DB::table('web_domain')->where('type', 'vhost')->value('php'));

        // Inactive, other clients' and unknown versions stop before any write and name the usable ones.
        foreach (['7.4', '8.1', '9.9'] as $version) {
            DB::table('web_domain')->delete();
            [$refused, $calls] = $this->runMigration($this->migration(['c57shop' => 40 * self::MB], ['php' => $version]));
            $this->assertFalse($refused['ok'], $version);
            $this->assertSame('PHP '.$version.' is not an active PHP-FPM version of the destination web server for this client (available: PHP 5.6, PHP 8.3)', $refused['error']);
            $this->assertSame([], $this->writes($calls), $version);
        }
    }

    public function test_limits_that_cannot_fit_the_migration_stop_before_any_write(): void
    {
        $cases = [
            'database count' => [fn () => $this->setClientLimit('clientB', 'limit_database', 1), ['a' => self::MB, 'b' => self::MB], 'Client limit for databases is too small: limit 1, used 0, migration needs 2 more.'],
            'alias count' => [fn () => $this->setClientLimit('clientB', 'limit_web_aliasdomain', 0), ['a' => self::MB], 'Client limit for alias domains is too small: limit 0, used 0, migration needs 1 more.'],
            'database size' => [fn () => null, ['a' => 2000 * self::MB], 'Database quota is too small: 1024 MB unallocated, the source database(s) need 2000 MB (a 2000 MB).'],
            'website size' => [fn () => $this->setClientLimit('clientB', 'limit_web_quota', 512), ['a' => self::MB], 'Source files (800 MB) exceed the website disk quota (512 MB).'],
        ];
        foreach ($cases as $name => [$limit, $databases, $message]) {
            $limit();
            [$result, $calls] = $this->runMigration($this->migration($databases));
            $this->assertFalse($result['ok'], $name);
            $this->assertStringStartsWith($message, $result['error'], $name);
            $this->assertSame([], $this->writes($calls), $name);
            $this->assertSame(0, DB::table('web_domain')->count(), $name);
            $this->setClientLimit('clientB', 'limit_database', -1);
            $this->setClientLimit('clientB', 'limit_web_aliasdomain', -1);
            $this->setClientLimit('clientB', 'limit_web_quota', 5120);
        }
    }
}
