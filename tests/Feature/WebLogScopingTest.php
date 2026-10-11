<?php

namespace IspconfigRestHosting\Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\Support\SitesSchema;
use Tests\Support\TenantFixtures;
use Tests\Support\TenantSchema;
use Tests\TestCase;

/** Website logs follow core's tenant scoping (spec 011): another tenant's website is 404 and queues nothing. */
class WebLogScopingTest extends TestCase
{
    use RefreshDatabase;
    use TenantFixtures;

    public function test_web_logs_never_queue_reads_for_another_tenant(): void
    {
        SitesSchema::create();
        TenantSchema::create();
        $this->seedTenants();
        DB::table('server')->insert(['server_id' => 1, 'server_name' => 'web1', 'web_server' => 1, 'mirror_server_id' => 0, 'active' => 1]);
        $foreign = (int) DB::table('web_domain')->insertGetId($this->ownedBy('clientB', [
            'server_id' => 1, 'domain' => 'b-site.test', 'type' => 'vhost', 'active' => 'y',
        ]), 'domain_id');
        DB::table('api_web_log_workers')->insert(['server_id' => 1, 'heartbeat' => time()]);

        $this->getJson('/api/v1/sites/web-domains/'.$foreign.'/logs/access', $this->tenantHeaders('clientA'))->assertNotFound();
        $this->assertDatabaseCount('api_web_log_reads', 0);
    }
}
