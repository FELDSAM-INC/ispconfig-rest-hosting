<?php

namespace IspconfigRestHosting\Tests\Feature;

use Illuminate\Support\Facades\DB;
use IspconfigRestHosting\Support\CronOutputLog;
use Tests\Support\SitesApiTestCase;

/** Scheduled tasks' own output logs (spec 054) on core's /sites/cron-jobs. */
class CronOutputLogApiTest extends SitesApiTestCase
{
    protected function seedCronJob(int $parentId, array $overrides = []): int
    {
        return (int) DB::table('cron')->insertGetId(array_merge([
            'sys_userid' => 1,
            'sys_groupid' => 5,
            'sys_perm_user' => 'riud',
            'sys_perm_group' => 'riud',
            'sys_perm_other' => '',
            'server_id' => 1,
            'parent_domain_id' => $parentId,
            'type' => 'url',
            'command' => 'https://example.com/cron.php',
            'run_min' => '*/5',
            'run_hour' => '*',
            'run_mday' => '*',
            'run_month' => '*',
            'run_wday' => '*',
            'log' => 'n',
            'active' => 'y',
        ], $overrides), 'id');
    }

    /**
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    protected function validPayload(int $parentId, array $overrides = []): array
    {
        return array_merge([
            'parent_domain_id' => $parentId,
            'run_min' => '*/5',
            'run_hour' => '*',
            'run_mday' => '*',
            'run_month' => '*',
            'run_wday' => '*',
            'command' => 'https://example.com/cron.php',
        ], $overrides);
    }

    public function test_output_log_wraps_only_the_native_command(): void
    {
        $chrooted = $this->seedVhost(['sys_groupid' => 5]);
        $root = DB::table('web_domain')->where('domain_id', $chrooted)->value('document_root');
        $id = $this->postJson('/api/v1/sites/cron-jobs', $this->validPayload($chrooted, [
            'command' => $root.'/web/cron.php # nightly', 'output_log' => true, 'log' => true,
        ]), $this->authHeaders())->assertCreated()
            ->assertJsonPath('type', 'chrooted')->assertJsonPath('output_log', true)->assertJsonPath('log', false)
            // ISPConfig drops a chrooted task's leading document root; behind the prefix the API does it
            ->assertJsonPath('command', '/web/cron.php # nightly')->json('id');
        $native = DB::table('cron')->where('id', $id)->value('command');
        $this->assertMatchesRegularExpression("~\\Acommand exec >>'/private/\\.ispcp-cron-[a-f0-9]{32}\\.log' 2>&1; .*; /web/cron\\.php # nightly\\z~", $native);
        $rows = $this->datalogRows('cron');
        $this->assertStringContainsString('command exec >>', end($rows)->data, 'ISPConfig receives the prefixed command');
        $token = CronOutputLog::parse($native)['token'];

        // Edits keep the task's file; the list shows and searches the task's own command
        $this->putJson('/api/v1/sites/cron-jobs/'.$id, ['command' => '/web/other.php'], $this->authHeaders())->assertOk()
            ->assertJsonPath('command', '/web/other.php')->assertJsonPath('output_log', true);
        $this->putJson('/api/v1/sites/cron-jobs/'.$id, ['run_min' => '0'], $this->authHeaders())->assertOk()->assertJsonPath('command', '/web/other.php');
        $this->assertSame(['token' => $token, 'command' => '/web/other.php'], array_intersect_key(CronOutputLog::parse(DB::table('cron')->where('id', $id)->value('command')), ['token' => 1, 'command' => 1]));
        $this->getJson('/api/v1/sites/cron-jobs?search=other.php', $this->authHeaders())->assertOk()->assertJsonPath('data.0.command', '/web/other.php');

        $this->putJson('/api/v1/sites/cron-jobs/'.$id, ['output_log' => false], $this->authHeaders())->assertOk()->assertJsonPath('output_log', false);
        $this->assertSame('/web/other.php', DB::table('cron')->where('id', $id)->value('command'));

        // Full tasks write into the document root's private directory; URL tasks keep ISPConfig's wget line
        $full = $this->seedVhost(['sys_groupid' => 6]);
        $fullId = $this->postJson('/api/v1/sites/cron-jobs', $this->validPayload($full, ['command' => '/usr/bin/php script.php', 'output_log' => true]), $this->authHeaders())
            ->assertCreated()->assertJsonPath('type', 'full')->json('id');
        $this->assertStringStartsWith("command exec >>'".DB::table('web_domain')->where('domain_id', $full)->value('document_root').'/private/.ispcp-cron-', DB::table('cron')->where('id', $fullId)->value('command'));
        $this->postJson('/api/v1/sites/cron-jobs', $this->validPayload($full, ['output_log' => true]), $this->authHeaders())
            ->assertCreated()->assertJsonPath('type', 'url')->assertJsonPath('output_log', false)->assertJsonPath('command', 'https://example.com/cron.php');
    }

    public function test_output_log_is_read_through_the_web_log_worker(): void
    {
        $site = $this->seedVhost(['sys_groupid' => 6]);
        $root = DB::table('web_domain')->where('domain_id', $site)->value('document_root');
        $plain = $this->seedCronJob($site, ['type' => 'full', 'command' => '/usr/bin/php x.php']);
        $this->getJson('/api/v1/sites/cron-jobs/'.$plain.'/log', $this->authHeaders())->assertOk()->assertJsonPath('state', 'disabled');

        $logged = $this->seedCronJob($site, ['type' => 'full', 'command' => CronOutputLog::wrap('/usr/bin/php x.php', str_repeat('a', 32), 'full', $root)]);
        $url = '/api/v1/sites/cron-jobs/'.$logged.'/log?lines=50';
        $this->getJson($url, $this->authHeaders())->assertOk()->assertJsonPath('state', 'unavailable');
        DB::table('api_web_log_workers')->insert(['server_id' => 1, 'heartbeat' => time()]);
        $this->getJson($url, $this->authHeaders())->assertOk()->assertJsonPath('state', 'pending')->assertHeader('Cache-Control', 'no-store, private');
        $this->assertSame(['kind' => 'cron', 'cron_id' => $logged, 'lines' => 50], json_decode(DB::table('api_web_log_reads')->value('request'), true));
        DB::table('api_web_log_reads')->update(['result' => json_encode(['lines' => ['=== Fri Oct  2 08:00:01 UTC 2026 ===', 'hello', '=== exit 0 ==='], 'size' => 64, 'modified_at' => 1790000000, 'truncated' => false])]);
        $this->getJson($url, $this->authHeaders())->assertOk()->assertJson(['state' => 'ready', 'lines' => ['=== Fri Oct  2 08:00:01 UTC 2026 ===', 'hello', '=== exit 0 ==='],
            'size' => 64, 'modified_at' => gmdate('c', 1790000000), 'truncated' => false]);
        $this->getJson('/api/v1/sites/cron-jobs/'.$logged.'/log?lines=0', $this->authHeaders())->assertStatus(422);

        // A WordPress cron takeover task shows the WordPress worker's wp-cron.log through the same read
        $wordpress = $this->seedCronJob($site, ['type' => 'full', 'command' => ": > '".$root."/private/.ispcp-wp-cron-7a86e429-b416-4e20-b7d3-b33580d81a38'"]);
        DB::table('api_wordpress_cron')->insert(['id' => '7a86e429-b416-4e20-b7d3-b33580d81a38', 'website_id' => $site, 'server_id' => 1, 'installation' => str_repeat('b', 32),
            'identity' => 'x', 'path' => '', 'cron_id' => $wordpress, 'state' => 'active']);
        $this->getJson('/api/v1/sites/cron-jobs/'.$wordpress.'/log', $this->authHeaders())->assertOk()->assertJsonPath('state', 'pending');
        $this->assertSame(['kind' => 'cron', 'cron_id' => $wordpress, 'lines' => 200], json_decode(DB::table('api_web_log_reads')->where('request', 'like', '%"cron_id":'.$wordpress.'%')->value('request'), true));
    }
}
