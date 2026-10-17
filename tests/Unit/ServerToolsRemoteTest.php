<?php

namespace IspconfigRestHosting\Tests\Unit;

use PHPUnit\Framework\TestCase;

if (! defined('ISPCP_SERVER_TOOLS_TEST')) {
    define('ISPCP_SERVER_TOOLS_TEST', true);
}
require_once dirname(__DIR__, 2).'/server-tools/remote.php';

class ServerToolsRemoteTest extends TestCase
{
    public function test_native_tables_are_read_only_and_no_global_grants_exist(): void
    {
        $tables = \ServerToolsRemote::permissions(['database', 'web-logs', 'file-manager', 'waf', 'php-limits']);
        foreach ($tables as $table => $rights) {
            $this->assertMatchesRegularExpression('/^[a-z_]+$/D', $table);
            if (! str_starts_with($table, 'api_')) {
                $this->assertSame(['SELECT'], $rights);
            }
            $this->assertSame([], array_diff($rights, ['SELECT', 'INSERT', 'UPDATE', 'DELETE']));
        }
        $this->assertSame(['SELECT', 'INSERT', 'UPDATE'], $tables['api_web_log_workers']);
        $this->assertSame(['SELECT', 'INSERT', 'UPDATE', 'DELETE'], $tables['api_web_waf_events']);
        $this->assertSame(['SELECT'], $tables['api_client_resource_limits']);
        $this->assertSame(['SELECT', 'INSERT', 'UPDATE', 'DELETE'], $tables['api_php_limits_usage']);
    }

    public function test_whmcs_addresses_accept_ipv4_and_ipv6(): void
    {
        $this->assertSame('192.0.2.10', \ServerToolsRemote::whmcsAddresses(['192.0.2.10']));
        $this->assertSame('192.0.2.10,2001:db8::10', \ServerToolsRemote::whmcsAddresses([' 192.0.2.10', '2001:0db8:0:0::10', '192.0.2.10']));
        foreach ([[], [''], ['192.0.2.10;id'], ['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4', '1.1.1.5'], [null]] as $addresses) {
            try {
                \ServerToolsRemote::whmcsAddresses($addresses);
                $this->fail('accepted '.json_encode($addresses));
            } catch (\RuntimeException $e) {
                $this->assertStringContainsString('WHMCS egress IP addresses', $e->getMessage());
            }
        }
    }

    public function test_unrecognized_component_is_rejected(): void
    {
        $this->expectException(\RuntimeException::class);
        \ServerToolsRemote::permissions(['waf;id']);
    }

    public function test_wrong_server_identity_stops_before_database_access(): void
    {
        $this->expectExceptionMessage('server ID does not match');
        \ServerToolsRemote::probe(['server_id' => 2], ['database'], 1);
    }

    public function test_grants_cannot_write_native_tables(): void
    {
        $this->expectExceptionMessage('non-worker table privilege');
        \ServerToolsRemote::grant(['db_database' => 'dbispconfig', 'db_host' => 'localhost'], [
            'database' => 'dbispconfig', 'account' => 'worker@localhost', 'missing' => ['web_domain' => ['UPDATE']],
        ]);
    }

    public function test_grants_cannot_target_another_database(): void
    {
        $this->expectExceptionMessage('master database on this host');
        \ServerToolsRemote::grant(['db_database' => 'dbispconfig', 'db_host' => 'localhost'], [
            'database' => 'mysql', 'account' => 'worker@localhost', 'missing' => ['api_web_waf_workers' => ['SELECT']],
        ]);
    }
}
