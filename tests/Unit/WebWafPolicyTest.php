<?php

namespace IspconfigRestHosting\Tests\Unit;

use IspconfigRestHosting\Support\WebWafPolicy;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class WebWafPolicyTest extends TestCase
{
    private const IDENTITY = '1-0123456789abcdef01234567';

    public function test_exact_paths_prefixes_and_whole_site_exceptions_compile_to_their_rules(): void
    {
        $rules = WebWafPolicy::rules(['enabled' => true, 'exclusions' => [
            ['rule_id' => 942100, 'path' => '/admin/pages/edit/*', 'parameter' => 'content'],
            ['rule_id' => 942200, 'path' => '/admin/pages/edit/102'],
            ['rule_id' => 942300, 'path' => '/*'],
            ['rule_id' => 942400],
        ]], self::IDENTITY);

        $this->assertStringContainsString('SecRule REQUEST_FILENAME "@beginsWith /admin/pages/edit/" "id:20000,phase:1,pass,t:none,t:urlDecodeUni,t:normalizePath,nolog,ctl:ruleRemoveTargetById=942100;ARGS:content"', $rules);
        $this->assertStringContainsString('SecRule REQUEST_FILENAME "@streq /admin/pages/edit/102" "id:20001,phase:1,pass,nolog,ctl:ruleRemoveById=942200"', $rules);
        $this->assertStringContainsString('SecRule REQUEST_FILENAME "@beginsWith /" "id:20002,phase:1,pass,t:none,t:urlDecodeUni,t:normalizePath,nolog,ctl:ruleRemoveById=942300"', $rules);
        $this->assertStringContainsString('SecAction "id:20003,phase:1,pass,nolog,ctl:ruleRemoveById=942400"', $rules);
    }

    public function test_prefix_and_exact_entries_of_the_same_path_stay_distinct(): void
    {
        $settings = WebWafPolicy::normalize(['exclusions' => [
            ['rule_id' => 1, 'path' => '/a/*'], ['rule_id' => 1, 'path' => '/a/'], ['rule_id' => 1, 'path' => '/a/*'],
        ]]);

        $this->assertSame(['/a/', '/a/*'], array_column($settings['exclusions'], 'path'));
    }

    #[DataProvider('validPaths')]
    public function test_valid_paths(string $path): void
    {
        $this->assertTrue(WebWafPolicy::validPath($path));
        $this->assertSame($path, WebWafPolicy::normalize(['exclusions' => [['rule_id' => 1, 'path' => $path]]])['exclusions'][0]['path']);
    }

    public static function validPaths(): array
    {
        return array_map(fn ($path) => [$path], ['', '/', '/wp-admin/admin-ajax.php', '/a%20b', '/a+b', '/*', '/admin/pages/edit/*',
            '/admin/pages/edit*', '/.well-known/*', '/a/.hidden*', '/'.str_repeat('a', 510).'*']);
    }

    #[DataProvider('invalidPaths')]
    public function test_invalid_paths(string $path): void
    {
        $this->assertFalse(WebWafPolicy::validPath($path));
        $this->expectException(InvalidArgumentException::class);
        WebWafPolicy::normalize(['exclusions' => [['rule_id' => 1, 'path' => $path]]]);
    }

    public static function invalidPaths(): array
    {
        // The prefix is compared with the decoded, normalized request path: an encoded or unnormalized prefix never matches.
        return array_map(fn ($path) => [$path], ['*', 'admin/*', '/a*b', '/a/**', '/*/edit', '/a%20b*', '/a+b*', '/a//b*', '/a/./b*',
            '/a/../b*', '/a/*?x=1', '/a b*', '/a"*', "/a\n*", '/a%{tx.x}*', '/'.str_repeat('a', 511).'*', '/a?b']);
    }
}
