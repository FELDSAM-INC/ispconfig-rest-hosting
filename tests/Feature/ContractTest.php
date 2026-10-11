<?php

namespace IspconfigRestHosting\Tests\Feature;

use Illuminate\Support\Facades\Route;
use Symfony\Component\Yaml\Yaml;
use Tests\TestCase;

/** The extension's contract as ispconfig-rest serves it (spec 058). */
class ContractTest extends TestCase
{
    private const HEADER_REF = '../../components/headers/ChangeSetId.yaml';

    /** API-owned transfer state; never journals ISPConfig records. */
    private const NON_JOURNALING_WRITES = [
        'PUT /sites/databases/{id}/operations/{operation}/chunks/{sequence}',
        'POST /sites/databases/{id}/operations/{operation}/upload-complete',
        'DELETE /sites/databases/{id}/operations/{operation}',
    ];

    /** @return array<string, array<string, mixed>> path => operations, resolved from the extension's root fragment */
    private function paths(): array
    {
        $paths = [];
        foreach (Yaml::parseFile(dirname(__DIR__, 2).'/api/openapi.yaml')['paths'] as $path => $item) {
            [$file, $pointer] = explode('#', $item['$ref'], 2);
            $document = Yaml::parseFile(dirname(__DIR__, 2).'/api/'.ltrim($file, './'));
            $key = str_replace(['~1', '~0'], ['/', '~'], ltrim($pointer, '/'));
            $this->assertArrayHasKey($key, $document, "{$path}: {$item['$ref']} does not resolve");
            $paths[$path] = $document[$key];
        }

        return $paths;
    }

    public function test_served_root_document_contains_the_extension_paths(): void
    {
        $served = Yaml::parse($this->get('/api/spec')->assertOk()->getContent());

        foreach (array_keys($this->paths()) as $path) {
            $this->assertArrayHasKey($path, $served['paths']);
        }
        $this->assertArrayHasKey('/sites/web-domains/{id}', $served['paths'], 'core paths stay');
    }

    public function test_every_route_is_documented_and_every_path_routed(): void
    {
        $documented = [];
        foreach ($this->paths() as $path => $operations) {
            foreach (array_intersect(array_keys($operations), ['get', 'post', 'put', 'patch', 'delete']) as $method) {
                $documented[] = strtoupper($method).' '.preg_replace('/\{[^}]+\}/', '{}', $path);
            }
        }
        $routed = [];
        foreach (Route::getRoutes() as $route) {
            $action = $route->getActionName();
            if (str_starts_with($action, 'IspconfigRestHosting\\')) {
                foreach (array_diff($route->methods(), ['HEAD']) as $method) {
                    $routed[] = $method.' '.preg_replace('/\{[^}]+\}/', '{}', substr($route->uri(), strlen('api/v1')));
                }
            }
        }

        $this->assertEqualsCanonicalizing($documented, $routed);
    }

    public function test_core_schemas_are_served_with_the_extension_fields(): void
    {
        $website = Yaml::parse($this->get('/api/components/schemas/WebDomain.yaml')->assertOk()->getContent());
        foreach (['logs_available', 'waf_available', 'waf_mode', 'wordpress', 'runtime_capabilities', 'runtime_settings', 'php_settings', 'public_document_root', 'domain'] as $field) {
            $this->assertArrayHasKey($field, $website['properties']);
        }
        $this->assertArrayHasKey('output_log', Yaml::parse($this->get('/api/components/schemas/CronJob.yaml')->getContent())['properties']);
        $this->assertArrayHasKey('operations', Yaml::parse($this->get('/api/components/schemas/Database.yaml')->getContent())['properties']);
        $client = Yaml::parse($this->get('/api/components/schemas/Client.yaml')->getContent())['properties'];
        $this->assertArrayHasKey('web_php_policy', $client);
        $this->assertArrayHasKey('web_resource_limits', $client);

        $this->get('/api/components/schemas/WebWaf.yaml')->assertOk()->assertSee('properties');
        $this->get('/api/modules/sites/web-waf.yaml')->assertOk();
    }

    public function test_every_journaling_write_documents_the_change_set_header(): void
    {
        $missing = [];
        $exceptions = [];
        foreach ($this->paths() as $path => $operations) {
            foreach ($operations as $method => $operation) {
                if (! in_array($method, ['post', 'put', 'patch', 'delete'], true)) {
                    continue;
                }
                $name = strtoupper($method).' '.$path;
                $exception = in_array($name, self::NON_JOURNALING_WRITES, true);
                if ($exception) {
                    $exceptions[] = $name;
                }
                foreach ($operation['responses'] ?? [] as $code => $response) {
                    $ref = $response['headers']['X-Change-Set-Id']['$ref'] ?? null;
                    if (preg_match('/^2\d\d$/', (string) $code) && ($exception ? $ref !== null : $ref !== self::HEADER_REF)) {
                        $missing[] = "{$name} {$code}";
                    }
                }
            }
        }

        $this->assertSame([], $missing);
        $this->assertEqualsCanonicalizing(self::NON_JOURNALING_WRITES, $exceptions);
    }
}
