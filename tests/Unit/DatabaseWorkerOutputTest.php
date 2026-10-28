<?php

namespace IspconfigRestHosting\Tests\Unit;

use IspconfigRest\Worker\DatabaseWorker;
use PDO;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ReflectionProperty;

final class DatabaseWorkerOutputTest extends TestCase
{
    public function test_import_discards_query_results_without_creating_an_output_file(): void
    {
        require_once dirname(__DIR__, 2).'/worker/DatabaseWorker.php';
        $workspace = sys_get_temp_dir().'/database-worker-output-'.bin2hex(random_bytes(8));
        mkdir($workspace, 0700);

        try {
            $db = new PDO('sqlite::memory:');
            $db->exec('CREATE TABLE api_database_workers (server_id INTEGER, heartbeat INTEGER)');
            $db->exec('CREATE TABLE api_database_operations (id TEXT, status TEXT, updated_at INTEGER)');

            foreach ([0, 1024] as $limit) {
                $worker = new DatabaseWorker($db, $db, 1, [], 65534, 65534, $workspace, $workspace.'/log', $limit);
                (new ReflectionProperty($worker, 'directory'))->setValue($worker, $workspace);
                (new ReflectionProperty($worker, 'started'))->setValue($worker, time());

                // A real child process simulates a small SQL import that emits
                // a large SELECT result. It must not allocate a disk output file.
                (new ReflectionMethod($worker, 'process'))->invoke($worker, [
                    PHP_BINARY, '-r', 'fwrite(STDOUT, str_repeat("x", 2 * 1024 * 1024));',
                ], '/dev/null', $workspace.'/output');

                self::assertFileDoesNotExist($workspace.'/output');
                self::assertSame(0, filesize($workspace.'/stderr'));
            }
        } finally {
            foreach (glob($workspace.'/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($workspace);
        }
    }
}
