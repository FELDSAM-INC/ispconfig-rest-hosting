<?php
// SQL strings/BLOBs are opaque: do not replace schema names using sed.
// The installer copies the same normalizer used by the database worker.
require is_file(__DIR__.'/SqlDump.php') ? __DIR__.'/SqlDump.php' : dirname(__DIR__).'/worker/SqlDump.php';
if ($argc !== 3 || !preg_match('/^[a-zA-Z0-9_]{1,64}$/D', $argv[1]) || !preg_match('/^[a-zA-Z0-9_]{1,64}$/D', $argv[2])) { exit(1); }
\IspconfigRest\Worker\SqlDump::stream(STDIN, STDOUT, $argv[1], $argv[2]);
