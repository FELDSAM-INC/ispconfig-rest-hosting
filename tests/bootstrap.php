<?php

// The extension is tested inside an ispconfig-rest checkout (extensions/hosting): core's autoloader, application and
// test support classes; the extension's own classes load through extension.json like in production.
$core = getenv('ISPCONFIG_REST_DIR') ?: dirname(__DIR__, 3);
$loader = require $core.'/vendor/autoload.php';
$loader->addPsr4('IspconfigRestHosting\\Tests\\', __DIR__);
$loader->addPsr4('IspconfigRestHosting\\', dirname(__DIR__).'/src');
