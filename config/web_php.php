<?php

return [
    // The PHP settings a new website starts with, written to its own PHP configuration like a customer's change in
    // the panel (which can change them later): the on/off settings of the panel (opcache.enable, display_errors,
    // log_errors, allow_url_fopen, file_uploads, short_open_tag) and error_reporting (one of the panel's choices).
    // JSON, e.g. {"opcache.enable":"on"}; {} uses the server's php.ini. OPcache stays on in the server's php.ini:
    // PHP-FPM cannot switch it on per website otherwise. Errors are logged without warnings, notices and deprecations.
    'new_site_defaults' => json_decode((string) env('WEB_PHP_NEW_SITE_DEFAULTS', json_encode([
        'opcache.enable' => 'off',
        'short_open_tag' => 'on',
        'error_reporting' => 'E_ALL & ~E_WARNING & ~E_NOTICE & ~E_DEPRECATED & ~E_STRICT',
    ])), true) ?: [],
];
