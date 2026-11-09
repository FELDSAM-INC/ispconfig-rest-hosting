<?php

return [
    // The PHP settings a new website starts with, written to its own PHP configuration like a customer's change in
    // the panel (which can change them later). On/off settings of the panel: opcache.enable, display_errors,
    // log_errors, allow_url_fopen, file_uploads, short_open_tag. JSON, e.g. {"opcache.enable":"on"}; {} uses the
    // server's php.ini. OPcache stays on in the server's php.ini: PHP-FPM cannot switch it on per website otherwise.
    'new_site_defaults' => json_decode((string) env('WEB_PHP_NEW_SITE_DEFAULTS', '{"opcache.enable":"off","short_open_tag":"on"}'), true) ?: [],
];
