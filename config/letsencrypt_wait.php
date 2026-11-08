<?php

// Spec 059: Let's Encrypt once the website's domain points to its server.
return [
    // Public recursive resolvers that must all agree (those that answer, at least two of them); "IP" or "IP:port".
    'resolvers' => array_values(array_filter(array_map('trim', explode(',', (string) env('LETSENCRYPT_WAIT_RESOLVERS', '1.1.1.1,8.8.8.8,9.9.9.9'))))),
    // Public addresses of a web server when ISPConfig's server_ip lists only private ones (NAT), as JSON:
    // {"4": ["203.0.113.10", "2001:db8::10"]}. Replaces the server_ip addresses of that server.
    'server_addresses' => json_decode((string) env('LETSENCRYPT_WAIT_SERVER_ADDRESSES', '{}'), true) ?: [],
    'expires_after' => 7 * 86400,
    // Every 5 minutes during the first day, then every 30 minutes.
    'intervals' => [[86400, 300], [PHP_INT_MAX, 1800]],
    'retry_after_failure' => 900,
    'max_failures' => 5,
    // A queued change ISPConfig did not process within this time counts as a failed attempt.
    'issuing_timeout' => 1800,
    // Names added to the certificate later are renewed at most this often.
    'renew_interval' => 3600,
    'keep_finished' => 30 * 86400,
];
