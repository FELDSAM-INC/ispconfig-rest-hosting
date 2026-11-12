<?php

// Maintainer tool (spec 047): move waf-server/crs.json to
// - the newest release of its OWASP CRS line (4.25 LTS: the same major and minor version), verified like the installer
//   verifies it: the release key's OpenPGP signature (gpgv against waf-server/crs-release-key.gpg, pinned fingerprint),
//   then a SHA-256 pin;
// - the newest commit of each application profile's official rule exclusion plugin that changed its rule files. The
//   plugins fix false positives on their main branch for months between tags, so they are pinned by commit and SHA-256.
// Exit 0 when crs.json changed (what changed on stdout, and as JSON in the file given as the first argument), 3 when it
// is current, 1 on any error. Used by crs-update.yml.
declare(strict_types=1);
require dirname(__DIR__).'/src/Support/WebWafProfiles.php';
require dirname(__DIR__).'/src/Support/WebWafCrs.php';

use IspconfigRestHosting\Support\WebWafCrs;

function fail(string $message): never
{
    fwrite(STDERR, $message."\n");
    exit(1);
}

function fetch(string $url, ?string $file = null): string
{
    $headers = "User-Agent: ispconfig-rest-hosting-crs-update\r\nAccept: application/vnd.github+json\r\n";
    if (getenv('GITHUB_TOKEN') && str_starts_with($url, 'https://api.github.com/')) {
        $headers .= 'Authorization: Bearer '.getenv('GITHUB_TOKEN')."\r\n";
    }
    $body = @file_get_contents($url, false, stream_context_create(['http' => ['header' => $headers, 'timeout' => 60]]));
    if ($body === false || $body === '') {
        fail('Could not download '.$url);
    }
    if ($file !== null && file_put_contents($file, $body) === false) {
        fail('Could not write '.$file);
    }

    return $body;
}

$root = dirname(__DIR__);
$path = $root.'/waf-server/crs.json';
$manifest = WebWafCrs::manifest((string) file_get_contents($path));
$changes = ['crs' => null, 'plugins' => []];

[, $line, $current] = array_map('intval', explode('.', $manifest['version']));
$newest = $current;
foreach (json_decode(fetch(getenv('CRS_RELEASES_URL') ?: 'https://api.github.com/repos/coreruleset/coreruleset/releases?per_page=100'), true) ?: [] as $release) {
    if (! is_array($release) || ! empty($release['draft']) || ! empty($release['prerelease'])
        || ! preg_match('/\Av4\.([0-9]{1,3})\.([0-9]{1,3})\z/D', (string) ($release['tag_name'] ?? ''), $match) || (int) $match[1] !== $line) {
        continue;
    }
    $newest = max($newest, (int) $match[2]);
}
if ($newest === $current) {
    echo 'OWASP CRS '.$manifest['version'].' is the newest release of the 4.'.$line." line.\n";
} else {
    $version = '4.'.$line.'.'.$newest;
    $archive = 'https://github.com/coreruleset/coreruleset/releases/download/v'.$version.'/coreruleset-'.$version.'-minimal.tar.gz';
    $work = sys_get_temp_dir().'/crs-update-'.bin2hex(random_bytes(6));
    mkdir($work.'/gnupg', 0700, true);
    try {
        fetch($archive, $work.'/archive.tar.gz');
        fetch($archive.'.asc', $work.'/archive.tar.gz.asc');
        $process = proc_open(['gpgv', '--homedir', $work.'/gnupg', '--status-fd', '1', '--keyring', $root.'/waf-server/crs-release-key.gpg',
            $work.'/archive.tar.gz.asc', $work.'/archive.tar.gz'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $status = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);
        if (! WebWafCrs::signatureValid((string) $status, $manifest['fingerprint'])) {
            fail('The signature of OWASP CRS '.$version.' is not valid for the pinned release key '.$manifest['fingerprint'].'.');
        }
        $manifest = ['version' => $version, 'archive' => $archive, 'sha256' => hash_file('sha256', $work.'/archive.tar.gz'),
            'signature' => $archive.'.asc'] + $manifest;
    } finally {
        exec('rm -rf '.escapeshellarg($work));
    }
    $changes['crs'] = $version;
    echo 'OWASP CRS '.$version."\n";
}

foreach ($manifest['plugins'] as $profile => $plugin) {
    $repository = 'coreruleset/'.$plugin['name'].'-plugin';
    $commits = json_decode(fetch(sprintf(getenv('CRS_PLUGIN_COMMITS_URL') ?: 'https://api.github.com/repos/%s/commits?path=plugins&per_page=1', $repository)), true);
    $commit = is_array($commits) && is_array($commits[0] ?? null) ? ($commits[0]['sha'] ?? null) : null;
    if (! is_string($commit) || ! preg_match('/\A[0-9a-f]{40}\z/D', $commit)) {
        fail('Could not read the newest commit of '.$repository.'.');
    }
    if ($commit === $plugin['commit']) {
        continue;
    }
    $texts = [];
    foreach (array_keys($plugin['files']) as $file) {
        $texts[$file] = fetch(WebWafCrs::pluginUrl($plugin['name'], $commit, $file));
    }
    $files = array_map(static fn (string $text): string => hash('sha256', $text), $texts);
    if ($files === $plugin['files']) {
        continue;
    }
    // The worker offers a profile only while its plugin can be switched off per website (WebWafProfiles::installed).
    if (! str_contains($texts[$plugin['name'].'-before.conf'], 'SecRule TX:'.$plugin['name'].'-plugin_enabled "@eq 0"')) {
        fail($repository.' '.$commit.' no longer has the rule that switches the plugin off; check it by hand.');
    }
    $version = preg_match('/^# Plugin version: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*$/m', $texts[$plugin['name'].'-config.conf'], $match)
        ? $match[1] : $plugin['version'];
    $manifest['plugins'][$profile] = ['name' => $plugin['name'], 'version' => $version, 'commit' => $commit, 'files' => $files];
    $changes['plugins'][] = ['profile' => $profile, 'name' => $plugin['name'], 'version' => $version, 'commit' => $commit, 'previous' => $plugin['commit']];
    echo $plugin['name'].' '.$version.' at '.substr($commit, 0, 7)."\n";
}

if ($changes['crs'] === null && $changes['plugins'] === []) {
    echo "The rule exclusion plugins are current.\n";
    exit(3);
}
$json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n";
WebWafCrs::manifest($json);
file_put_contents($path, $json);
if (isset($argv[1]) && file_put_contents($argv[1], json_encode($changes, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n") === false) {
    fail('Could not write '.$argv[1]);
}
