<?php
// Parse customer PHP as text. Never include/eval it, or bootstrap WordPress.
declare(strict_types=1);
function literal(string $token): string {
    $quote = $token[0]; $body = substr($token, 1, -1);
    if ($quote === "'") { return str_replace(array("\\'", "\\\\"), array("'", "\\"), $body); }
    // Unusual escapes and interpolation require manual review.
    if (preg_match('/\\\\[^\\\\"$]/', $body)) { throw new RuntimeException('nonliteral'); }
    return str_replace(array('\\"', '\\$', '\\\\'), array('"', '$', '\\'), $body);
}
function quoteValue(string $value): string { return "'".str_replace(array('\\', "'"), array('\\\\', "\\'"), $value)."'"; }
try {
    $request = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
    $source = base64_decode($request['content'], true);
    if ($source === false) { throw new RuntimeException('invalid'); }
    $tokens = token_get_all($source);
    $significant = array();
    foreach ($tokens as $i => $token) {
        if (is_array($token) && in_array($token[0], array(T_WHITESPACE, T_COMMENT, T_DOC_COMMENT), true)) { continue; }
        $significant[] = $i;
    }
    $definitions = array();
    foreach ($significant as $n => $index) {
        $token = $tokens[$index];
        if (!is_array($token) || $token[0] !== T_STRING || strtolower($token[1]) !== 'define') { continue; }
        $previous = $tokens[$significant[$n-1] ?? -1] ?? null;
        if (is_array($previous) && in_array($previous[0], array(T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION), true)) { continue; }
        $part = array();
        for ($j = 1; $j <= 5; ++$j) { $part[] = $tokens[$significant[$n+$j] ?? -1] ?? null; }
        if ($part[0] !== '(' || !is_array($part[1]) || $part[1][0] !== T_CONSTANT_ENCAPSED_STRING) { continue; }
        $name = literal($part[1][1]);
        if (!in_array($name, array('DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST'), true)) { continue; }
        if (isset($definitions[$name]) || $part[2] !== ',' || !is_array($part[3]) || $part[3][0] !== T_CONSTANT_ENCAPSED_STRING || $part[4] !== ')') {
            throw new RuntimeException('ambiguous');
        }
        $definitions[$name] = array('index'=>$significant[$n+4], 'value'=>$name === 'DB_PASSWORD' ? '' : literal($part[3][1]));
    }
    if (count($definitions) !== 4) { throw new RuntimeException('incomplete'); }
    $name = $definitions['DB_NAME']['value'];
    $mapping = $request['databases'][$name] ?? null;
    $expectedUser = $mapping['old_user'] ?? null;
    if (!$mapping) {
        foreach ($request['databases'] as $oldName => $candidate) {
            if ($candidate['name'] === $name) {
                $name = $oldName; $mapping = $candidate; $expectedUser = $candidate['user']; break;
            }
        }
    }
    // A Plesk database can have several users; any of them identifies the same database.
    $users = isset($mapping['old_users']) && is_array($mapping['old_users']) && $expectedUser === ($mapping['old_user'] ?? null) ? $mapping['old_users'] : array($expectedUser);
    if (!$mapping || !in_array($definitions['DB_USER']['value'], $users, true)) { throw new RuntimeException('unmapped'); }
    foreach (array('DB_NAME'=>'name', 'DB_USER'=>'user', 'DB_PASSWORD'=>'password', 'DB_HOST'=>'host') as $constant=>$field) {
        $tokens[$definitions[$constant]['index']][1] = quoteValue($mapping[$field]);
    }
    $output = '';
    foreach ($tokens as $token) { $output .= is_array($token) ? $token[1] : $token; }
    echo json_encode(array('content'=>base64_encode($output), 'database'=>$name), JSON_THROW_ON_ERROR), "\n";
} catch (Throwable $e) {
    // No customer code, credentials or excerpts in diagnostics.
    fwrite(STDERR, "WordPress configuration needs manual review\n"); exit(2);
}
