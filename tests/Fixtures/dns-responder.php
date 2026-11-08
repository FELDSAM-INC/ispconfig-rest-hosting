<?php

// A UDP DNS responder for DnsLookupTest: php dns-responder.php PORT JSON. JSON maps "name TYPE" to a list of addresses,
// "nxdomain", or "drop-once" (the first query is not answered, the retransmission is). Prints "ready" when bound.
[, $port, $json] = $argv;
$answers = json_decode($json, true);
$socket = stream_socket_server('udp://127.0.0.1:'.$port, $errno, $error, STREAM_SERVER_BIND);
if ($socket === false) {
    fwrite(STDERR, $error);
    exit(1);
}
echo "ready\n";
$dropped = [];
$deadline = time() + 20;
while (time() < $deadline) {
    $read = [$socket];
    $write = $except = null;
    if (! stream_select($read, $write, $except, 1)) {
        continue;
    }
    $packet = stream_socket_recvfrom($socket, 512, 0, $peer);
    $id = unpack('n', $packet)[1];
    $offset = 12;
    $labels = [];
    while (($length = ord($packet[$offset])) !== 0) {
        $labels[] = substr($packet, $offset + 1, $length);
        $offset += 1 + $length;
    }
    $question = substr($packet, 12, $offset + 5 - 12);
    $type = unpack('n', $packet, $offset + 1)[1];
    $key = implode('.', $labels).' '.($type === 1 ? 'A' : 'AAAA');
    $answer = $answers[$key] ?? [];
    if ($answer === 'drop-once' && ! isset($dropped[$key])) {
        $dropped[$key] = true;

        continue;
    }
    $records = '';
    $count = 0;
    foreach (is_array($answer) ? $answer : ($answer === 'drop-once' ? ['192.0.2.1'] : []) as $address) {
        $data = inet_pton($address);
        // Name as a pointer to the question.
        $records .= "\xC0\x0C".pack('nnNn', $type, 1, 300, strlen($data)).$data;
        $count++;
    }
    $flags = 0x8180 | ($answer === 'nxdomain' ? 3 : 0);
    stream_socket_sendto($socket, pack('nnnnnn', $id, $flags, 1, $count, 0, 0).$question.$records, 0, $peer);
}
