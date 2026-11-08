<?php

namespace IspconfigRestHosting\Support;

/**
 * A and AAAA lookups through chosen recursive resolvers over UDP (spec 059). The panel's own resolver may be
 * authoritative for the zone, or cache it differently, so the certificate authority's view is approximated by public
 * resolvers. All queries go out at once and are answered within one timeout; nothing is cached.
 */
class DnsLookup
{
    public const TYPES = ['A' => 1, 'AAAA' => 28];

    /**
     * @param  list<string>  $names  lower-case host names
     * @param  list<string>  $resolvers  "IP" or "IP:port" ("[IPv6]:port")
     * @return array<string, array<string, array<string, list<string>|string>>> resolver => name => type => addresses,
     *                                                                          or "nxdomain", "servfail", "refused", "error", "timeout"
     */
    public function lookup(array $names, array $resolvers, float $timeout = 2.5): array
    {
        $result = [];
        $pending = [];
        $sockets = [];
        foreach ($resolvers as $resolver) {
            [$host, $port] = self::endpoint($resolver);
            $socket = $host === null ? false : @stream_socket_client('udp://'.(str_contains($host, ':') ? '['.$host.']' : $host).':'.$port, $errno, $error, 1);
            foreach ($names as $name) {
                foreach (array_keys(self::TYPES) as $type) {
                    $result[$resolver][$name][$type] = 'timeout';
                }
            }
            if ($socket === false) {
                continue;
            }
            stream_set_blocking($socket, false);
            $sockets[$resolver] = $socket;
            foreach ($names as $name) {
                foreach (self::TYPES as $type => $code) {
                    do {
                        $id = random_int(0, 0xFFFF);
                    } while (isset($pending[$resolver][$id]));
                    $packet = self::query($id, $name, $code);
                    $pending[$resolver][$id] = [$name, $type, $packet];
                    @fwrite($socket, $packet);
                }
            }
        }
        $start = microtime(true);
        $resent = false;
        while ($sockets !== [] && array_filter($pending) !== [] && ($left = $timeout - (microtime(true) - $start)) > 0) {
            if (! $resent && $left < $timeout / 2) {
                // One retransmission of the unanswered queries: UDP packets get lost.
                $resent = true;
                foreach ($pending as $resolver => $queries) {
                    foreach ($queries as [, , $packet]) {
                        @fwrite($sockets[$resolver], $packet);
                    }
                }
            }
            $read = array_values($sockets);
            $write = $except = null;
            $wait = min($left, $resent ? $left : $left - $timeout / 2);
            if (@stream_select($read, $write, $except, (int) $wait, (int) (fmod($wait, 1) * 1_000_000)) === false) {
                break;
            }
            foreach ($read as $socket) {
                $resolver = array_search($socket, $sockets, true);
                while (($packet = @fread($socket, 4096)) !== false && $packet !== '') {
                    $answer = self::parse($packet);
                    $query = $answer === null ? null : ($pending[$resolver][$answer['id']] ?? null);
                    if ($query === null || $answer['name'] !== $query[0] || $answer['type'] !== self::TYPES[$query[1]]) {
                        continue;
                    }
                    unset($pending[$resolver][$answer['id']]);
                    $result[$resolver][$query[0]][$query[1]] = $answer['result'];
                }
            }
        }
        foreach ($sockets as $socket) {
            fclose($socket);
        }

        return $result;
    }

    /** @return array{0: string|null, 1: int} */
    public static function endpoint(string $resolver): array
    {
        if (filter_var($resolver, FILTER_VALIDATE_IP)) {
            return [$resolver, 53];
        }
        if (preg_match('/\A\[([0-9a-fA-F:.]+)\]:(\d{1,5})\z/D', $resolver, $m) || preg_match('/\A([0-9.]+):(\d{1,5})\z/D', $resolver, $m)) {
            return filter_var($m[1], FILTER_VALIDATE_IP) && (int) $m[2] > 0 && (int) $m[2] < 65536 ? [$m[1], (int) $m[2]] : [null, 0];
        }

        return [null, 0];
    }

    /** A recursive query (RD) for one name and type. */
    public static function query(int $id, string $name, int $type): string
    {
        $qname = '';
        foreach (explode('.', rtrim($name, '.')) as $label) {
            $qname .= chr(strlen($label)).$label;
        }

        return pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0).$qname."\0".pack('nn', $type, 1);
    }

    /**
     * The answer to one query: its id, question and the addresses of the question's type in the answer section (the
     * resolver follows CNAME chains). Null for anything that is not a well-formed response.
     *
     * @return array{id: int, name: string, type: int, result: list<string>|string}|null
     */
    public static function parse(string $packet): ?array
    {
        if (strlen($packet) < 12) {
            return null;
        }
        $header = unpack('nid/nflags/nqd/nan', $packet);
        if (($header['flags'] & 0x8000) === 0 || $header['qd'] !== 1) {
            return null;
        }
        $offset = 12;
        $name = self::name($packet, $offset);
        if ($name === null || strlen($packet) < $offset + 4) {
            return null;
        }
        ['type' => $type, 'class' => $class] = unpack('ntype/nclass', $packet, $offset);
        $offset += 4;
        $rcode = $header['flags'] & 0x000F;
        $base = ['id' => $header['id'], 'name' => $name, 'type' => $type];
        if ($class !== 1) {
            return null;
        }
        if ($header['flags'] & 0x0200) {
            return $base + ['result' => 'error'];
        }
        if ($rcode !== 0) {
            return $base + ['result' => [3 => 'nxdomain', 2 => 'servfail', 5 => 'refused'][$rcode] ?? 'error'];
        }
        $addresses = [];
        for ($i = 0; $i < $header['an']; $i++) {
            if (self::name($packet, $offset) === null || strlen($packet) < $offset + 10) {
                return $base + ['result' => 'error'];
            }
            $record = unpack('ntype/nclass/Nttl/nlength', $packet, $offset);
            $offset += 10;
            if (strlen($packet) < $offset + $record['length']) {
                return $base + ['result' => 'error'];
            }
            $data = substr($packet, $offset, $record['length']);
            $offset += $record['length'];
            if ($record['class'] === 1 && $record['type'] === $type && strlen($data) === ($type === 1 ? 4 : ($type === 28 ? 16 : -1))) {
                $addresses[] = (string) inet_ntop($data);
            }
        }
        $addresses = array_values(array_unique($addresses));
        sort($addresses);

        return $base + ['result' => $addresses];
    }

    /** A (possibly compressed) domain name in lower case; $offset moves past it. */
    private static function name(string $packet, int &$offset): ?string
    {
        $labels = [];
        $position = $offset;
        $jumped = false;
        for ($steps = 0; $steps < 128; $steps++) {
            if ($position >= strlen($packet)) {
                return null;
            }
            $length = ord($packet[$position]);
            if ($length === 0) {
                if (! $jumped) {
                    $offset = $position + 1;
                }

                return strtolower(implode('.', $labels));
            }
            if (($length & 0xC0) === 0xC0) {
                if ($position + 1 >= strlen($packet)) {
                    return null;
                }
                if (! $jumped) {
                    $offset = $position + 2;
                }
                $jumped = true;
                $position = (($length & 0x3F) << 8) | ord($packet[$position + 1]);

                continue;
            }
            if ($length > 63 || $position + 1 + $length > strlen($packet)) {
                return null;
            }
            $labels[] = substr($packet, $position + 1, $length);
            $position += 1 + $length;
        }

        return null;
    }
}
