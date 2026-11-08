<?php

namespace IspconfigRestHosting\Tests\Unit;

use IspconfigRestHosting\Support\DnsLookup;
use PHPUnit\Framework\TestCase;

final class DnsLookupTest extends TestCase
{
    /** A response to DnsLookup::query() with the given answer records (name pointers to the question). */
    private static function response(int $id, string $name, int $type, array $records, int $flags = 0x8180): string
    {
        $query = DnsLookup::query($id, $name, $type);
        $answers = '';
        foreach ($records as [$recordType, $data]) {
            $answers .= "\xC0\x0C".pack('nnNn', $recordType, 1, 60, strlen($data)).$data;
        }

        return pack('nnnnnn', $id, $flags, 1, count($records), 0, 0).substr($query, 12).$answers;
    }

    public function test_queries_ask_recursively_for_one_name(): void
    {
        $this->assertSame("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x1c\x00\x01", DnsLookup::query(0x1234, 'www.example.com', 28));
    }

    public function test_answers_return_the_addresses_of_the_asked_type_behind_cnames(): void
    {
        // CNAME to a compressed target, then the target's A records.
        $cname = "\x03cdn\xC0\x10";
        $packet = self::response(7, 'www.example.com', 1, [[5, $cname], [1, inet_pton('198.51.100.2')], [1, inet_pton('198.51.100.1')], [28, inet_pton('2001:db8::1')]]);
        $this->assertSame(['id' => 7, 'name' => 'www.example.com', 'type' => 1, 'result' => ['198.51.100.1', '198.51.100.2']], DnsLookup::parse($packet));
        $packet = self::response(8, 'Example.COM', 28, [[28, inet_pton('2001:db8::1')]]);
        $this->assertSame(['2001:db8::1'], DnsLookup::parse($packet)['result']);
        $this->assertSame('example.com', DnsLookup::parse($packet)['name']);
    }

    public function test_response_codes_and_malformed_packets(): void
    {
        $this->assertSame('nxdomain', DnsLookup::parse(self::response(1, 'example.com', 1, [], 0x8183))['result']);
        $this->assertSame('servfail', DnsLookup::parse(self::response(1, 'example.com', 1, [], 0x8182))['result']);
        $this->assertSame('refused', DnsLookup::parse(self::response(1, 'example.com', 1, [], 0x8185))['result']);
        $this->assertSame('error', DnsLookup::parse(self::response(1, 'example.com', 1, [], 0x8380))['result'], 'truncated');
        $this->assertSame([], DnsLookup::parse(self::response(1, 'example.com', 1, []))['result'], 'no data');
        $this->assertNull(DnsLookup::parse(DnsLookup::query(1, 'example.com', 1)), 'a query is not a response');
        $this->assertNull(DnsLookup::parse('short'));
        $truncated = self::response(1, 'example.com', 1, [[1, inet_pton('198.51.100.1')]]);
        $this->assertSame('error', DnsLookup::parse(substr($truncated, 0, -2))['result']);
        // A pointer loop never ends a name.
        $loop = pack('nnnnnn', 1, 0x8180, 1, 0, 0, 0)."\xC0\x0C".pack('nn', 1, 1);
        $this->assertNull(DnsLookup::parse($loop));
    }

    public function test_resolver_endpoints(): void
    {
        $this->assertSame(['1.1.1.1', 53], DnsLookup::endpoint('1.1.1.1'));
        $this->assertSame(['2606:4700:4700::1111', 53], DnsLookup::endpoint('2606:4700:4700::1111'));
        $this->assertSame(['127.0.0.1', 5353], DnsLookup::endpoint('127.0.0.1:5353'));
        $this->assertSame(['::1', 5353], DnsLookup::endpoint('[::1]:5353'));
        foreach (['resolver.example', '1.1.1.1:0', '1.1.1.1:70000', '[1.1.1.1]:53x', ''] as $invalid) {
            $this->assertSame([null, 0], DnsLookup::endpoint($invalid), $invalid);
        }
    }

    public function test_lookups_over_udp_with_a_retransmission_and_a_silent_resolver(): void
    {
        $port = random_int(20000, 40000);
        $answers = ['example.com A' => ['198.51.100.1'], 'example.com AAAA' => [], 'www.example.com A' => 'drop-once',
            'www.example.com AAAA' => ['2001:db8::1'], 'missing.example A' => 'nxdomain', 'missing.example AAAA' => 'nxdomain'];
        $process = proc_open([PHP_BINARY, __DIR__.'/../Fixtures/dns-responder.php', (string) $port, json_encode($answers)], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $this->assertSame("ready\n", fgets($pipes[1]));
        try {
            $silent = '127.0.0.1:'.($port + 1);
            $result = (new DnsLookup)->lookup(['example.com', 'www.example.com', 'missing.example'], ['127.0.0.1:'.$port, $silent, 'invalid'], 1.0);
        } finally {
            proc_terminate($process);
            proc_close($process);
        }
        $this->assertSame([
            'example.com' => ['A' => ['198.51.100.1'], 'AAAA' => []],
            'www.example.com' => ['A' => ['192.0.2.1'], 'AAAA' => ['2001:db8::1']],
            'missing.example' => ['A' => 'nxdomain', 'AAAA' => 'nxdomain'],
        ], $result['127.0.0.1:'.$port]);
        $this->assertSame(['A' => 'timeout', 'AAAA' => 'timeout'], $result[$silent]['example.com']);
        $this->assertSame(['A' => 'timeout', 'AAAA' => 'timeout'], $result['invalid']['missing.example']);
    }
}
