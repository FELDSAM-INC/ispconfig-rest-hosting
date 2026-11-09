"""Small recursive-resolver stand-in for tests: UDP and TCP on 127.0.0.1, one port.

records: {name: [('A'|'AAAA'|'CNAME'|'NS', value)]}; a name that is missing answers NXDOMAIN.
cname_only: names whose CNAME is answered without chasing it (the client asks again).
truncate: names whose UDP answer only sets TC, so the client repeats the query over TCP.
"""
import ipaddress
import socket
import struct
import threading

TYPES = {'A': 1, 'AAAA': 28, 'CNAME': 5, 'NS': 2}


def wire(name):
    return b''.join(bytes([len(label)]) + label.encode() for label in name.split('.') if label) + b'\0'


class FakeDns:
    def __init__(self, records=None, *, rcode=0, cname_only=(), truncate=()):
        self.records, self.rcode = records or {}, rcode
        self.cname_only, self.truncate = set(cname_only), set(truncate)
        self.queries = []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(('127.0.0.1', 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind(('127.0.0.1', self.port))
        self.tcp.listen()
        self.address = ('127.0.0.1', self.port)
        for target in (self.serve_udp, self.serve_tcp):
            threading.Thread(target=target, daemon=True).start()

    def close(self):
        self.udp.close()
        self.tcp.close()

    def answer(self, query, *, tcp):
        ident, = struct.unpack('!H', query[:2])
        end = query.index(b'\0', 12) + 5
        labels, offset = [], 12
        while query[offset]:
            labels.append(query[offset + 1:offset + 1 + query[offset]].decode())
            offset += 1 + query[offset]
        name, qtype = '.'.join(labels).lower(), struct.unpack('!H', query[end - 4:end - 2])[0]
        self.queries.append((name, qtype, 'tcp' if tcp else 'udp'))
        answers, rcode, owner = [], self.rcode, name
        if not rcode and not tcp and name in self.truncate:
            return struct.pack('!HHHHHH', ident, 0x8380, 1, 0, 0, 0) + query[12:end]
        for _ in range(8):
            if rcode:
                break
            if owner not in self.records:
                rcode = 3
                break
            cname = [value for kind, value in self.records[owner] if kind == 'CNAME']
            if not cname:
                for kind, value in self.records[owner]:
                    if TYPES[kind] == qtype:
                        data = wire(value) if kind == 'NS' else ipaddress.ip_address(value).packed
                        answers.append(wire(owner) + struct.pack('!HHIH', qtype, 1, 60, len(data)) + data)
                break
            # Owner of the query name is compressed to the question (offset 12).
            data = wire(cname[0])
            answers.append((b'\xc0\x0c' if owner == name else wire(owner)) + struct.pack('!HHIH', 5, 1, 60, len(data)) + data)
            if owner in self.cname_only:
                break
            owner = cname[0]
        return struct.pack('!HHHHHH', ident, 0x8180 | rcode, 1, len(answers), 0, 0) + query[12:end] + b''.join(answers)

    def serve_udp(self):
        while True:
            try:
                query, peer = self.udp.recvfrom(4096)
                self.udp.sendto(self.answer(query, tcp=False), peer)
            except OSError:
                return

    def serve_tcp(self):
        while True:
            try:
                connection, _ = self.tcp.accept()
            except OSError:
                return
            with connection:
                size, = struct.unpack('!H', connection.recv(2))
                response = self.answer(connection.recv(size), tcp=True)
                connection.sendall(struct.pack('!H', len(response)) + response)
