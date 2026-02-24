import socket
import struct
import random
import sys

SERVER = ("127.0.0.1", 53)

def build_query(domain, qtype=1):
    tid = random.randint(0, 65535)
    flags = 0x0100
    qdcount = 1
    header = struct.pack("!HHHHHH", tid, flags, qdcount, 0, 0, 0)

    parts = domain.strip(".").split(".")
    qname = b"".join(struct.pack("B", len(p)) + p.encode() for p in parts) + b"\x00"

    question = qname + struct.pack("!HH", qtype, 1)

    return tid, header + question

def read_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break

        if (length & 0xC0) == 0xC0:
            pointer = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            continue

        offset += 1
        labels.append(data[offset:offset+length].decode())
        offset += length

    return ".".join(labels), (original_offset if jumped else offset)

def parse_response(data, expected_tid):
    tid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])

    if tid != expected_tid:
        print("Expected TID:", expected_tid)
        print("Received TID:", tid)
        return []

    offset = 12

    for _ in range(qdcount):
        _, offset = read_name(data, offset)
        offset += 4

    answers = []

    for _ in range(ancount):
        name, offset = read_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlength]
        offset += rdlength

        if rtype == 1:
            ip = socket.inet_ntoa(rdata)
            answers.append(("A", name, ip))
        elif rtype == 28:
            ip = socket.inet_ntop(socket.AF_INET6, rdata)
            answers.append(("AAAA", name, ip))

    return answers

def main():
    if len(sys.argv) < 2:
        print("Usage: python dns_query.py example.com")
        return

    domain = sys.argv[1]

    tid, query = build_query(domain, qtype=1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)

    sock.sendto(query, SERVER)
    print(f"Query sent for {domain}")

    data, _ = sock.recvfrom(4096)

    answers = parse_response(data, tid)

    print("Response:")
    for rtype, name, ip in answers:
        print(f"{rtype} {name} -> {ip}")

if __name__ == "__main__":
    main()