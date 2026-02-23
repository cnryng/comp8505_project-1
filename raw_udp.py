import socket
import struct

DEST_IP = '192.168.1.1'
SRC_IP = '192.168.1.0'
DEST_PORT = 12345
SRC_PORT = 12345
PAYLOAD = b"Hello World!"

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xff)
    s += s >> 16
    return ~s & 0xffff

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
ver_ihl = (4 << 4) + 5
tos = 0
tot_len = 20 + 8 + len(PAYLOAD)
id = 0x1234
frag = 0
ttl = 64
proto = socket.IPPROTO_UDP
check = 0
saddr = socket.inet_aton(SRC_IP)
daddr = socket.inet_aton(DEST_IP)
ip_header = struct.pack("!BBHHHBBH4s4s",
                        ver_ihl,
                        tos,
                        tot_len,
                        id,
                        frag,
                        ttl,
                        proto,
                        check,
                        saddr,
                        daddr
                        )
check = checksum(ip_header)
udp_len = 8 + len(PAYLOAD)
udp_header = struct.pack("!HHHH",
                         SRC_PORT,
                         DEST_PORT,
                         udp_len,
                         0)
packet = ip_header + udp_header + PAYLOAD
s.sendto(packet, (DEST_IP, 0))