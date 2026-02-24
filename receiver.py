import socket
import struct

LISTEN_IP = "192.168.5.61"
DEST_PORT = 9999 # filter by expected dst_port value (== total_chunks)
OUTPUT_FILE = "received_file.txt"
REAL_UDP_LEN = 12 # 8 byte header + 4 byte dummy payload

def parse_covert_packet(raw):
    udp = raw[20:28]
    src_port, dst_port, length, covert_checksum = struct.unpack("!HHHH", udp)

    # Filter: only our stream
    if dst_port != DEST_PORT:
        return None

    seq_num = src_port
    total_chunks = length - REAL_UDP_LEN   # decode total_chunks from length offset
    data_chunk = struct.pack("!H", covert_checksum)

    return seq_num, total_chunks, data_chunk


def receive_file():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    chunks = {}
    total_expected = None

    print("[*] Listening for covert packets...")

    while True:
        raw, addr = s.recvfrom(65535)

        try:
            result = parse_covert_packet(raw)
            if result is None:
                continue
            seq, total, data = result
        except Exception:
            continue

        if total <= 0 or total > 50000:
            continue

        if total_expected is None:
            total_expected = total
            print(f"[*] Expecting {total_expected} chunks...")

        chunks[seq] = data

        if len(chunks) >= total_expected:
            break

    result = b"".join(chunks[i] for i in sorted(chunks.keys()))

    with open(OUTPUT_FILE, "wb") as f:
        f.write(result)

    print(f"[+] File received and saved to '{OUTPUT_FILE}'")


receive_file()
