#!/usr/bin/env python3
"""
Client Program - Port Knock Listener with Command Execution
Demonstrates proper command execution patterns for remote administration.
"""

import socket
import threading
import time
from collections import deque
import subprocess
import json
import os
import sys

# Configuration
KNOCK_SEQUENCE = [7000, 8000, 9000]
KNOCK_TIMEOUT = 10
COMMAND_PORT = 9999
LISTEN_PORTS = [7000, 8000, 9000]


class CommandExecutor:
    """Handles execution of various command types"""

    @staticmethod
    def execute_shell_command(command):
        """
        Execute a shell command and return output.
        Uses subprocess for safe execution.
        """
        try:
            # Run command with timeout and capture output
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,  # 30 second timeout
                cwd=os.getcwd()
            )

            output = {
                'success': True,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }

            return output

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Command timed out after 30 seconds'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @staticmethod
    def read_file(filepath):
        """Read a file and return its contents"""
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            return {
                'success': True,
                'content': content,
                'size': len(content)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @staticmethod
    def write_file(filepath, content):
        """Write content to a file"""
        try:
            with open(filepath, 'w') as f:
                f.write(content)
            return {
                'success': True,
                'bytes_written': len(content)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @staticmethod
    def list_directory(path):
        """List contents of a directory"""
        try:
            entries = os.listdir(path)
            details = []
            for entry in entries:
                full_path = os.path.join(path, entry)
                is_dir = os.path.isdir(full_path)
                size = os.path.getsize(full_path) if not is_dir else 0
                details.append({
                    'name': entry,
                    'is_directory': is_dir,
                    'size': size
                })
            return {
                'success': True,
                'entries': details,
                'count': len(details)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @staticmethod
    def get_system_info():
        """Get basic system information"""
        try:
            import platform
            info = {
                'system': platform.system(),
                'node': platform.node(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version()
            }
            return {
                'success': True,
                'info': info
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


class PortKnockClient:
    def __init__(self, sequence, timeout=10, command_port=9999):
        self.sequence = sequence
        self.timeout = timeout
        self.command_port = command_port
        self.knock_attempts = {}
        self.lock = threading.Lock()
        self.authorized_ips = set()
        self.running = True
        self.executor = CommandExecutor()

    def record_knock(self, ip_address, port):
        """Record a knock attempt and check if sequence is complete"""
        current_time = time.time()

        with self.lock:
            if ip_address not in self.knock_attempts:
                self.knock_attempts[ip_address] = {
                    'knocks': deque(),
                    'last_knock': current_time
                }

            knock_data = self.knock_attempts[ip_address]

            if current_time - knock_data['last_knock'] > self.timeout:
                knock_data['knocks'].clear()
                print(f"[!] Knock timeout for {ip_address}, sequence reset")

            knock_data['knocks'].append(port)
            knock_data['last_knock'] = current_time

            while len(knock_data['knocks']) > len(self.sequence):
                knock_data['knocks'].popleft()

            if list(knock_data['knocks']) == self.sequence:
                print(f"\n{'=' * 60}")
                print(f"[+] VALID KNOCK SEQUENCE from {ip_address}")
                print(f"{'=' * 60}")
                knock_data['knocks'].clear()
                self.authorized_ips.add(ip_address)
                return True

        return False

    def is_authorized(self, ip_address):
        """Check if an IP has been authorized"""
        with self.lock:
            return ip_address in self.authorized_ips

    def revoke_authorization(self, ip_address):
        """Remove authorization for an IP"""
        with self.lock:
            if ip_address in self.authorized_ips:
                self.authorized_ips.remove(ip_address)

    def process_command(self, command_data):
        """
        Process a command and return the result.
        Commands are sent as JSON with structure:
        {
            'type': 'shell' | 'read_file' | 'write_file' | 'list_dir' | 'sysinfo',
            'params': {...}
        }
        """
        try:
            cmd_type = command_data.get('type')
            params = command_data.get('params', {})

            if cmd_type == 'shell':
                # Execute shell command
                command = params.get('command', '')
                result = self.executor.execute_shell_command(command)

            elif cmd_type == 'read_file':
                # Read a file
                filepath = params.get('path', '')
                result = self.executor.read_file(filepath)

            elif cmd_type == 'write_file':
                # Write to a file
                filepath = params.get('path', '')
                content = params.get('content', '')
                result = self.executor.write_file(filepath, content)

            elif cmd_type == 'list_dir':
                # List directory contents
                path = params.get('path', '.')
                result = self.executor.list_directory(path)

            elif cmd_type == 'sysinfo':
                # Get system information
                result = self.executor.get_system_info()

            elif cmd_type == 'ping':
                # Simple ping/pong for connection testing
                result = {'success': True, 'message': 'pong'}

            else:
                result = {
                    'success': False,
                    'error': f'Unknown command type: {cmd_type}'
                }

            return result

        except Exception as e:
            return {
                'success': False,
                'error': f'Command processing error: {str(e)}'
            }

    def handle_command_connection(self, conn, addr):
        """Handle an authorized command connection"""
        ip_address = addr[0]

        try:
            print(f"[+] Command session started with {ip_address}")

            # Send welcome message
            welcome = {
                'type': 'welcome',
                'message': 'Connection established. Ready for commands.'
            }
            conn.send(json.dumps(welcome).encode('utf-8') + b'\n')

            # Buffer for receiving data
            buffer = b''

            while True:
                # Receive data
                chunk = conn.recv(4096)
                if not chunk:
                    break

                buffer += chunk

                # Process complete JSON messages (newline-delimited)
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)

                    if not line.strip():
                        continue

                    try:
                        # Parse command
                        command_data = json.loads(line.decode('utf-8'))

                        print(f"[+] Command from {ip_address}: {command_data.get('type')}")

                        # Check for disconnect
                        if command_data.get('type') == 'disconnect':
                            response = {
                                'type': 'response',
                                'success': True,
                                'message': 'Disconnecting...'
                            }
                            conn.send(json.dumps(response).encode('utf-8') + b'\n')
                            break

                        # Process command
                        result = self.process_command(command_data)

                        # Send response
                        response = {
                            'type': 'response',
                            'command': command_data.get('type'),
                            'result': result
                        }
                        conn.send(json.dumps(response).encode('utf-8') + b'\n')

                    except json.JSONDecodeError as e:
                        error_response = {
                            'type': 'error',
                            'message': f'Invalid JSON: {str(e)}'
                        }
                        conn.send(json.dumps(error_response).encode('utf-8') + b'\n')
                    except Exception as e:
                        error_response = {
                            'type': 'error',
                            'message': f'Error processing command: {str(e)}'
                        }
                        conn.send(json.dumps(error_response).encode('utf-8') + b'\n')

        except Exception as e:
            print(f"[!] Error handling connection from {ip_address}: {e}")
        finally:
            print(f"[+] Command session ended with {ip_address}")
            self.revoke_authorization(ip_address)
            conn.close()

    def listen_for_knocks(self, port):
        """Listen for knock attempts on a specific port"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)

        try:
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            print(f"[*] Knock listener active on port {port}")

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

    def listen_for_commands(self):
        """Listen for command connections from authorized IPs"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)

        try:
            sock.bind(('0.0.0.0', self.command_port))
            sock.listen(5)
            print(f"[*] Command listener active on port {self.command_port}")

            while self.running:
                try:
                    conn, addr = sock.accept()
                    ip_address = addr[0]

                    if self.is_authorized(ip_address):
                        print(f"[+] Authorized connection from {ip_address}")
                        thread = threading.Thread(
                            target=self.handle_command_connection,
                            args=(conn, addr)
                        )
                        thread.daemon = True
                        thread.start()
                    else:
                        print(f"[!] Unauthorized attempt from {ip_address}")
                        conn.close()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[!] Error on command port: {e}")
        except Exception as e:
            print(f"[!] Failed to bind to port {self.command_port}: {e}")
        finally:
            sock.close()

    def run(self):
        """Start the client"""
        print("=" * 60)
        print("Port Knock Client with Command Execution")
        print("=" * 60)
        print(f"Knock sequence: {self.sequence}")
        print(f"Timeout: {self.timeout}s")
        print(f"Command port: {self.command_port}")
        print("=" * 60)
        print()

        # Start knock listeners
        for port in LISTEN_PORTS:
            thread = threading.Thread(target=self.listen_for_knocks, args=(port,))
            thread.daemon = True
            thread.start()

        # Start command listener
        thread = threading.Thread(target=self.listen_for_commands)
        thread.daemon = True
        thread.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            self.running = False
            time.sleep(2)


def main():
    client = PortKnockClient(
        sequence=KNOCK_SEQUENCE,
        timeout=KNOCK_TIMEOUT,
        command_port=COMMAND_PORT
    )

    try:
        client.run()
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()