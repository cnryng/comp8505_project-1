#!/usr/bin/env python3
"""
Client Program - Port Knock Listener
Waits for a specific port knocking sequence before accepting commands.
"""

import socket
import threading
import time
from collections import deque
import sys

# Configuration
KNOCK_SEQUENCE = [7000, 8000, 9000]  # Required knock sequence
KNOCK_TIMEOUT = 10  # Seconds to complete the sequence
COMMAND_PORT = 9999  # Port for command communication after successful knock
LISTEN_PORTS = [7000, 8000, 9000]  # Ports to monitor for knocks

class PortKnockClient:
    def __init__(self, sequence, timeout=10, command_port=9999):
        self.sequence = sequence
        self.timeout = timeout
        self.command_port = command_port
        self.knock_attempts = {}  # Track knocks by IP
        self.lock = threading.Lock()
        self.authorized_ips = set()  # IPs that have successfully knocked
        self.running = True
        
    def record_knock(self, ip_address, port):
        """Record a knock attempt and check if sequence is complete"""
        current_time = time.time()
        
        with self.lock:
            # Initialize knock tracking for new IP
            if ip_address not in self.knock_attempts:
                self.knock_attempts[ip_address] = {
                    'knocks': deque(),
                    'last_knock': current_time
                }
            
            knock_data = self.knock_attempts[ip_address]
            
            # Clear old knocks if timeout exceeded
            if current_time - knock_data['last_knock'] > self.timeout:
                knock_data['knocks'].clear()
                print(f"[!] Knock timeout for {ip_address}, sequence reset")
            
            # Add new knock
            knock_data['knocks'].append(port)
            knock_data['last_knock'] = current_time
            
            # Keep only last N knocks
            while len(knock_data['knocks']) > len(self.sequence):
                knock_data['knocks'].popleft()
            
            # Check if sequence matches
            if list(knock_data['knocks']) == self.sequence:
                print(f"\n{'='*60}")
                print(f"[+] VALID KNOCK SEQUENCE from {ip_address}")
                print(f"{'='*60}")
                knock_data['knocks'].clear()
                self.authorized_ips.add(ip_address)
                return True
        
        return False
    
    def is_authorized(self, ip_address):
        """Check if an IP has been authorized via knock sequence"""
        with self.lock:
            return ip_address in self.authorized_ips
    
    def revoke_authorization(self, ip_address):
        """Remove authorization for an IP"""
        with self.lock:
            if ip_address in self.authorized_ips:
                self.authorized_ips.remove(ip_address)
    
    def listen_for_knocks(self, port):
        """Listen for knock attempts on a specific port"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)  # Timeout to allow checking self.running
        
        try:
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            print(f"[*] Knock listener active on port {port}")
            
            while self.running:
                try:
                    conn, addr = sock.accept()
                    ip_address = addr[0]
                    
                    print(f"[+] Knock detected on port {port} from {ip_address}")
                    
                    # Record knock and check sequence
                    self.record_knock(ip_address, port)
                    
                    conn.close()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[!] Error on knock port {port}: {e}")
                    
        except Exception as e:
            print(f"[!] Failed to bind knock listener to port {port}: {e}")
        finally:
            sock.close()
    
    def handle_command_connection(self, conn, addr):
        """Handle an authorized command connection"""
        ip_address = addr[0]
        
        try:
            print(f"[+] Command session started with {ip_address}")
            
            # Send welcome message
            conn.send(b"[*] Connection established. Awaiting commands...\n")
            
            while True:
                # Receive command
                data = conn.recv(4096)
                if not data:
                    break
                
                command = data.decode('utf-8').strip()
                print(f"[+] Received command from {ip_address}: {command}")
                
                # Process commands
                if command.lower() == 'disconnect':
                    response = "[*] Disconnecting...\n"
                    conn.send(response.encode('utf-8'))
                    break
                elif command.lower() == 'status':
                    response = "[*] Client is running normally\n"
                    conn.send(response.encode('utf-8'))
                elif command.lower().startswith('echo '):
                    message = command[5:]
                    response = f"[*] Echo: {message}\n"
                    conn.send(response.encode('utf-8'))
                else:
                    response = f"[*] Command received: {command}\n[*] (Command processing not implemented)\n"
                    conn.send(response.encode('utf-8'))
                    
        except Exception as e:
            print(f"[!] Error handling command connection from {ip_address}: {e}")
        finally:
            print(f"[+] Command session ended with {ip_address}")
            self.revoke_authorization(ip_address)
            conn.close()
    
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
                    
                    # Check authorization
                    if self.is_authorized(ip_address):
                        print(f"[+] Authorized connection from {ip_address}")
                        # Handle in separate thread
                        thread = threading.Thread(
                            target=self.handle_command_connection,
                            args=(conn, addr)
                        )
                        thread.daemon = True
                        thread.start()
                    else:
                        print(f"[!] Unauthorized connection attempt from {ip_address}")
                        conn.close()
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[!] Error on command port: {e}")
                    
        except Exception as e:
            print(f"[!] Failed to bind command listener to port {self.command_port}: {e}")
        finally:
            sock.close()
    
    def run(self):
        """Start the client and all listeners"""
        print("="*60)
        print("Port Knock Client - Waiting for connections")
        print("="*60)
        print(f"Knock sequence required: {self.sequence}")
        print(f"Knock timeout: {self.timeout} seconds")
        print(f"Command port: {self.command_port}")
        print("="*60)
        print()
        
        # Start knock listeners
        knock_threads = []
        for port in LISTEN_PORTS:
            thread = threading.Thread(target=self.listen_for_knocks, args=(port,))
            thread.daemon = True
            thread.start()
            knock_threads.append(thread)
        
        # Start command listener
        command_thread = threading.Thread(target=self.listen_for_commands)
        command_thread.daemon = True
        command_thread.start()
        
        # Keep main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down client...")
            self.running = False
            time.sleep(2)  # Give threads time to clean up

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
