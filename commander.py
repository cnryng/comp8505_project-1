#!/usr/bin/env python3
"""
Commander Program - Connects to client after port knocking
"""

import socket
import time
import sys

class Commander:
    def __init__(self, target_host, knock_sequence, command_port):
        self.target_host = target_host
        self.knock_sequence = knock_sequence
        self.command_port = command_port
        self.connected = False
        self.sock = None
    
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
                time.sleep(0.5)  # Brief delay between knocks
            except Exception as e:
                print(f"✗ ({e})")
        
        print("\n[+] Knock sequence complete!")
        time.sleep(1)  # Give the client time to process
    
    def connect(self):
        """Connect to the command port after knocking"""
        print(f"\n[*] Connecting to command port {self.command_port}...")
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect((self.target_host, self.command_port))
            self.connected = True
            
            # Receive welcome message
            response = self.sock.recv(4096).decode('utf-8')
            print(f"[+] {response.strip()}")
            
            return True
            
        except Exception as e:
            print(f"[!] Failed to connect: {e}")
            self.connected = False
            return False
    
    def send_command(self, command):
        """Send a command to the client"""
        if not self.connected:
            print("[!] Not connected to client")
            return None
        
        try:
            # Send command
            self.sock.send(command.encode('utf-8'))
            
            # Receive response
            response = self.sock.recv(4096).decode('utf-8')
            return response
            
        except Exception as e:
            print(f"[!] Error sending command: {e}")
            self.connected = False
            return None
    
    def disconnect(self):
        """Disconnect from the client"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        self.connected = False
        print("[*] Disconnected")
    
    def interactive_session(self):
        """Run an interactive command session"""
        print("\n" + "="*60)
        print("Interactive Command Session")
        print("="*60)
        print("Enter commands (type 'exit' or 'disconnect' to quit)")
        print("Available test commands: status, echo <message>, disconnect")
        print("="*60)
        print()
        
        while self.connected:
            try:
                command = input("cmd> ").strip()
                
                if not command:
                    continue
                
                if command.lower() in ['exit', 'quit']:
                    command = 'disconnect'
                
                response = self.send_command(command)
                
                if response:
                    print(response.strip())
                
                if command.lower() == 'disconnect':
                    break
                    
            except KeyboardInterrupt:
                print("\n[*] Interrupted by user")
                break
            except Exception as e:
                print(f"[!] Error: {e}")
                break
        
        self.disconnect()

def main():
    if len(sys.argv) > 1:
        target_host = sys.argv[1]
    else:
        target_host = 'localhost'
    
    # Configuration
    knock_sequence = [7000, 8000, 9000]
    command_port = 9999
    
    print("="*60)
    print("Port Knock Commander")
    print("="*60)
    
    commander = Commander(target_host, knock_sequence, command_port)
    
    try:
        # Perform knock sequence
        commander.perform_knock_sequence()
        
        # Connect to command port
        if commander.connect():
            # Run interactive session
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
