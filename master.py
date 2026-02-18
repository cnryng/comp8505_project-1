#!/usr/bin/env python3
"""
Remote Administration Menu
A command menu interface for remote system management.
"""

import sys


class CommandMenu:
    def __init__(self):
        self.running = True
        self.connected = False

    def display_menu(self):
        """Display the main menu options"""
        print("\n" + "=" * 60)
        print("Remote Administration Menu")
        print("=" * 60)

        if self.connected:
            print("Status: CONNECTED")
        else:
            print("Status: DISCONNECTED")

        print("\nAvailable Commands:")
        print("  1. Connect to remote system")
        print("  2. Disconnect from remote system")
        print("  3. Uninstall from remote system")
        print("  4. Start keylogger on remote system")
        print("  5. Stop keylogger on remote system")
        print("  6. Transfer key log file from remote system")
        print("  7. Transfer a file to remote system")
        print("  8. Transfer a file from remote system")
        print("  9. Watch a file on remote system")
        print(" 10. Watch a directory on remote system")
        print(" 11. Run a program on remote system")
        print("  0. Exit")
        print("=" * 60)

    def connect(self):
        """Initiate connection to remote system"""
        if self.connected:
            print("[!] Already connected to remote system")
            return

        print("\n[*] Initiating port knock sequence...")
        print("[*] Establishing secure connection...")
        print("[*] Connection successful!")
        self.connected = True

    def disconnect(self):
        """Disconnect from remote system"""
        if not self.connected:
            print("[!] Not currently connected")
            return

        print("\n[*] Closing connection...")
        print("[*] Disconnected successfully")
        self.connected = False

    def uninstall(self):
        """Uninstall from remote system"""
        if not self.connected:
            print("[!] Must be connected to perform this operation")
            return

        print("\n[*] Sending uninstall command...")
        print("[*] Remote system will clean up and terminate")
        print("[*] Uninstall initiated successfully")
        self.connected = False

    def start_keylogger(self):
        """Start keylogger on remote system"""
        if not self.connected:
            print("[!] Must be connected to perform this operation")
            return

        print("\n[*] Starting keylogger on remote system...")
        print("[*] Keylogger started successfully")

    def stop_keylogger(self):
        """Stop keylogger on remote system"""
        if not self.connected:
            print("[!] Must be connected to perform this operation")
            return

        print("\n[*] Stopping keylogger on remote system...")
        print("[*] Keylogger stopped successfully")

    def transfer_keylog(self):
        """Transfer key log file from remote system"""
        if not self.connected:
            print("[!] Must be connected to perform this operation")
            return

        print("\n[*] Requesting key log file from remote system...")
        print("[*] Receiving file...")
        print("[*] Key log file saved to: ./keylog.txt")

    def transfer_file_to_remote(self):
        """Transfer a file to remote system"""
        if not self.connected:
            print("[!] Must be connected to perform this operation")
            return

        filename = input("Enter local file path to transfer: ")
        remote_path = input("Enter remote destination path: ")

        print(f"\n[*] Transferring {filename} to {remote_path}...")
        print("[*] File transfer complete")

    def transfer_file_from_remote(self):
        """Transfer a file from remote system"""
        if not self.connected:
            print("[!] Must be connected to perform this operation")
            return

        remote_file = input("Enter remote file path: ")
        local_path = input("Enter local destination path: ")

        print(f"\n[*] Requesting {remote_file} from remote system...")
        print(f"[*] Saving to {local_path}...")
        print("[*] File transfer complete")

    def watch_file(self):
        """Watch a file on remote system"""
        if not self.connected:
            print("[!] Must be connected to perform this operation")
            return

        filepath = input("Enter file path to watch: ")

        print(f"\n[*] Setting up file watch on {filepath}...")
        print("[*] File watch active - will notify on changes")

    def watch_directory(self):
        """Watch a directory on remote system"""
        if not self.connected:
            print("[!] Must be connected to perform this operation")
            return

        dirpath = input("Enter directory path to watch: ")

        print(f"\n[*] Setting up directory watch on {dirpath}...")
        print("[*] Directory watch active - will notify on changes")

    def run_program(self):
        """Run a program on remote system"""
        if not self.connected:
            print("[!] Must be connected to perform this operation")
            return

        command = input("Enter command to execute: ")

        print(f"\n[*] Executing command: {command}")
        print("[*] Output:")
        print("    (command output would appear here)")
        print("[*] Command completed")

    def handle_choice(self, choice):
        """Handle menu selection"""
        actions = {
            '1': self.connect,
            '2': self.disconnect,
            '3': self.uninstall,
            '4': self.start_keylogger,
            '5': self.stop_keylogger,
            '6': self.transfer_keylog,
            '7': self.transfer_file_to_remote,
            '8': self.transfer_file_from_remote,
            '9': self.watch_file,
            '10': self.watch_directory,
            '11': self.run_program,
            '0': self.exit_program
        }

        action = actions.get(choice)
        if action:
            action()
        else:
            print("[!] Invalid selection. Please try again.")

    def exit_program(self):
        """Exit the program"""
        if self.connected:
            print("\n[*] Disconnecting before exit...")
            self.disconnect()

        print("\n[*] Exiting program. Goodbye!")
        self.running = False

    def run(self):
        """Main program loop"""
        print("Welcome to Remote Administration System")

        while self.running:
            self.display_menu()
            choice = input("\nEnter your choice: ").strip()
            self.handle_choice(choice)

        sys.exit(0)


def main():
    menu = CommandMenu()
    try:
        menu.run()
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user. Exiting...")
        sys.exit(0)


if __name__ == "__main__":
    main()