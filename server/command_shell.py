import cmd
from server import TCPServer
import shlex
import argparse
import threading
import socket
import sys
import time
import atexit


def intro():
    print("""

█████   ██████ ███████     ██       ██████   ██████ ██   ██ 
██   ██ ██      ██          ██      ██    ██ ██      ██  ██  
███████ ██      █████       ██      ██    ██ ██      █████   
██   ██ ██      ██          ██      ██    ██ ██      ██  ██  
██   ██  ██████ ███████     ███████  ██████   ██████ ██   ██ 


    """)


class CommandShell(cmd.Cmd):
    def __init__(self):
        super().__init__()
        self.intro = intro()
        self.prompt = 'AceLock> '
        self.server_object = None
        self.current_client = None
        self.server_thread = None
        self.server_running = False
        self._lock = threading.Lock()

        # Register cleanup function to ensure proper shutdown
        atexit.register(self.cleanup)

    def cleanup(self):
        """Ensure server is properly stopped when program exits"""
        if self.server_running and self.server_object:
            try:
                print("[*] Cleaning up server resources...")
                self.server_object.stop()

                # Don't join the thread here learned that the hard way
                with self._lock:
                    self.server_running = False
            except:
                pass

    def do_start_server(self, args):
        """
        Start the TCP server with specified host and port
        Usage: start_server [-host HOST] [-port PORT]
        """
        if self.server_running:
            print("[!] Server is already running")
            return

        parser = argparse.ArgumentParser(description='Start the server')
        parser.add_argument('-host', default='0.0.0.0', help='Server host address')
        parser.add_argument('-port', type=int, default=8000, help='Server port number')

        try:
            parsed_args = parser.parse_args(shlex.split(args))
            self.server_object = TCPServer(parsed_args.host, parsed_args.port)

            # Create and start the server thread
            self.server_thread = threading.Thread(
                target=self._run_server,
                name="ServerThread"
            )
            self.server_thread.daemon = True  # IMPORTANT: Make thread exit when main program exits

            with self._lock:
                self.server_running = True

            self.server_thread.start()
            time.sleep(0.5)

            if self.server_running:
                print(f"[+] Server started on {parsed_args.host}:{parsed_args.port}")
            else:
                print("[!] Failed to start server")
        except Exception as e:
            print(f"[!] Error starting server: {e}")
            with self._lock:
                self.server_running = False

    def _run_server(self):
        """Thread target function to run the server and handle exceptions"""
        try:
            self.server_object.start()
        except Exception as e:
            print(f"[!] Server error: {e}")
        finally:
            with self._lock:
                self.server_running = False

    def do_server_status(self, args):
        """
        Display the current status of the server
        Usage: server_status
        """
        if self.server_running:
            print("[+] Server is running")
            if self.server_object and hasattr(self.server_object, 'clients'):
                print(f"[+] Connected clients: {len(self.server_object.clients)}")
        else:
            print("[+] Server is not running")

    def do_list_clients(self, args):
        """
        List all connected clients with their addresses and connection details
        Usage: list_clients
        """
        if not self.server_running:
            print("[!] Server not running. Use start_server first.")
            return

        if not self.server_object or not self.server_object.clients:
            print("[!] No clients connected.")
            return

        print("\nConnected Clients:")
        print("==================")
        for i, (address, client_socket) in enumerate(self.server_object.clients.items()):
            # Check if this is the current client
            current = " (current)" if self.current_client and self.current_client == client_socket else ""

            # Get client IP and port
            ip, port = address

            # Get socket details
            try:
                socket_family = socket.AF_INET if client_socket.family == socket.AF_INET else "Unknown"
                socket_type = "TCP" if client_socket.type == socket.SOCK_STREAM else "UDP"
                is_encrypted = "Yes" if hasattr(client_socket, 'context') else "No"
            except:
                socket_family = "Unknown"
                socket_type = "Unknown"
                is_encrypted = "Unknown"

            print(f"{i + 1}. Client: {ip}:{port}{current}")
            print(f"   Connection: {socket_type} ({socket_family})")
            print(f"   Encrypted: {is_encrypted}")
            print(f"   Connected since: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print()

        # Print summary
        print(f"Total clients: {len(self.server_object.clients)}")
        print()
+
    #send command

    def do_stop_server(self, args):
        """
        Stop the server
        Usage: stop_server
        """
        if not self.server_running:
            print("[!] Server is not running")
            return

        try:
            print("[*] Stopping server...")
            self.server_object.stop()

            with self._lock:
                self.server_running = False

            print("[+] Server stopped")

            # Reset client connection if server is stopped
            self.current_client = None
              Exception as e:
            print(f"[!] Error stopping server: {e}")

    def do_exit(self, args):
        """
        Stop the server and exit the command shell
        Usage: stop
        """
        if self.server_running:
            self.do_stop_server(args)
        print("[+] Exiting AceLock command shell...")
        return True  # Return True to exit the cmd loop
