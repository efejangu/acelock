import socket
import ssl
import threading
import os
import time
import logging

# --- Logging Setup ---
# Configure logging for the server module
log_format = '%(asctime)s - %(threadName)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format)
server_logger = logging.getLogger()


class TCPServer:
    """
    A thread-safe TLS-enabled TCP server designed for C2 operations.
    Handles client connections, provides mechanisms for listing clients,
    sending files, and disconnecting clients safely.
    """
    def __init__(self, host="0.0.0.0", port=8000, certfile='server.crt', keyfile='server.key'):
        """
        Initializes the server.

        Args:
            host (str): Host address to bind to.
            port (int): Port number to listen on.
            certfile (str): Path to the SSL certificate file.
            keyfile (str): Path to the SSL key file.
        """
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.server_socket = None # The main listening socket
        # Stores { address: (socket, connection_time) }
        self.clients = {}
        # Lock for ensuring thread-safe access to the clients dictionary
        self._clients_lock = threading.Lock()
        # Event to signal the server's main loop to stop gracefully
        self._stop_event = threading.Event()

        # --- END SECURITY WARNING ---

    def start(self, started_event):
        """
        Starts the server's main listening loop. This should be run in a thread.
        Signals the provided 'started_event' when successfully bound and listening.

        Args:
            started_event (threading.Event): An event object that will be set
                                             when the server is ready to accept connections.

        """
        server_logger.info(f"Initializing secure server on {self.host}:{self.port}...")
        try:
            # 1. Create SSL Context
            # Use PROTOCOL_TLS_SERVER for modern compatibility, automatically negotiates highest version
            # *** FIX APPLIED HERE ***
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # ************************
            # Load server certificate and private key
            context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
            # Optional: Set preferred ciphers (example)
            # context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!eNULL:!MD5:!DSS')

            # --- Optional: Client Certificate Verification (Mutual TLS) ---
            # To enable, uncomment and provide CA cert path:
            # context.verify_mode = ssl.CERT_REQUIRED
            # context.load_verify_locations(cafile='path/to/client_ca_bundle.pem')
            # server_logger.info("Client certificate verification enabled (Mutual TLS).")
            # --- End Optional ---


            # 2. Create and Bind Socket
            bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Allow address reuse quickly after server restart
            bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bindsocket.bind((self.host, self.port))
            bindsocket.listen(5) # Listen backlog of 5 connections
            server_logger.info(f"Socket bound to {self.host}:{self.port} and listening.")


            # 3. Wrap Listening Socket with TLS
            self.server_socket = context.wrap_socket(bindsocket, server_side=True)
            server_logger.info("Server socket wrapped with TLS.")


            # 4. Signal Server Readiness <<-- Fix for Startup Synchronization
            started_event.set()
            server_logger.info("Server startup complete. Ready to accept connections.")


            # 5. Main Accept Loop <<-- Fix for Graceful Shutdown
            self._stop_event.clear()
            while not self._stop_event.is_set():
                 try:
                     # Set a timeout on accept() to allow checking the stop event periodically
                     self.server_socket.settimeout(1.0) # Check every 1 second
                     try:
                          # Accept new connection
                          client_socket, client_address = self.server_socket.accept()
                          # Important: Reset timeout after successful accept
                          self.server_socket.settimeout(None)

                          server_logger.info(f"Accepted connection from {client_address}")
                          # Add client to the managed dictionary <<-- Stores Timestamp
                          self.add_client(client_address, client_socket)

                     except socket.timeout:
                          # Timeout is expected, just loop again to check stop_event
                          continue
                     except (ssl.SSLError, ConnectionAbortedError, OSError) as accept_err:
                          # Handle errors during the accept process
                          server_logger.error(f"Error accepting connection: {accept_err}", exc_info=False) # Avoid excessive logging detail in loop
                          time.sleep(0.5) # Prevent fast spinning on repeated errors
                          continue # Try accepting again

                 except Exception as inner_e:
                      # Catch unexpected errors within the loop itself
                      server_logger.error(f"Critical error in server accept loop: {inner_e}", exc_info=True)
                      # Decide if error is fatal or recoverable
                      # For simplicity here, we'll break the loop on unexpected errors
                      break

        except (ssl.SSLError, OSError, socket.error) as e:
            server_logger.critical(f"Fatal server initialization error: {e}", exc_info=True)
            started_event.set() # Signal event anyway so caller doesn't hang forever
            raise # Re-raise the exception to be caught by the calling thread runner
        except Exception as e:
            server_logger.critical(f"Unexpected fatal server error during startup: {e}", exc_info=True)
            started_event.set() # Signal event anyway
            raise
        finally:
            server_logger.info("Server accept loop terminating.")
            # Final cleanup of the main server socket
            if self.server_socket:
                 try:
                     self.server_socket.close()
                     self.server_socket = None
                     server_logger.info("Main server socket closed.")
                 except Exception as close_err:
                     server_logger.error(f"Error closing main server socket: {close_err}", exc_info=True)

    def add_client(self, address, client_socket):
        """
        Adds a client connection to the internal dictionary, including connection time. Thread-safe.

        Args:
            address (tuple): The client's address (ip, port).
            client_socket (socket.socket): The client's socket object (TLS wrapped).
        """
        connection_time = time.time() # <<-- Fix: Store Timestamp
        with self._clients_lock: # <<-- Fix: Thread Safety
            self.clients[address] = (client_socket, connection_time)
        server_logger.info(f"Client {address} added to active connections at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(connection_time))}.")

    def disconnect_client(self, address):
        """
        Gracefully closes a client's socket and removes it from the active connections map. Thread-safe.

        Args:
            address (tuple): The address (ip, port) of the client to disconnect.

        Returns:
            bool: True if the client was found and disconnection was attempted, False otherwise.
        """
        server_logger.info(f"Attempting to disconnect client {address}...")
        socket_to_close = None
        with self._clients_lock: # <<-- Fix: Thread Safety
             # Use pop to atomically get the socket and remove the entry
             client_info = self.clients.pop(address, None) # Returns None if key doesn't exist
             if client_info:
                  socket_to_close, _ = client_info # Unpack the tuple
                  server_logger.info(f"Client {address} removed from active map for disconnection.")
             else:
                  server_logger.warning(f"Attempted to disconnect client {address}, but it was not found in the active map.")
                  return False # Client not found

        # Perform socket operations outside the lock
        if socket_to_close:
            try:
                # Politely ask the socket to shut down read/write operations
                # This might fail if the socket is already dead, which is fine.
                socket_to_close.shutdown(socket.SHUT_RDWR)
            except (OSError, socket.error, ssl.SSLError) as shutdown_err:
                 # Log non-critical errors during shutdown
                 server_logger.debug(f"Socket shutdown error for {address} (may be okay): {shutdown_err}")
            except Exception as e:
                 server_logger.error(f"Unexpected error during socket shutdown for {address}: {e}")

            try:
                # Close the socket resource
                socket_to_close.close()
                server_logger.info(f"Socket closed successfully for {address}")
                return True # Indicate disconnection attempt was made
            except (OSError, socket.error, ssl.SSLError) as close_err:
                server_logger.error(f"Error closing socket for {address}: {close_err}", exc_info=True)
                return False # Indicate failure during close
            except Exception as e:
                 server_logger.error(f"Unexpected error closing socket for {address}: {e}")
                 return False
        else:
             # This case should technically not be reached due to the check above, but added for safety
             return False


    def get_clients(self):
        """
        Returns a copy of the current clients dictionary. Thread-safe.

        Returns:
            dict: A dictionary containing { address: (socket, connection_time) }
        """
        with self._clients_lock: # <<-- Fix: Thread Safety
            # Return a copy so the caller can iterate without holding the lock
            return self.clients.copy()

    def send_file(self, local_filepath, client_address):
        """
        Sends a file to a specific client using a simple header protocol. Thread-safe.

        Args:
            local_filepath (str): The path to the file on the server to send.
            client_address (tuple): The address of the target client.

        Returns:
            bool: True if the file was sent successfully, False otherwise.
        """
        server_logger.info(f"Request to send file '{local_filepath}' to {client_address}")
        socket_to_use = None
        # 1. Get socket safely
        with self._clients_lock: # <<-- Fix: Thread Safety
            client_info = self.clients.get(client_address) # Use get for safe lookup
            if client_info:
                socket_to_use, _ = client_info
            else:
                server_logger.error(f"send_file failed: Client {client_address} not found.")
                return False

        # 2. Perform sending outside the lock
        try:
            # Check file exists before proceeding
            if not os.path.isfile(local_filepath):
                 server_logger.error(f"send_file failed: Local file not found: {local_filepath}")
                 return False

            filesize = os.path.getsize(local_filepath)
            filename = os.path.basename(local_filepath)

            # <<-- Fix: Simple File Transfer Protocol Header -->>
            header = f"FILE {filename} {filesize}\n".encode('utf-8')
            server_logger.debug(f"Sending header to {client_address}: {header.decode()}")
            socket_to_use.sendall(header)

            # Optional: Could add a step here to wait for client ACK "READY" before sending data

            server_logger.info(f"Sending file data for '{filename}' ({filesize} bytes) to {client_address}")
            sent_bytes = 0
            with open(local_filepath, 'rb') as f:
                while chunk := f.read(4096): # Read and send in chunks
                    socket_to_use.sendall(chunk)
                    sent_bytes += len(chunk)
            server_logger.info(f"Finished sending file '{filename}' ({sent_bytes}/{filesize} bytes) to {client_address}")
            return True

        except FileNotFoundError:
             # This check is redundant now but kept for safety
             server_logger.error(f"send_file failed: Local file not found: {local_filepath}")
             return False
        except (socket.error, ssl.SSLError, BrokenPipeError, ConnectionResetError) as e:
             server_logger.error(f"send_file failed: Socket error sending to {client_address}: {e}", exc_info=True)
             # Assume client is dead on send error, attempt cleanup
             self.disconnect_client(client_address)
             return False
        except Exception as e:
             server_logger.error(f"send_file failed: Unexpected error sending to {client_address}: {e}", exc_info=True)
             # Attempt cleanup on unexpected errors too
             self.disconnect_client(client_address)
             return False

    def stop(self):
        """
        Signals the server thread to stop accepting new connections and disconnects
        all currently connected clients gracefully. Thread-safe.
        """
        server_logger.info("Stop requested. Signaling server loop to exit...")
        # 1. Signal the accept loop to stop <<-- Fix for Graceful Shutdown
        self._stop_event.set()

        # 2. Close the main server socket to interrupt accept() immediately <<-- Fix
        # Needs to be done carefully to avoid race conditions if called multiple times
        server_sock_ref = self.server_socket
        if server_sock_ref:
            try:
                # Optional: Attempt to unblock accept() by connecting briefly to self
                # Works only if host is not 0.0.0.0 or if connecting to 127.0.0.1 works
                unblock_host = self.host if self.host != '0.0.0.0' else '127.0.0.1'
                try:
                    # Use a timeout to prevent waiting too long if connection fails
                    with socket.create_connection((unblock_host, self.port), timeout=0.1) as temp_sock:
                        server_logger.debug("Briefly connected to self to potentially unblock accept().")
                except Exception:
                    server_logger.debug("Could not connect to self to unblock accept (may be okay).")

                server_sock_ref.close()
                server_logger.info("Main server listening socket closed.")
                self.server_socket = None # Clear reference
            except (OSError, socket.error) as e:
                 server_logger.error(f"Error closing server listening socket during stop: {e}", exc_info=True)

        # 3. Disconnect all active clients <<-- Fix for Graceful Shutdown & Thread Safety
        server_logger.info("Closing all active client connections...")
        # Get a snapshot of addresses to avoid issues while modifying the dictionary
        client_addresses = list(self.get_clients().keys()) # get_clients() is thread-safe
        disconnected_count = 0
        for address in client_addresses:
            # disconnect_client is thread-safe and handles removal+close
            if self.disconnect_client(address):
                 disconnected_count += 1

        server_logger.info(f"Server stop sequence complete. Closed {disconnected_count}/{len(client_addresses)} client connections.")


