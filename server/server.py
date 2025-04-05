import socket
import ssl
import threading


class ClientHandler(threading.Thread):
    def __init__(self, client_socket, client_address, server):
        """
        Handles communication with a single client in a separate thread.
        """
        super().__init__()
        self.client_socket = client_socket  # The client's socket connection
        self.client_address = client_address  # The client's address
        self.server = server  # Reference to the main server

    def run(self):
        """
        Handles the receiving and sending of messages for this client.
        """
        print(f"[+] Secure connection established with {self.client_address}")
        self.server.add_client(self.client_address, self.client_socket)

        try:
            while True:
                # Receive data from the client
                data = self.client_socket.recv(1024).decode('utf-8')
                if not data:
                    break  # Exit loop if no data is received (client disconnected)
                print(f"[Client {self.client_address}] {data}")
                response = f"Echo: {data}"
                # Send an echo response back to the client
                self.client_socket.sendall(response.encode('utf-8'))
        except ConnectionResetError:
            print(f"[-] Connection lost with {self.client_address}")
        finally:
            # Remove client from active connections and close socket
            self.server.remove_client(self.client_address)
            self.client_socket.close()
            print(f"[+] Connection closed for {self.client_address}")


class TCPServer:
    def __init__(self, host, port, max_clients=5, certfile='../ssl_deets/server.crt', keyfile='../ssl_deets/server.key'):
        """
        Initializes the TCP server with SSL encryption.
        """
        if certfile is None:
            host = "0.0.0.0"
        if port is None:
            port = 8000

        self.host = host
        self.port = port
        self.max_clients = max_clients
        self.clients = {}  # Dictionary to store active client connections
        self.current_client = None  # Stores the currently selected client for communication

        # Create a standard TCP socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(self.max_clients)

        # Wrap the socket with SSL for secure communication
        self.server_socket = ssl.wrap_socket(self.server_socket, certfile=certfile, keyfile=keyfile, server_side=True)

        print(f"[*] Secure server started on {self.host}:{self.port}")

    def add_client(self, address, client_socket):
        """
        Stores the client connection in the active clients dictionary.
        """
        self.clients[address] = client_socket
        print(f"[*] Client {address} added to active connections")

    def remove_client(self, address):
        """
        Removes the client from the active clients dictionary when they disconnect.
        """
        if address in self.clients:
            del self.clients[address]
            print(f"[*] Client {address} removed from active connections")

    def switch_connection(self, target_address):
        """
        Allows switching between connected clients.
        """
        if target_address in self.clients:
            self.current_client = self.clients[target_address]
            print(f"[*] Switched to client {target_address}")
        else:
            print(f"[!] Client {target_address} not found")

    def send_command(self, command):
        """
        Sends a command to the currently selected client.
        """
        if self.current_client:
            try:
                self.current_client.sendall(command.encode('utf-8'))
            except Exception as e:
                print(f"[!] Error sending command: {e}")
        else:
            print("[!] No client selected. Use switch_connection() first.")

    def start(self):
        """
        Starts the server to accept and handle client connections.
        """
        try:
            while True:
                # Accept a new client connection
                client_socket, client_address = self.server_socket.accept()

                # Create a new thread for the client
                client_handler = ClientHandler(client_socket, client_address, self)
                client_handler.start()
        except KeyboardInterrupt:
            print("\n[!] Server shutting down...")
        finally:
            # Close the server socket before shutting down
            self.server_socket.close()
            print("[*] Secure server closed")


