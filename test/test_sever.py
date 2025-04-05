from server import server
import time
import socket

def test_server():
    try:
        test_server = server.TCPServer()
        test_server.start()
        time.sleep(5)
        test_server.stop()
    except socket.error as e:
        print(f"Error starting server: /n __________________________ /n{e}")

def test_with_host_and_port():
    try:
        test_server = server.TCPServer('127.0.0.1', 8000)
        test_server.start()
        time.sleep(5)  # Wait for the server to start
        test_server.stop()
    except socket.error as e:
        print(f"Error starting server: /n/n ___________________________/n{e}")


def test_stop():
    pass

