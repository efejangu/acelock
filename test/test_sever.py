import socket
import ssl
import threading
import pytest
from unittest.mock import MagicMock, patch
from server.server import TCPServer

# ... (Your TCPServer and ClientHandler code) ...


@pytest.fixture
def server():
    server = TCPServer()
    yield server
    server.stop()

#
# def test_add_remove_client(server):
#     mock_socket = MagicMock()
#     mock_address = ("127.0.0.1", 12345)
#     server.add_client(mock_address, mock_socket)
#     assert mock_address in server.clients
#     server.remove_client(mock_address)
#     assert mock_address not in server.clients
#
#
# def test_switch_connection(server):
#     mock_socket1 = MagicMock()
#     mock_socket2 = MagicMock()
#     mock_address1 = ("127.0.0.1", 12345)
#     mock_address2 = ("127.0.0.2", 12346)
#     server.add_client(mock_address1, mock_socket1)
#     server.add_client(mock_address2, mock_socket2)
#
#     server.switch_connection(mock_address1)
#     assert server.current_client == mock_socket1
#
#     server.switch_connection(mock_address2)
#     assert server.current_client == mock_socket2

    server.switch_connection(("1.1.1.1", 1234))  # Non-existent client
    assert server.current_client == mock_socket2


@patch('socket.socket')
def test_send_command(mock_socket, server):
    mock_socket_instance = mock_socket.return_value
    mock_socket_instance.sendall = MagicMock()
    mock_address = ("127.0.0.1", 12345)
    server.add_client(mock_address, mock_socket_instance)
    server.switch_connection(mock_address)
    server.send_command("test command")
    mock_socket_instance.sendall.assert_called_once_with(b"test command")


@patch('socket.socket')
@patch('ssl.SSLContext')
def test_server_start_stop(mock_ssl_context, mock_socket):
    mock_socket_instance = mock_socket.return_value
    mock_socket_instance.accept = MagicMock(return_value=(MagicMock(), ("127.0.0.1", 12345)))
    mock_ssl_context.return_value.wrap_socket = MagicMock(return_value=mock_socket_instance)

    server = TCPServer()
    with patch('sys.stdout', new=MagicMock()) as mock_stdout:
        with pytest.raises(KeyboardInterrupt):
            server.start()
        assert mock_socket_instance.accept.called  #Check if server accepted connections
        mock_socket_instance.close.assert_called_once()

    server.stop()
    assert len(server.clients) == 0
    mock_socket_instance.close.assert_called() # Check if server socket is closed


@patch('socket.socket')
def test_client_handler(mock_socket):
    mock_socket_instance = mock_socket.return_value
    mock_socket_instance.recv = MagicMock(side_effect=["test message", b""])
    mock_socket_instance.sendall = MagicMock()
    mock_address = ("127.0.0.1", 12345)
    server = TCPServer() #Server needs to be instantiated to be passed into handler
    client_handler = ClientHandler(mock_socket_instance, mock_address, server)
    client_handler.run()
    mock_socket_instance.recv.assert_called()
    mock_socket_instance.sendall.assert_called_with(b"Echo: test message")
    mock_socket_instance.close.assert_called_once()