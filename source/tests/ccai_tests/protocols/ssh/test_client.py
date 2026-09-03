
import unittest
from unittest.mock import MagicMock, patch
import socket

from ccai.protocols.ssh.sshclient import SshClient
from ccai.protocols.ssh.sshtransport import SshTransport
from ccai.protocols.ssh.sshconnection import SshConnection
from ccai.protocols.ssh.sshauth import SshAuthAgent

class TestSshClient(unittest.TestCase):
    def setUp(self):
        self.client = SshClient()

    def tearDown(self):
        if self.client.transport:
            self.client.transport.active = False


    @patch('ccai.protocols.ssh.sshclient.socket.create_connection')
    @patch('ccai.protocols.ssh.sshclient.SshTransport')
    @patch('ccai.protocols.ssh.sshclient.SshConnection')
    @patch('ccai.protocols.ssh.sshclient.SshAuthAgent')
    def test_connect_password(self, MockAuth, MockConn, MockTransport, MockSocket):
        # Setup mocks
        mock_sock = MagicMock()
        MockSocket.return_value = mock_sock
        
        mock_transport = MagicMock()
        mock_transport.kex_error = None
        mock_transport.active = True
        mock_transport.kex_complete.wait.return_value = True
        MockTransport.return_value = mock_transport
        
        mock_conn = MagicMock()
        MockConn.return_value = mock_conn
        
        mock_auth = MagicMock()
        MockAuth.return_value = mock_auth
        
        # Call connect
        self.client.connect('hostname', username='user', password='password')
        
        # Verify socket creation
        MockSocket.assert_called_with(('hostname', 22), timeout=None)
        
        # Verify SshTransport creation and connection
        MockTransport.assert_called_with(mock_sock)
        mock_transport.connect.assert_called_once()
        
        # Verify Auth
        MockAuth.assert_called_with(mock_transport)
        mock_auth.authenticate_password.assert_called_with('user', 'password')
        
        # Verify SshConnection layer
        MockConn.assert_called_with(mock_transport)
        self.assertIsNotNone(self.client.connection)
        
        # Stop thread loop
        mock_transport.active = False

    @patch('ccai.protocols.ssh.sshclient.SshSFTPClient')
    def test_open_sftp(self, MockSftp):
        # A real SshSFTPClient would block reading the SFTP VERSION reply from the
        # channel, so the class is patched and the wiring is what gets verified.
        self.client.connection = MagicMock()
        mock_chan = MagicMock()
        self.client.connection.open_channel.return_value = mock_chan
        MockSftp.return_value = MagicMock(channel=mock_chan)

        sftp = self.client.open_sftp()

        self.client.connection.open_channel.assert_called_with('session')
        MockSftp.assert_called_once_with(mock_chan)
        self.assertIsNotNone(sftp)
        self.assertEqual(sftp.channel, mock_chan)

    def test_exec_command(self):
        # Mock connection and channel
        self.client.connection = MagicMock()
        mock_chan = MagicMock()
        self.client.connection.open_channel.return_value = mock_chan
        
        # Call exec_command
        stdin, stdout, stderr = self.client.exec_command('ls -la')
        
        # Verify channel opened and exec requested
        self.client.connection.open_channel.assert_called_with('session')
        mock_chan.request_exec.assert_called_with('ls -la')
        
        # Verify returns (currently returns None, chan, None mock)
        self.assertEqual(stdout, mock_chan)

    def test_invoke_shell(self):
        # Mock connection and channel
        self.client.connection = MagicMock()
        mock_chan = MagicMock()
        self.client.connection.open_channel.return_value = mock_chan
        
        # Call invoke_shell
        chan = self.client.invoke_shell()
        
        # Verify channel opened and shell requested
        self.client.connection.open_channel.assert_called_with('session')
        mock_chan.request_pty.assert_called_with(term='vt100', width=80, height=24)
        mock_chan.request_shell.assert_called_once()
        
        self.assertEqual(chan, mock_chan)

    @patch('ccai.protocols.ssh.sshclient.SshTransport')
    def test_close(self, MockTransport):
        mock_transport = MagicMock()
        self.client.transport = mock_transport
        
        self.client.close()
        
        mock_transport.close.assert_called_once()    
