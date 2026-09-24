import socket
import time
import unittest
from unittest.mock import MagicMock

from ccai.protocols.ssh import sshconstants
from ccai.protocols.ssh.sshconnection import SshConnection
from ccai.protocols.ssh.sshpacket import SshPacket
from ccai.protocols.ssh.sshtunnel import SshTunnel

from ccai_tests.protocols.ssh.fakepeertransport import FakePeerTransport, PEER_CHANNEL_BASE

PEER_CHANNEL_ID = PEER_CHANNEL_BASE # our first channel is local id 0


class TestSshTunnel(unittest.TestCase):

    def setUp(self):
        self.transport = FakePeerTransport()
        self.connection = SshConnection(self.transport)
        self.transport.connection = self.connection

        self.ssh_client = MagicMock()
        self.ssh_client.get_transport.return_value = self.transport
        self.ssh_client.connection = self.connection

        self.tunnel = SshTunnel._create_internal(self.ssh_client, 0, "db.internal", 5432)
        return

    def tearDown(self):
        self.tunnel.shutdown()
        return

    def _wait_for(self, predicate, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        satisfied = predicate()
        while satisfied is False and time.monotonic() < deadline:
            time.sleep(0.01)
            satisfied = predicate()
        return satisfied

    def _sent_channel_data(self) -> bytes:
        data = b""
        for pkt in self.transport.sent_of_type(sshconstants.SSH_MSG_CHANNEL_DATA):
            pkt._position = 0
            recipient = pkt.get_uint32()
            self.assertEqual(recipient, PEER_CHANNEL_ID)
            data += pkt.get_string()
        return data

    def _dispatch_to_channel(self, message_id: int, data: bytes = None):
        pkt = SshPacket(payload=bytes([message_id]))
        pkt.add_uint32(0) # our local channel id
        if data is not None:
            pkt.add_string(data)
        pkt._position = 0
        self.connection.dispatch_message(pkt)
        return

    def test_tunnel_forwards_data_both_ways_and_closes_with_the_channel(self):
        client = socket.create_connection(("127.0.0.1", self.tunnel.local_port), timeout=5)
        try:
            client.sendall(b"ping")

            # Local socket -> channel
            forwarded = self._wait_for(lambda: self._sent_channel_data() == b"ping")
            self.assertTrue(forwarded, "data written to the tunnel's local port was not sent on the channel")

            # The channel was opened as direct-tcpip to the tunnel's remote end, from the local client's address.
            opens = self.transport.sent_of_type(sshconstants.SSH_MSG_CHANNEL_OPEN)
            self.assertEqual(len(opens), 1)
            opens[0]._position = 0
            self.assertEqual(opens[0].get_string(), b"direct-tcpip")
            opens[0].get_uint32() # sender channel
            opens[0].get_uint32() # window
            opens[0].get_uint32() # max packet
            self.assertEqual(opens[0].get_string(), b"db.internal")
            self.assertEqual(opens[0].get_uint32(), 5432)
            client_host, client_port = client.getsockname()
            self.assertEqual(opens[0].get_string(), client_host.encode())
            self.assertEqual(opens[0].get_uint32(), client_port)

            # Channel -> local socket
            self._dispatch_to_channel(sshconstants.SSH_MSG_CHANNEL_DATA, b"pong")
            self.assertEqual(client.recv(4), b"pong")

            # When the peer closes the channel the local client sees end-of-stream and the close is answered.
            self._dispatch_to_channel(sshconstants.SSH_MSG_CHANNEL_CLOSE)
            self.assertEqual(client.recv(4), b"")
            answered = self._wait_for(
                lambda: len(self.transport.sent_of_type(sshconstants.SSH_MSG_CHANNEL_CLOSE)) == 1)
            self.assertTrue(answered)
        finally:
            client.close()
        return

    def test_tunnel_closes_channel_when_local_client_disconnects(self):
        client = socket.create_connection(("127.0.0.1", self.tunnel.local_port), timeout=5)
        client.sendall(b"hello")
        forwarded = self._wait_for(lambda: self._sent_channel_data() == b"hello")
        self.assertTrue(forwarded)

        client.close()

        closed = self._wait_for(lambda: len(self.transport.sent_of_type(sshconstants.SSH_MSG_CHANNEL_CLOSE)) == 1)
        self.assertTrue(closed, "closing the local connection should close the SSH channel")
        return

    def test_tunnel_passes_peer_eof_to_local_client_and_keeps_forwarding_its_data(self):
        client = socket.create_connection(("127.0.0.1", self.tunnel.local_port), timeout=5)
        try:
            client.sendall(b"request")
            forwarded = self._wait_for(lambda: self._sent_channel_data() == b"request")
            self.assertTrue(forwarded)

            self._dispatch_to_channel(sshconstants.SSH_MSG_CHANNEL_DATA, b"response")
            self._dispatch_to_channel(sshconstants.SSH_MSG_CHANNEL_EOF)

            # The local client gets the data and then end-of-stream ...
            received = b""
            chunk = client.recv(1024)
            while len(chunk) > 0:
                received += chunk
                chunk = client.recv(1024)
            self.assertEqual(received, b"response")

            # ... while its own direction stays open (half-close, RFC 4254 section 5.3).
            client.sendall(b"more")
            forwarded = self._wait_for(lambda: self._sent_channel_data() == b"requestmore")
            self.assertTrue(forwarded, "data sent after the peer's EOF should still be forwarded")
            self.assertEqual(self.transport.sent_of_type(sshconstants.SSH_MSG_CHANNEL_CLOSE), [])
        finally:
            client.close()

        closed = self._wait_for(lambda: len(self.transport.sent_of_type(sshconstants.SSH_MSG_CHANNEL_CLOSE)) == 1)
        self.assertTrue(closed, "closing the local connection should close the SSH channel")
        return


if __name__ == '__main__':
    unittest.main()
