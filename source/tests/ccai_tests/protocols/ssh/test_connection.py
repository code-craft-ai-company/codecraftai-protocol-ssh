import unittest
from unittest.mock import MagicMock
from ccai.protocols.ssh.sshconnection import SshConnection
from ccai.protocols.ssh import sshconstants
from ccai.protocols.ssh.sshpacket import SshPacket

class TestConnection(unittest.TestCase):
    def setUp(self):
        self.mock_transport = MagicMock()
        self.connection = SshConnection(self.mock_transport)

    def test_open_channel(self):
        chan = self.connection.open_channel()
        self.assertIsNotNone(chan)
        self.assertEqual(chan.local_id, 0)
        
        # Verify packet sent
        self.mock_transport.send_packet.assert_called()
        args = self.mock_transport.send_packet.call_args[0][0]
        self.assertEqual(args.message_id, sshconstants.SSH_MSG_CHANNEL_OPEN)

    def test_data_transfer(self):
        chan = self.connection.open_channel()
        # Simulate Confirmation
        pkt = SshPacket(payload=bytes([sshconstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION]))
        pkt.add_uint32(chan.local_id)
        pkt.add_uint32(100) # remote id
        pkt.add_uint32(1000) # window
        pkt.add_uint32(1000) # max packet
        pkt._position = 0
        
        self.connection.dispatch_message(pkt)
        self.assertEqual(chan.remote_id, 100)
        self.assertTrue(chan.active)
        
        # Simulate receiving data
        data_pkt = SshPacket(payload=bytes([sshconstants.SSH_MSG_CHANNEL_DATA]))
        data_pkt.add_uint32(chan.local_id)
        data_pkt.add_string("hello")
        data_pkt._position = 0
        
        self.connection.dispatch_message(data_pkt)
        
        # Verify Channel received data
        received = chan.recv()
        self.assertEqual(received, b"hello")
        
    def test_send_data(self):
        chan = self.connection.open_channel()
        chan.remote_id = 99
        chan.active = True
        
        chan.send(b"foo")
        
        # Verify packet
        # Last call might be OPEN. We want calls after that.
        # send_packet called twice (OPEN, then DATA)
        self.assertEqual(self.mock_transport.send_packet.call_count, 2)
        args = self.mock_transport.send_packet.call_args_list[1][0][0]
        self.assertEqual(args.message_id, sshconstants.SSH_MSG_CHANNEL_DATA)
        # Check remote ID
        # Payload starts with remote_id (uint32).
        args._position = 0
        rid = args.get_uint32()
        self.assertEqual(rid, 99)
        data = args.get_string()
        self.assertEqual(data, b"foo")

if __name__ == '__main__':
    unittest.main()
