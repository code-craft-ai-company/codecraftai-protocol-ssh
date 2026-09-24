import unittest
from unittest.mock import MagicMock
from ccai.protocols.ssh import sshconstants
from ccai.protocols.ssh.sshconnection import SshConnection
from ccai.protocols.ssh.sshpacket import SshPacket

class TestInteractive(unittest.TestCase):
    def setUp(self):
        self.mock_transport = MagicMock()
        self.mock_transport.active = True
        # open_channel() waits for the peer, so answer SSH_MSG_CHANNEL_OPEN with a confirmation.
        self.mock_transport.send_packet.side_effect = self._confirm_channel_open
        self.connection = SshConnection(self.mock_transport)
        self.channel = self.connection.open_channel()
        self.channel.remote_id = 100 # Mock remote ID

    def _confirm_channel_open(self, pkt):
        if pkt.message_id == sshconstants.SSH_MSG_CHANNEL_OPEN:
            pkt._position = 0
            pkt.get_string() # channel type
            local_id = pkt.get_uint32()

            confirm = SshPacket(payload=bytes([sshconstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION]))
            confirm.add_uint32(local_id)
            confirm.add_uint32(100) # remote id
            confirm.add_uint32(1024 * 1024) # window
            confirm.add_uint32(32768) # max packet
            confirm._position = 0
            self.connection.dispatch_message(confirm)

        elif pkt.message_id == sshconstants.SSH_MSG_CHANNEL_REQUEST:
            # Requests that want a reply wait for the peer's answer; accept them.
            pkt._position = 0
            pkt.get_uint32() # recipient channel
            pkt.get_string() # request type
            want_reply = pkt.get_boolean()
            if want_reply is True:
                success = SshPacket(payload=bytes([sshconstants.SSH_MSG_CHANNEL_SUCCESS]))
                success.add_uint32(self.channel.local_id)
                success._position = 0
                self.connection.dispatch_message(success)
        return

    def test_encode_terminal_modes(self):
        modes = {
            sshconstants.ECHO: 1,
            sshconstants.TTY_OP_ISPEED: 14400,
            sshconstants.TTY_OP_OSPEED: 14400
        }
        encoded = self.channel._encode_terminal_modes(modes)
        
        # Structure: Opcode (1) + Arg (4) ... + TTY_OP_END (1)
        pkt = SshPacket(payload=encoded)
        pkt._position = 0
        
        self.assertEqual(pkt.get_byte(), sshconstants.ECHO)
        self.assertEqual(pkt.get_uint32(), 1)
        
        self.assertEqual(pkt.get_byte(), sshconstants.TTY_OP_ISPEED)
        self.assertEqual(pkt.get_uint32(), 14400)
        
        self.assertEqual(pkt.get_byte(), sshconstants.TTY_OP_OSPEED)
        self.assertEqual(pkt.get_uint32(), 14400)
        
        self.assertEqual(pkt.get_byte(), sshconstants.TTY_OP_END)

    def test_request_pty(self):
        modes = {sshconstants.ECHO: 0}
        self.channel.request_pty(term='xterm', width=120, height=30, modes=modes)
        
        # Verify request packet
        # 3 calls: Channel Open, then pty-req
        # We need to find the pty-req call
        
        # Last call
        args = self.mock_transport.send_packet.call_args[0][0]
        self.assertEqual(args.message_id, sshconstants.SSH_MSG_CHANNEL_REQUEST)
        
        args._position = 0
        self.assertEqual(args.get_uint32(), 100) # Remote ID
        self.assertEqual(args.get_string(), b"pty-req")
        self.assertTrue(args.get_boolean()) # want_reply
        
        # Specific pty-req data
        self.assertEqual(args.get_string(), b"xterm")
        self.assertEqual(args.get_uint32(), 120) # width
        self.assertEqual(args.get_uint32(), 30)  # height
        self.assertEqual(args.get_uint32(), 0)   # px width
        self.assertEqual(args.get_uint32(), 0)   # px height
        
        encoded_modes = args.get_string()
        # Verify mode inside
        mode_pkt = SshPacket(payload=encoded_modes)
        mode_pkt._position = 0
        self.assertEqual(mode_pkt.get_byte(), sshconstants.ECHO)
        self.assertEqual(mode_pkt.get_uint32(), 0)
        self.assertEqual(mode_pkt.get_byte(), sshconstants.TTY_OP_END)

    def test_resize_pty(self):
        self.channel.resize_pty(100, 50)
        
        args = self.mock_transport.send_packet.call_args[0][0]
        self.assertEqual(args.message_id, sshconstants.SSH_MSG_CHANNEL_REQUEST)
        
        args._position = 0
        self.assertEqual(args.get_uint32(), 100)
        self.assertEqual(args.get_string(), b"window-change")
        self.assertFalse(args.get_boolean()) # want_reply
        
        self.assertEqual(args.get_uint32(), 100) # width
        self.assertEqual(args.get_uint32(), 50)  # height
        self.assertEqual(args.get_uint32(), 0)
        self.assertEqual(args.get_uint32(), 0)

if __name__ == '__main__':
    unittest.main()
