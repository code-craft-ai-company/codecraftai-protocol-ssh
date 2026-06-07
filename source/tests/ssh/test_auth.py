import unittest
from unittest.mock import MagicMock
from ccai.ssh.auth import AuthAgent, AuthError
from ccai.ssh import constants
from ccai.ssh.packet import Packet

class TestAuth(unittest.TestCase):
    def setUp(self):
        self.mock_transport = MagicMock()
        self.auth = AuthAgent(self.mock_transport)

    def test_auth_success(self):
        # Simulator successful auth
        pkt = Packet(payload=bytes([constants.SSH_MSG_USERAUTH_SUCCESS]))
        self.auth.dispatch_message(pkt)
        self.assertTrue(self.auth.authenticated)
        
    def test_auth_failure(self):
        pkt = Packet(payload=bytes([constants.SSH_MSG_USERAUTH_FAILURE]))
        pkt.add_name_list(["publickey", "password"]) # methods
        pkt.add_boolean(False) # partial
        
        # Reset position for reading
        pkt._position = 0
        
        self.auth.dispatch_message(pkt)
        self.assertFalse(self.auth.authenticated)
        # Note: add_name_list adds to payload. 
        # But if we init with payload, then add?
        # Packet(payload=...) inits payload.
        # .add_... appends.
        # So we have MSG_ID + Methods + Partial.
        # But dispatch_message calls get_byte() first.
        # So we need to ensure pointer is at 0?
        # Packet.__init__ sets _position = 0.
        # add_... appends to payload.
        # So structure is correct.
        
        self.assertEqual(self.auth.auth_methods, ["publickey", "password"])

    def test_authenticate_password_flow(self):
        # We verify it sends the packet.
        # We mock _wait_for_response to avoid blocking/timeout
        
        with unittest.mock.patch.object(self.auth, '_wait_for_response') as mock_wait:
            self.auth.authenticate_password("user", "pass")
            mock_wait.assert_called_once()
        
        self.mock_transport.send_packet.assert_called()
        args = self.mock_transport.send_packet.call_args[0][0]
        # Verify packet content
        self.assertEqual(args.message_id, constants.SSH_MSG_USERAUTH_REQUEST)

if __name__ == '__main__':
    unittest.main()
