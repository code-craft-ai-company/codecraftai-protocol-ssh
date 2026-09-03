import unittest
import struct
from ccai.protocols.ssh.sshpacket import SshPacket
from ccai.protocols.ssh import sshconstants

class TestPacket(unittest.TestCase):

    def test_packet_init(self):
        pkt = SshPacket(sshconstants.SSH_MSG_DISCONNECT)
        self.assertEqual(pkt.message_id, sshconstants.SSH_MSG_DISCONNECT)
        self.assertEqual(pkt.payload, bytearray())

    def test_add_get_byte(self):
        pkt = SshPacket()
        pkt.add_byte(0xAB)
        self.assertEqual(pkt.payload, b'\xAB')
        self.assertEqual(pkt.get_byte(), 0xAB)

    def test_add_get_boolean(self):
        pkt = SshPacket()
        pkt.add_boolean(True)
        pkt.add_boolean(False)
        self.assertEqual(pkt.payload, b'\x01\x00')
        self.assertTrue(pkt.get_boolean())
        self.assertFalse(pkt.get_boolean())

    def test_add_get_uint32(self):
        pkt = SshPacket()
        pkt.add_uint32(0x12345678)
        self.assertEqual(pkt.payload, b'\x12\x34\x56\x78')
        self.assertEqual(pkt.get_uint32(), 0x12345678)

    def test_add_get_uint64(self):
        pkt = SshPacket()
        pkt.add_uint64(0x1234567890ABCDEF)
        self.assertEqual(pkt.payload, b'\x12\x34\x56\x78\x90\xAB\xCD\xEF')
        self.assertEqual(pkt.get_uint64(), 0x1234567890ABCDEF)

    def test_add_get_string(self):
        pkt = SshPacket()
        test_str = "hello"
        pkt.add_string(test_str)
        # Length (4 bytes) + string content
        self.assertEqual(pkt.payload, b'\x00\x00\x00\x05hello')
        self.assertEqual(pkt.get_string(), b'hello')

    def test_add_get_mpint(self):
        pkt = SshPacket()
        # Test 0
        pkt.add_mpint(0)
        self.assertEqual(pkt.payload, b'\x00\x00\x00\x00') # Length 0 string
        
        pkt = SshPacket()
        # Test 80
        pkt.add_mpint(80)
        # 80 is 0x50. Positive, MSB 0.
        # Length 1, content 0x50
        self.assertEqual(pkt.payload, b'\x00\x00\x00\x01\x50')
        self.assertEqual(pkt.get_mpint(), 80)
        
        pkt = SshPacket()
        # Test -128 (0x80)
        # Needs to be a two's complement. 
        # -128 is 10000000. 
        pkt.add_mpint(-128)
        # mpint logic in packet.py for negative? 
        # int.to_bytes supports signed.
        # -128 signed is \x80
        self.assertEqual(pkt.payload, b'\x00\x00\x00\x01\x80') # Length 1
        self.assertEqual(pkt.get_mpint(), -128)

    def test_add_get_name_list(self):
        pkt = SshPacket()
        names = ["ssh-rsa", "ssh-dss"]
        pkt.add_name_list(names)
        self.assertEqual(pkt.get_name_list(), names)
        
    def test_remaining(self):
        pkt = SshPacket(payload=b'abc')
        self.assertEqual(pkt.remaining, b'abc')
        pkt.get_byte()
        self.assertEqual(pkt.remaining, b'bc')

if __name__ == '__main__':
    unittest.main()
