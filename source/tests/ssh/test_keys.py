import unittest
from automojo.protocols.ssh.keys import RSAKey, Ed25519Key

class TestKeys(unittest.TestCase):
    def test_rsa_key(self):
        key = RSAKey()
        self.assertEqual(key.get_name(), "ssh-rsa")
        data = b"hello world"
        sig = key.sign(data)
        self.assertTrue(key.verify(data, sig))
        self.assertFalse(key.verify(b"wrong data", sig))
        
        # Test export/import (partially, just export for now)
        pub_bytes = key.as_bytes()
        self.assertTrue(len(pub_bytes) > 0)

    def test_ed25519_key(self):
        key = Ed25519Key()
        self.assertEqual(key.get_name(), "ssh-ed25519")
        data = b"hello ed25519"
        sig = key.sign(data)
        self.assertTrue(key.verify(data, sig))
        self.assertFalse(key.verify(b"wrong data", sig))

if __name__ == '__main__':
    unittest.main()
