import unittest
import socket
import os
import hashlib
import struct
from unittest.mock import MagicMock, patch
from ccai.protocols.ssh.sshtransport import SshTransport
from ccai.protocols.ssh import sshconstants
from ccai.protocols.ssh.sshpacket import SshPacket
from ccai.protocols.ssh.sshkeys import SshRSAKey

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class TestTransport(unittest.TestCase):
    def setUp(self):
        self.mock_sock = MagicMock(spec=socket.socket)
        self.transport = SshTransport(self.mock_sock)

    def test_is_active_tracks_connection_state(self):
        # SshTunnel stops forwarding when is_active() reports a dead transport.
        self.assertFalse(self.transport.is_active())

        self.transport.active = True
        self.assertTrue(self.transport.is_active())

        self.transport.close()
        self.assertFalse(self.transport.is_active())
        return

    def test_version_exchange(self):
        # Setup mock to return a valid version string
        self.mock_sock.recv.side_effect = [b'S', b'S', b'H', b'-', b'2', b'.', b'0', b'-', b'O', b'p', b'e', b'n', b'S', b'S', b'H', b'\n']
        
        # Run connect (we override start() to avoid spawning thread in test)
        with patch.object(self.transport, 'start'):
            with patch.object(self.transport, 'send_kex_init'):
                self.transport.connect()
        
        # Verify we sent our version
        expected_send = f"{sshconstants.MSG_STR_VERSION}\r\n".encode('utf-8')
        self.mock_sock.sendall.assert_called_with(expected_send)
        
        # Verify we parsed remote version
        self.assertEqual(self.transport.remote_version, 'SSH-2.0-OpenSSH')

    def test_kex_exchange_logic(self):
        # Testing logic step-by-step without full thread loop to control inputs
        
        # 1. Connect & Client KEXINIT
        # Mock send/receive version
        self.mock_sock.recv.side_effect = [b'S', b'S', b'H', b'-', b'2', b'.', b'0', b'-', b'S', b'r', b'v', b'\n']
        self.transport.remote_version = "SSH-2.0-Srv"
        
        # Manually trigger client KEXINIT sent storage
        self.transport.send_kex_init()
        # Verify client payload stored
        self.assertIsNotNone(self.transport.client_kex_init_payload)
        
        # 2. Receive Server KEXINIT
        server_kex_init = SshPacket(sshconstants.SSH_MSG_KEXINIT)
        server_kex_init.add_bytes(os.urandom(16)) # Cookie: 16 raw bytes
        server_kex_init.add_name_list(["diffie-hellman-group14-sha1"])
        server_kex_init.add_name_list(["ssh-rsa"]) 
        server_kex_init.add_name_list(["aes128-ctr"])
        server_kex_init.add_name_list(["aes128-ctr"])
        server_kex_init.add_name_list(["hmac-sha1"])
        server_kex_init.add_name_list(["hmac-sha1"])
        server_kex_init.add_name_list(["none"])
        server_kex_init.add_name_list(["none"])
        server_kex_init.add_name_list([""])
        server_kex_init.add_name_list([""])
        server_kex_init.add_boolean(False)
        server_kex_init.add_uint32(0)
        
        # Simulate receiving it
        # Pack to bytes to simulate wire reception if needed, but we pass SshPacket object to _handle_kex_init
        # We need to ensure payload allows accurate H calculation.
        # SshTransport receives bytes, unpacks to SshPacket. SshPacket.payload contains the data.
        # We constructed SshPacket with correct payload.
        
        # Host-key trust is delegated to the client; accept the key for this test.
        self.transport.hostname = 'srv'
        self.transport.host_key_verifier = lambda hostname, key_type, blob: True

        # Capture sent KEXDH_INIT
        with patch.object(self.transport, 'send_packet') as mock_send:
            self.transport._handle_kex_init(server_kex_init)
            
            # Should have called send_packet with KEXDH_INIT
            call_args = mock_send.call_args[0][0]
            self.assertEqual(call_args.message_id, sshconstants.SSH_MSG_KEXDH_INIT)
            
            # Client e should be set
            self.assertIsNotNone(self.transport.dh_public_key)
            client_e = self.transport.dh_public_key.public_numbers().y
        
        # 3. Handle KEXDH OR REPLY
        # Generate Server DH
        # Must match Group 14
        p = self.transport.dh_parameters.parameter_numbers().p
        g = 2
        params = dh.DHParameterNumbers(p, g)
        server_private = params.parameters(default_backend()).generate_private_key()
        server_public = server_private.public_key()
        server_f = server_public.public_numbers().y
        
        # Compute Expected Shared Secret
        shared_secret = server_private.exchange(
             dh.DHPublicNumbers(client_e, params).public_key(default_backend())
        )
        K_int = int.from_bytes(shared_secret, byteorder='big')
        
        # Generate Server Host Key
        server_host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_host_pub = server_host_key.public_key()
        pub_numbers = server_host_pub.public_numbers()
        
        # Host Key Blob (ssh-rsa)
        hk_pkt = SshPacket()
        hk_pkt.add_string("ssh-rsa")
        hk_pkt.add_mpint(pub_numbers.e)
        hk_pkt.add_mpint(pub_numbers.n)
        host_key_blob = hk_pkt.payload
        
        # Compute H for signature
        h_pkt = SshPacket()
        h_pkt.add_string(self.transport.local_version)
        h_pkt.add_string(self.transport.remote_version)
        h_pkt.add_string(self.transport.client_kex_init_payload)
        h_pkt.add_string(server_kex_init.payload) # I_S
        h_pkt.add_string(host_key_blob) # K_S
        h_pkt.add_mpint(client_e) # e
        h_pkt.add_mpint(server_f) # f
        h_pkt.add_mpint(K_int) # K
        
        digest = hashlib.sha1(h_pkt.payload).digest()
        
        # Sign H
        signature = server_host_key.sign(digest, padding.PKCS1v15(), hashes.SHA1())
        
        # Signature Blob
        sig_blob_pkt = SshPacket()
        sig_blob_pkt.add_string("ssh-rsa")
        sig_blob_pkt.add_string(signature)
        sig_blob = sig_blob_pkt.payload
        
        # 4. Construct Reply SshPacket
        reply = SshPacket(sshconstants.SSH_MSG_KEXDH_REPLY)
        reply.add_string(host_key_blob)
        reply.add_mpint(server_f)
        reply.add_string(sig_blob)
        
        # 5. Process Reply, shaped as it would arrive off the wire (message id first)
        self.transport._handle_kexdh_reply(SshPacket(payload=reply.to_bytes()))
        
        # 6. Verify State
        self.assertIsNotNone(self.transport.shared_secret_K)
        self.assertEqual(self.transport.shared_secret_K, K_int)
        self.assertEqual(self.transport.exchange_hash_H, digest)
        self.assertIsNotNone(self.transport.host_key)
        self.assertIsInstance(self.transport.host_key, SshRSAKey)

    def test_encryption_activation_and_traffic(self):
        # Setup dummy KEX state
        self.transport.shared_secret_K = 1234567890
        self.transport.exchange_hash_H = b'0'*20
        self.transport.session_id = b'0'*20
        
        # Activate
        self.transport._activate_incoming()
        
        self.assertIsNotNone(self.transport.decryptor)
        
        # We want to test _read_packet (Decryption).
        # It uses s2c keys (IV: 'B', Key: 'D').
        # We need to generate a valid encrypted packet using these keys.
        
        # Re-derive keys locally to encrypt
        iv_len = 16
        key_len = 16
        s2c_iv = self.transport._compute_key(b'B', iv_len)
        s2c_key = self.transport._compute_key(b'D', key_len)
        
        # Re-derive MAC key
        mac_key_len = 20
        s2c_mac_key = self.transport._compute_key(b'F', mac_key_len)
        
        # Create external encryptor (simulating server)
        cipher = Cipher(algorithms.AES(s2c_key), modes.CTR(s2c_iv), backend=default_backend())
        server_encryptor = cipher.encryptor()
        
        # Construct Plaintext SshPacket
        payload = b"Hello Secure World"
        pkt = SshPacket(sshconstants.SSH_MSG_DEBUG)
        pkt.add_boolean(True)
        pkt.add_string(payload)
        pkt.add_string("")
        
        # SshPacket Packing Logic (same as send_packet but manual)
        payload_bytes = pkt.to_bytes()
        block_size = 16
        current_len = 4 + 1 + len(payload_bytes)
        pad_len = block_size - (current_len % block_size)
        if pad_len < 4: pad_len += block_size
        padding = b'\x00' * pad_len
        packet_len = 1 + len(payload_bytes) + len(padding)
        
        # To be MAC'ed
        unencrypted_packet = struct.pack('>I', packet_len) + struct.pack('B', pad_len) + payload_bytes + padding
        
        # Encrypt
        encrypted_data = server_encryptor.update(unencrypted_packet)
        
        # Compute MAC
        # Seqno is 0
        seqno = 0
        seqno_bytes = struct.pack('>I', seqno)
        
        h = hmac.HMAC(s2c_mac_key, hashes.SHA1(), backend=default_backend())
        h.update(seqno_bytes)
        h.update(unencrypted_packet)
        mac = h.finalize()
        
        # Feed to transport (Encrypted Data + MAC)
        data_with_mac = encrypted_data + mac
        
        # Feed to transport
        # Split into chunks for _read_packet logic
        # 1. First block (16)
        # 2. Rest of encrypted
        # 3. MAC
        
        chunk1 = data_with_mac[:16]
        chunk2 = data_with_mac[16:len(encrypted_data)]
        chunk3 = data_with_mac[len(encrypted_data):]
        
        self.transport.sock.recv.side_effect = [chunk1, chunk2, chunk3]
        
        # Read
        read_pkt = self.transport._read_packet()
        
        self.assertIsNotNone(read_pkt)
        self.assertEqual(read_pkt.payload[0], sshconstants.SSH_MSG_DEBUG)
        
        # Verify content
        read_pkt.get_byte() # Msg ID
        always_display = read_pkt.get_boolean()
        message = read_pkt.get_string().decode('utf-8')
        
        self.assertTrue(always_display)
        self.assertEqual(message, "Hello Secure World")
        
        # Verify seqno incremented
        self.assertEqual(self.transport.seqno_in, 1)

if __name__ == '__main__':
    unittest.main()
