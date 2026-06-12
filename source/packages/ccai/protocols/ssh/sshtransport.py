import socket
import threading
import logging
import struct
import os
import hashlib
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from ccai.protocols.ssh import sshconstants
from ccai.protocols.ssh.sshpacket import SshPacket
from ccai.protocols.ssh.sshkeys import SshRSAKey, SshEd25519Key

# Setup logger
logger = logging.getLogger(__name__)

class SshTransport(threading.Thread):
    """
    SSH Transport Layer implementation.
    Handles encryption, decryption, compression, and key exchange.
    Run as a thread to handle incoming data.
    """

    def __init__(self, sock: socket.socket):
        super().__init__()
        self.sock = sock
        self.active = False
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        
        # Versions
        self.remote_version = None
        self.local_version = sshconstants.MSG_STR_VERSION
        
        # State
        self.session_id = None
        self.packet_queue = [] # Replace with Queue in prod
        
        # Cipher state (Initially None/Cleartext)
        self.encryptor = None
        self.decryptor = None
        self.hmac_out = None # Deprecated/unused field? Removed in previous step but let's keep clean.
        self.hmac_in = None
        self.hmac_out_key = None
        self.hmac_in_key = None
        self.mac_len_out = 0
        self.mac_len_in = 0
        
        # Sequence Numbers
        self.seqno_out = 0
        self.seqno_in = 0
        
        # KEX State
        self.kex_init_sent = False
        self.kex_init_rcvd = False
        
        # Diffie-Hellman State
        self.dh_private_key = None
        self.dh_public_key = None
        self.shared_secret_K = None
        self.exchange_hash_H = None
        self.host_key = None # The server's host key
        
        # Exchange values
        self.client_kex_init_payload = None
        self.server_kex_init_payload = None
        
        # Buffer for incoming data
        self._buffer = bytearray()

    def connect(self):
        """
        Perform initial SSH handshake.
        """
        self.active = True
        
        # 1. Send Version String
        self._send_version()
        
        # 2. Receive Version String
        self._receive_version()
        
        # 3. Start processing thread
        self.start()
        
        # 4. Start Key Exchange (KEXINIT)
        self.send_kex_init()

    def run(self):
        """
        Main loop for reading packets from the socket.
        """
        logger.info("Transport thread started")
        while self.active and not self.stop_event.is_set():
            try:
                packet = self._read_packet()
                if packet:
                    self._process_packet(packet)
            except Exception as e:
                logger.error(f"Error in transport loop: {e}")
                self.close()
                break
        logger.info("Transport thread stopped")

    def close(self):
        self.active = False
        self.stop_event.set()
        try:
            self.sock.close()
        except:
            pass

    def _send_version(self):
        v_str = f"{self.local_version}\r\n".encode('utf-8')
        self.sock.sendall(v_str)

    def _receive_version(self):
        # Spec says we can receive lines before the version string.
        # We must look for "SSH-"
        buf = b""
        while True:
            recv = self.sock.recv(1)
            if not recv:
                raise ConnectionError("Connection closed while waiting for version")
            buf += recv
            if buf.endswith(b"\n"):
                line = buf.strip()
                if line.startswith(b"SSH-"):
                    self.remote_version = line.decode('utf-8')
                    break
                buf = b"" # Discard non-version lines

    def send_packet(self, packet: SshPacket):
        """
        Encapsulate and send a packet.
        Format:
        uint32    packet_length
        byte      padding_length
        byte[n1]  payload; n1 = packet_length - padding_length - 1
        byte[n2]  random padding; n2 = padding_length
        byte[m]   mac (Message Authentication Code - MAC); m = mac_length
        """
        payload = packet.to_bytes()
        
        # Calculate padding
        # Block size (encryptor block size or 8)
        block_size = 8 
        if self.encryptor:
            # AES block size is 128 bit = 16 bytes.
            # But CTR mode is stream-like.
            # SSH protocol: "The length of the packet payload... length field... etc."
            # "The packet length ... must be a multiple of the cipher block size or 8, whichever is larger."
            # For AES (block cipher), block size is 16.
            # Even in CTR mode, SSH framing might respect block size for padding alignment?
            # RFC 4344: "The 'block size' for ... aes128-ctr ... is 16 octets."
            block_size = 16
            
        # len(packet_length) + len(padding_length) + len(payload) + len(padding)
        # 4 + 1 + len(payload) + pad_len must be multiple of block_size
        # Minimum padding is 4 bytes.
        
        current_len = 4 + 1 + len(payload)
        pad_len = block_size - (current_len % block_size)
        if pad_len < 4:
            pad_len += block_size
            
        padding = os.urandom(pad_len)
        
        packet_len = 1 + len(payload) + len(padding) # Excluding 'packet_length' field itself (4 bytes)
        
        out = struct.pack('>I', packet_len)
        out += struct.pack('B', pad_len)
        out += payload
        out += padding
        
        # Encrypt 'out' (excluding packet_len field if not etm? SSH default is encrypt payload+padding+len?)
        # RFC 4253:
        # The ciphertext is produced by correctly encrypting the plaintext packet.
        # Plaintext packet: packet_length || padding_length || payload || padding
        # So we encrypt the WHOLE thing except the mac.
        # Wait, some ciphers (stream) encrypt length too?
        # RFC 4253 Section 6:
        # "The packet length, padding length, payload, and padding are encrypted."
        
        final_data = out
        if self.encryptor:
            final_data = self.encryptor.update(out)
            
        # MAC
        # Calculated over SequenceNumber || UnencryptedPacket
        # UnencryptedPacket = packet_length || padding_length || payload || padding
        # 'out' IS the UnencryptedPacket (before encryption step, but wait).
        # SSH_MSG_NEWKEYS and before are NOT encrypted, NOT MAC'ed?
        # "Everything sent after this message [NEWKEYS] MUST be encrypted."
        # So encryptor is None before that.
        
        mac = b''
        if self.hmac_out_key:
             # seqno (uint32)
             seqno_bytes = struct.pack('>I', self.seqno_out)
             
             # HMAC(key, seqno || unencrypted_packet)
             h = hmac.HMAC(self.hmac_out_key, hashes.SHA1(), backend=default_backend())
             h.update(seqno_bytes)
             h.update(out)
             mac = h.finalize()
             
             self.seqno_out += 1
             # Wrap around uint32? Python ints are infinite, but struct.pack >I handles it? No.
             self.seqno_out &= 0xffffffff

        # Encrypt 'out'
        final_data = out
        if self.encryptor:
            final_data = self.encryptor.update(out)
            
        with self.lock:
             self.sock.sendall(final_data + mac)

    def send_kex_init(self):
        pkt = SshPacket(sshconstants.SSH_MSG_KEXINIT)
        cookie = os.urandom(16)
        pkt.add_string(cookie) # Cookie
        pkt.add_name_list(["diffie-hellman-group14-sha1"]) # kex_algorithms
        pkt.add_name_list(["ssh-rsa", "ssh-ed25519"]) # server_host_key_algorithms
        pkt.add_name_list(["aes128-ctr"]) # encryption_algorithms_client_to_server
        pkt.add_name_list(["aes128-ctr"]) # encryption_algorithms_server_to_client
        pkt.add_name_list(["hmac-sha1"]) # mac_algorithms_client_to_server
        pkt.add_name_list(["hmac-sha1"]) # mac_algorithms_server_to_client
        pkt.add_name_list(["none"]) # compression_algorithms_client_to_server
        pkt.add_name_list(["none"]) # compression_algorithms_server_to_client
        pkt.add_name_list([""]) # languages_client_to_server
        pkt.add_name_list([""]) # languages_server_to_client
        pkt.add_boolean(False) # kex_first_packet_follows
        pkt.add_uint32(0) # reserved
        
        self.client_kex_init_payload = pkt.payload[1:] # Store payload without msg_id for H calc (msg_id is byte 0)
        # Wait, per RFC 4253, I_C is the payload of the client's KEXINIT packet.
        # "The payload of the client's KEXINIT packet."
        # Does it include the message ID?
        # RFC 4253 Section 7. Key Exchange:
        # H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
        # I_C: "The payload of the client's SSH_MSG_KEXINIT packet."
        # Usually this means everything starting from SSH_MSG_KEXINIT byte.
        # My Packet.payload INCLUDES the message ID if I initialized it with one?
        # Packet(constants.SSH_MSG_KEXINIT) sets self.message_id = 20.
        # But payload is empty initially.
        # When I call to_bytes(), it prepends message_id.
        # So I should store the FULL packet bytes for hash calculation.
        
        self.kex_init_sent = True
        self.send_packet(pkt)
        self.client_kex_init_payload = pkt.to_bytes()

    def _read_packet(self):
        """
        Read a single SSH packet from the socket.
        """
        # 1. Read first block (or 4 bytes for length if no encryption)
        # Block size is 8 for unencrypted
        # 1. Read first block (or 4 bytes for length if no encryption)
        # Block size is 8 for unencrypted
        block_size = 8
        if self.decryptor:
            block_size = 16

        try:
             # We need to read enough to get packet length.
             # packet_len is 4 bytes.
             # If encrypted, we must read a full block to decrypt the first block which contains length.
             
             first_block = self._read_bytes(block_size)
             if not first_block:
                 return None
                 
             if self.decryptor:
                 first_block = self.decryptor.update(first_block)
                 
             # Extract packet length (uint32)
             packet_len = struct.unpack('>I', first_block[:4])[0]
             
             # Calculate remaining bytes to read
             # We already read 'block_size' bytes.
             # Total encrypted part is 'packet_len' + 4 (size field itself is not included in packet_len usually? Wait)
             # RFC 4253: "packet_length: The length of the packet in bytes, not including 'mac' or 'packet_length' field itself."
             # So total data AFTER the 4-byte length field is 'packet_len'.
             # We read 'block_size' bytes. 4 bytes were length. So we read 'block_size - 4' bytes of the rest.
             
             bytes_read_so_far = block_size - 4
             bytes_remaining = packet_len - bytes_read_so_far
             
             if bytes_remaining < 0:
                 raise ValueError("Invalid packet length")
                 
             data = self._read_bytes(bytes_remaining)
             if len(data) < bytes_remaining:
                 raise ConnectionError("Connection closed during packet read")
                 
             if self.decryptor:
                 data = self.decryptor.update(data)
                 
             # Full decrypted payload (including padding_len and padding) is:
             # first_block[4:] + data
             
             full_data = first_block[4:] + data
             
             # Padding length is first byte
             pad_len = full_data[0]
             
             # Payload is restart
             # payload = full_data[1 : -pad_len]
             # Check bounds
             if pad_len > len(full_data) - 1:
                 raise ValueError("Invalid padding length")
                 
             payload = full_data[1 : len(full_data) - pad_len]
             
             # TODO: Check MAC (read mac_len bytes)
             if self.hmac_in_key and self.mac_len_in > 0:
                 mac = self._read_bytes(self.mac_len_in)
                 if not mac or len(mac) < self.mac_len_in:
                     raise ConnectionError("Connection closed during MAC read")
                     
                 # Verify MAC
                 # mac = HMAC(key, seqno || unencrypted_packet)
                 # unencrypted_packet is what we decrypted (full_data) PLUS the length field (which was in first_block[:4])
                 # Wait, 'full_data' is first_block[4:] + data. 
                 # So we need to reconstruct the "unencrypted packet" as it was sent.
                 # It includes packet_length field.
                 
                 packet_len_bytes = struct.pack('>I', packet_len)
                 unencrypted_packet = packet_len_bytes + full_data
                 
                 seqno_bytes = struct.pack('>I', self.seqno_in)
                 
                 h = hmac.HMAC(self.hmac_in_key, hashes.SHA1(), backend=default_backend())
                 h.update(seqno_bytes)
                 h.update(unencrypted_packet)
                 expected_mac = h.finalize()
                 
                 if mac != expected_mac:
                     raise Exception("MAC Verification Failed!")
                 
                 self.seqno_in += 1
                 self.seqno_in &= 0xffffffff
             
             return SshPacket(payload=payload)
             
        except (ConnectionError, struct.error) as e:
            logger.warning(f"Read error: {e}")
            raise e

    def _read_bytes(self, n):
        """Helper to read exactly n bytes"""
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return data if len(data) > 0 else None # Return partial or None? if 0 return None
            data += chunk
        return data

    def _process_packet(self, packet: SshPacket):
        # Extract message ID
        if not packet.payload:
            return
        
        msg_id = packet.payload[0]
        # Rewrap packet with correct ID
        # Wait, my Packet class assumes payload includes msg_id if unpacked? 
        # Packet(payload=...) puts it in payload.
        # packet.get_byte() gets the first byte.
        
        # Let's peek
        # msg_id is already in payload[0]
        
        logger.debug(f"Received packet {msg_id}")
        
        if msg_id == sshconstants.SSH_MSG_KEXINIT:
            self._handle_kex_init(packet)
        elif msg_id == sshconstants.SSH_MSG_KEXDH_REPLY:
            self._handle_kexdh_reply(packet)
        elif msg_id == sshconstants.SSH_MSG_NEWKEYS:
            logger.info("Received SSH_MSG_NEWKEYS")
            # TODO: Enable encryption/decryption
            pass
        elif msg_id == sshconstants.SSH_MSG_DISCONNECT:
            self.close()
        elif msg_id == sshconstants.SSH_MSG_IGNORE:
            pass
        elif msg_id == sshconstants.SSH_MSG_DEBUG:
            pass
        else:
            # Queue for application / auth / connection layer
            with self.lock:
                self.packet_queue.append(packet)

    def _handle_kex_init(self, packet):
        self.kex_init_rcvd = True
        logger.info("Received KEXINIT")
        
        # Store for hash H
        # Packet payload contains the bytes properly (with msg_id at 0 if unpacked directly?)
        # My _read_packet returns Packet(payload=...). Payload starts with message_id.
        self.server_kex_init_payload = packet.payload
        
        # Parse server proposals (simplified, assuming we match)
        # Skipping parsing for now, assuming server speaks Group14 + ssh-rsa/ed25519
        
        self._negotiate_algorithms()

    def _negotiate_algorithms(self):
        # In a real impl, we match lists. Here we assume success.
        # Send KEXDH INIT
        self._send_kexdh_init()

    def _send_kexdh_init(self):
        logger.info("Sending KEXDH_INIT")
        # Generate DH key pair (Group 14: 2048-bit MODP)
        params = dh.DHParameterNumbers(p=int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
                                             '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
                                             'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
                                             'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
                                             'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'
                                             'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
                                             '83655D23DCA3AD961C62F356208552BB9ED529077096966D'
                                             '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
                                             'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'
                                             'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
                                             '15728E5A8AACAA68FFFFFFFFFFFFFFFF', 16),
                                       g=2)
        self.dh_parameters = params.parameters(default_backend())
        self.dh_private_key = self.dh_parameters.generate_private_key()
        self.dh_public_key = self.dh_private_key.public_key()
        
        e = self.dh_public_key.public_numbers().y
        
        # Send packet
        pkt = SshPacket(sshconstants.SSH_MSG_KEXDH_INIT)
        pkt.add_mpint(e)
        self.send_packet(pkt)

    def _handle_kexdh_reply(self, packet: SshPacket):
        logger.info("Received KEXDH_REPLY")
        
        # 1. Parse packet
        # K_S: server public host key and certificates (K_S)
        host_key_bytes = packet.get_string()
        # f: server public host key (f)
        server_f = packet.get_mpint()
        # s: signature of H
        signature_blob = packet.get_string()
        
        # 2. Parse Host Key
        self.host_key = self._parse_host_key(host_key_bytes)
        if not self.host_key:
             raise Exception("Unsupported host key type")
             
        # 3. Compute Shared Secret K
        self.shared_secret_K = self._compute_shared_secret(server_f)
        
        # 4. Compute Exchange Hash H
        # Client e is needed.
        client_e = self.dh_public_key.public_numbers().y
        
        self.exchange_hash_H = self._compute_exchange_hash(
            host_key_bytes,
            client_e,
            server_f,
            self.shared_secret_K
        )
        
        # 5. Verify Signature
        # Signature blob structure: string algo, string sig
        # We need to parse it to get the raw signature bytes if needed, 
        # but our Keys class verify might expect raw bytes? 
        # RFC 4253: "The signature is produced using the private host key... 
        # The signature format is defined in section 6.6."
        # Section 6.6: string "ssh-rsa", string rsa_signature_blob.
        # So signature_blob IS the structure (algo, blob).
        
        # We need to extract the raw signature from the blob.
        # Let's peek at the algo.
        # Helper to parse signature blob
        sig_pkt = SshPacket(payload=signature_blob)
        sig_algo = sig_pkt.get_string().decode('utf-8')
        raw_sig = sig_pkt.get_string()
        
        if sig_algo != self.host_key.get_name():
            raise Exception(f"Signature algorithm mismatch: {sig_algo} vs {self.host_key.get_name()}")
            
        if not self.host_key.verify(self.exchange_hash_H, raw_sig):
            raise Exception("Host Key Verification Failed!")
            
        logger.info("Host Key Verified Successfully")
        
        # 6. Send NEWKEYS
        self._send_newkeys()

    def _parse_host_key(self, data: bytes):
        # Allow parsing of supported keys
        # Data is: string key_type, ...
        pkt = SshPacket(payload=data)
        key_type = pkt.get_string().decode('utf-8')
        
        if key_type == 'ssh-rsa':
            e = pkt.get_mpint()
            n = pkt.get_mpint()
            # Construct RSA Key
            pub_numbers = rsa.RSAPublicNumbers(e, n)
            pub_key = pub_numbers.public_key(default_backend())
            return SshRSAKey(pub_key=pub_key)
        elif key_type == 'ssh-ed25519':
            key_bytes = pkt.get_string()
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
            return SshEd25519Key(pub_key=pub_key)
        else:
            logger.warning(f"Unknown host key type: {key_type}")
            return None

    def _compute_shared_secret(self, server_f: int) -> int:
        # K = f^x mod p
        # cryptography DH object doing exchange
        
        # Check f range [1, p-1]
        p = self.dh_parameters.parameter_numbers().p
        if not (1 <= server_f < p):
             raise Exception("DH public value f out of range")
             
        # Compute shared key
        # cryptography requires the peer public key as object
        # but we only have the int y (f). 
        # We reconstruct DHPublicKey.
        
        # Note: parameter_numbers() returns full p/g/q if available?
        # Group 14 p and g are known.
        
        peer_public_numbers = dh.DHPublicNumbers(server_f, self.dh_parameters.parameter_numbers())
        peer_public_key = peer_public_numbers.public_key(default_backend())
        
        shared_key = self.dh_private_key.exchange(peer_public_key)
        
        # "K is stored as a mpint" -> The shared secret K IS the result of exchange,
        # but SSH treats it as mpint (signed). 
        # Cryptography returns bytes. We need to convert bytes to int.
        
        K_int = int.from_bytes(shared_key, byteorder='big')
        return K_int

    def _compute_exchange_hash(self, host_key_bytes, client_e, server_f, shared_secret_K):
        # H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
        # V_C: Client ID string (CR, LF excluded if present? No, raw string sent)
        # RFC 4253: V_C is the client's identification string (CR and LF excluded).
        # My self.local_version is "SSH-2.0-..."
        # self.remote_version is also stripped.
        
        # H calculation requires packing data into a buffer.
        h_pkt = SshPacket()
        h_pkt.add_string(self.local_version)
        h_pkt.add_string(self.remote_version)
        h_pkt.add_string(self.client_kex_init_payload) # I_C
        h_pkt.add_string(self.server_kex_init_payload) # I_S
        h_pkt.add_string(host_key_bytes) # K_S
        h_pkt.add_mpint(client_e) # e
        h_pkt.add_mpint(server_f) # f
        h_pkt.add_mpint(shared_secret_K) # K
        
        # Hash SHA1 (for Group14-SHA1)
        digest = hashlib.sha1(h_pkt.payload).digest()
        return digest

    def _activate_encryption(self):
        """
        Derive keys and Initialize Ciphers.
        Assuming aes128-ctr for both directions.
        """
        # Need session_id. If first KEX, session_id is H.
        if not self.session_id:
            self.session_id = self.exchange_hash_H
            
        # Key length for AES-128 is 16 bytes.
        # IV length for AES (CTR) is 16 bytes (block size).
        key_len = 16
        iv_len = 16
        
        # Client to Server (Encryption)
        # IV: 'A', Key: 'C'
        c2s_iv = self._compute_key(b'A', iv_len)
        c2s_key = self._compute_key(b'C', key_len)
        
        # Server to Client (Decryption)
        # IV: 'B', Key: 'D'
        s2c_iv = self._compute_key(b'B', iv_len)
        s2c_key = self._compute_key(b'D', key_len)
        
        # Integrity Keys (MAC) (hmac-sha1 = 20 bytes)
        mac_key_len = 20
        # Client to Server (Integrity 'E')
        c2s_mac_key = self._compute_key(b'E', mac_key_len)
        # Server to Client (Integrity 'F')
        s2c_mac_key = self._compute_key(b'F', mac_key_len)
        
        # Initialize Encryptor
        # AES-CTR requires a nonce/IV which acts as counter.
        # RFC 4344: "aes128-ctr"
        cipher_enc = Cipher(algorithms.AES(c2s_key), modes.CTR(c2s_iv), backend=default_backend())
        self.encryptor = cipher_enc.encryptor()
        
        # Initialize Decryptor
        cipher_dec = Cipher(algorithms.AES(s2c_key), modes.CTR(s2c_iv), backend=default_backend())
        self.decryptor = cipher_dec.decryptor()
        
        # Initialize HMAC
        # We store the key, or pre-create `hmac.HMAC` instances?
        # `hmac.HMAC` is single-use for `finalize()`. `copy()` can be used?
        # Or just store keys.
        self.hmac_out_key = c2s_mac_key
        self.hmac_in_key = s2c_mac_key
        self.mac_len_out = 20
        self.mac_len_in = 20
        
        logger.info("Traffic Encryption Activated (AES-128-CTR + HMAC-SHA1)")
        
        logger.info("Traffic Encryption Activated (AES-128-CTR)")

    def _compute_key(self, id_byte: bytes, key_len: int) -> bytes:
        """
        Derive key of length 'key_len' using id_byte.
        K = HASH(K || H || id_byte || session_id)
        Extend if needed.
        """
        # K is mpint. Need bytes.
        # Helper to encode mpint as bytes (including length field)? 
        # RFC 4253: "K is encoded as mpint". 
        # But for hash input, it is just the mpint bytes?
        # RFC 4253 Section 5: "Representation of mpints in the hash..."
        # It says: "The shared secret K is encoded as a mpint".
        # So it includes the 4-byte length.
        
        def to_mpint_bytes(n):
            # Same logic as Packet.add_mpint but return bytes
            l = n.bit_length()
            if l == 0:
                 return b'\x00\x00\x00\x00'
            byte_len = (l + 8) // 8
            val_bytes = n.to_bytes(byte_len, 'big', signed=True)
            return struct.pack('>I', len(val_bytes)) + val_bytes

        K_bytes = to_mpint_bytes(self.shared_secret_K)
        H_bytes = self.exchange_hash_H
        
        # Hash 1
        h = hashlib.sha1()
        h.update(K_bytes)
        h.update(H_bytes)
        h.update(id_byte)
        h.update(self.session_id)
        digest = h.digest()
        
        result = digest
        
        # Extend if needed
        while len(result) < key_len:
            h = hashlib.sha1()
            h.update(K_bytes)
            h.update(H_bytes)
            h.update(result)
            result += h.digest()
            
        return result[:key_len]

    def _send_newkeys(self):
        pkt = SshPacket(sshconstants.SSH_MSG_NEWKEYS)
        self.send_packet(pkt)
        logger.info("Sent NEWKEYS")
        # Activate encryption IMMEDIATELY after sending NEWKEYS? 
        # RFC 4253: "Everything sent after this message MUST be encrypted."
        self._activate_encryption()
