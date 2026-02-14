import unittest
import struct
from unittest.mock import MagicMock
from automojo.ssh.sftp import SFTPClient
from automojo.ssh import constants
from automojo.ssh.packet import Packet

class TestSFTP(unittest.TestCase):
    def setUp(self):
        self.mock_channel = MagicMock()
        # Mock subsystem request
        self.mock_channel.request_subsystem = MagicMock()
        
    def test_init(self):
        # SFTP Init expects recv of VERSION packet
        # Response: Length (4) + Type (1) + Version (4)
        # Length = 1 + 4 = 5
        # Type = SSH_FXP_VERSION (2)
        # Version = 3
        
        version_payload = struct.pack('>I', 3)
        msg_type = constants.SSH_FXP_VERSION
        length = 1 + len(version_payload)
        
        response = struct.pack('>I', length) + bytes([msg_type]) + version_payload
        
        # recv needs to return length (4 bytes) then rest.
        # SFTPClient calls recv twice: _read_exactly(4) -> 4 bytes len.
        # then _read_exactly(len) -> Type + Payload.
        
        self.mock_channel.recv.side_effect = [
            response[:4], # Length
            response[4:]  # Rest
        ]
        
        sftp = SFTPClient(self.mock_channel)
        
        # Verify INIT sent
        # Send call 0: INIT packet
        # Frame: Len + Type(SSH_FXP_INIT=1) + Version(3)
        self.mock_channel.send.assert_called()
        args = self.mock_channel.send.call_args[0][0]
        
        # Check first 4 bytes length
        sent_len = struct.unpack('>I', args[:4])[0]
        self.assertEqual(sent_len, 5)
        self.assertEqual(args[4], constants.SSH_FXP_INIT)
        
    def test_open_read_close(self):
        # Setup Init response first
        init_resp = struct.pack('>I', 5) + bytes([constants.SSH_FXP_VERSION]) + struct.pack('>I', 3)
        
        # Setup Open response: HANDLE
        # Handle "handle1" (7 chars? no 'handle1' is 7 bytes string)
        # String 'handle1': Len(7) + bytes
        handle_str = b'\x00\x00\x00\x07handle1'
        # Packet: Type(SSH_FXP_HANDLE=102) + ReqID + HandleString
        # We don't know ReqID yet (it increments). Should be 1 (0 was init?? Init doesn't use ID field in v3? Yes it does? 
        # Wait, SSH_FXP_INIT does NOT have request-id.
        # SSH_FXP_OPEN DOES have request-id.
        
        # ReqID 1.
        open_payload = struct.pack('>I', 1) + handle_str
        open_resp_len = 1 + len(open_payload)
        open_resp = struct.pack('>I', open_resp_len) + bytes([constants.SSH_FXP_HANDLE]) + open_payload
        
        # Setup Read response: DATA
        # Data "hello"
        data_str = b'\x00\x00\x00\x05hello'
        # ReqID 2.
        read_payload = struct.pack('>I', 2) + data_str
        read_resp_len = 1 + len(read_payload)
        read_resp = struct.pack('>I', read_resp_len) + bytes([constants.SSH_FXP_DATA]) + read_payload
        
        # Setup Close response: STATUS OK
        status_payload = struct.pack('>I', 3) + struct.pack('>I', constants.SSH_FX_OK)
        # Assuming simple status (no lang/msg) for test compactness, but spec says:
        # uint32 id, uint32 code, string message, string lang
        # update Status payload:
        status_payload = struct.pack('>I', 3) + struct.pack('>I', constants.SSH_FX_OK) + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00'
        
        status_resp_len = 1 + len(status_payload)
        status_resp = struct.pack('>I', status_resp_len) + bytes([constants.SSH_FXP_STATUS]) + status_payload
        
        # Chain responses
        self.mock_channel.recv.side_effect = [
            init_resp[:4], init_resp[4:],
            open_resp[:4], open_resp[4:],
            read_resp[:4], read_resp[4:],
            status_resp[:4], status_resp[4:]
        ]
        
        sftp = SFTPClient(self.mock_channel)
        handle = sftp.open("foo.txt")
        self.assertEqual(handle, b"handle1")
        
        data = sftp.read(handle, 0, 100)
        self.assertEqual(data, b"hello")
        
        sftp.close(handle)

    def test_write_and_listdir(self):
        # Setup Init
        init_resp = struct.pack('>I', 5) + bytes([constants.SSH_FXP_VERSION]) + struct.pack('>I', 3)
        
        # Write setup:
        # Request: WRITE (id, handle, offset, data)
        # Response: STATUS OK
        status_ok_payload = struct.pack('>I', 1) + struct.pack('>I', constants.SSH_FX_OK) + b'\x00'*8
        status_resp_len = 1 + len(status_ok_payload)
        status_resp = struct.pack('>I', status_resp_len) + bytes([constants.SSH_FXP_STATUS]) + status_ok_payload
        
        # Listdir setup:
        # 1. OPENDIR -> HANDLE ("dirhandle")
        handle_payload = struct.pack('>I', 2) + b'\x00\x00\x00\x09dirhandle'
        handle_resp_len = 1 + len(handle_payload)
        handle_resp = struct.pack('>I', handle_resp_len) + bytes([constants.SSH_FXP_HANDLE]) + handle_payload
        
        # 2. READDIR -> NAME (count=2, "file1", "file2")
        # NAME packet: ID, Count, [filename, longname, attrs]...
        # File 1: "file1", "long1", attrs(0)
        # File 2: "file2", "long2", attrs(0)
        
        def make_string(s):
            b = s.encode('utf-8')
            return struct.pack('>I', len(b)) + b
            
        file1 = make_string("file1") + make_string("long1") + struct.pack('>I', 0)
        file2 = make_string("file2") + make_string("long2") + struct.pack('>I', 0)
        
        name_payload = struct.pack('>I', 3) + struct.pack('>I', 2) + file1 + file2
        name_resp_len = 1 + len(name_payload)
        name_resp = struct.pack('>I', name_resp_len) + bytes([constants.SSH_FXP_NAME]) + name_payload
        
        # 3. READDIR -> STATUS EOF
        status_eof_payload = struct.pack('>I', 4) + struct.pack('>I', constants.SSH_FX_EOF) + b'\x00'*8
        status_eof_resp_len = 1 + len(status_eof_payload)
        status_eof_resp = struct.pack('>I', status_eof_resp_len) + bytes([constants.SSH_FXP_STATUS]) + status_eof_payload

        # 4. CLOSE -> STATUS OK
        status_close_payload = struct.pack('>I', 5) + struct.pack('>I', constants.SSH_FX_OK) + b'\x00'*8
        status_close_resp_len = 1 + len(status_close_payload)
        status_close_resp = struct.pack('>I', status_close_resp_len) + bytes([constants.SSH_FXP_STATUS]) + status_close_payload

        self.mock_channel.recv.side_effect = [
            init_resp[:4], init_resp[4:], # Init
            status_resp[:4], status_resp[4:], # Write response
            handle_resp[:4], handle_resp[4:], # OpenDir response
            name_resp[:4], name_resp[4:], # ReadDir response 1
            status_eof_resp[:4], status_eof_resp[4:], # ReadDir response 2 (EOF)
            status_close_resp[:4], status_close_resp[4:] # Close response
        ]
        
        sftp = SFTPClient(self.mock_channel)
        
        # Test Write
        sftp.write(b"handle", 0, b"data")
        
        # Test Listdir
        items = sftp.listdir("/path")
        self.assertEqual(items, ["file1", "file2"])

if __name__ == '__main__':
    unittest.main()
