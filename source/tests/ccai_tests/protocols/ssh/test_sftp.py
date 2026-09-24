import unittest
import struct
from unittest.mock import MagicMock
from ccai.protocols.ssh.sshconnection import SshConnection
from ccai.protocols.ssh.sshsftp import SshSFTPClient
from ccai.protocols.ssh import sshconstants

from ccai_tests.protocols.ssh.fakepeertransport import FakePeerTransport, PEER_CHANNEL_BASE

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
        msg_type = sshconstants.SSH_FXP_VERSION
        length = 1 + len(version_payload)
        
        response = struct.pack('>I', length) + bytes([msg_type]) + version_payload
        
        # recv needs to return length (4 bytes) then rest.
        # SshSFTPClient calls recv twice: _read_exactly(4) -> 4 bytes len.
        # then _read_exactly(len) -> Type + Payload.
        
        self.mock_channel.recv.side_effect = [
            response[:4], # Length
            response[4:]  # Rest
        ]
        
        SshSFTPClient(self.mock_channel)
        
        # Verify INIT sent
        # Send call 0: INIT packet
        # Frame: Len + Type(SSH_FXP_INIT=1) + Version(3)
        self.mock_channel.send.assert_called()
        args = self.mock_channel.send.call_args[0][0]
        
        # Check first 4 bytes length
        sent_len = struct.unpack('>I', args[:4])[0]
        self.assertEqual(sent_len, 5)
        self.assertEqual(args[4], sshconstants.SSH_FXP_INIT)
        
    def test_open_read_close(self):
        # Setup Init response first
        init_resp = struct.pack('>I', 5) + bytes([sshconstants.SSH_FXP_VERSION]) + struct.pack('>I', 3)
        
        # Setup Open response: HANDLE
        # Handle "handle1" (7 chars? no 'handle1' is 7 bytes string)
        # String 'handle1': Len(7) + bytes
        handle_str = b'\x00\x00\x00\x07handle1'
        # SshPacket: Type(SSH_FXP_HANDLE=102) + ReqID + HandleString
        # We don't know ReqID yet (it increments). Should be 1 (0 was init?? Init doesn't use ID field in v3? Yes it does? 
        # Wait, SSH_FXP_INIT does NOT have request-id.
        # SSH_FXP_OPEN DOES have request-id.
        
        # ReqID 1.
        open_payload = struct.pack('>I', 1) + handle_str
        open_resp_len = 1 + len(open_payload)
        open_resp = struct.pack('>I', open_resp_len) + bytes([sshconstants.SSH_FXP_HANDLE]) + open_payload
        
        # Setup Read response: DATA
        # Data "hello"
        data_str = b'\x00\x00\x00\x05hello'
        # ReqID 2.
        read_payload = struct.pack('>I', 2) + data_str
        read_resp_len = 1 + len(read_payload)
        read_resp = struct.pack('>I', read_resp_len) + bytes([sshconstants.SSH_FXP_DATA]) + read_payload
        
        # Setup Close response: STATUS OK
        # Assuming simple status (no lang/msg) for test compactness, but spec says:
        # uint32 id, uint32 code, string message, string lang
        # update Status payload:
        status_payload = struct.pack('>I', 3) + struct.pack('>I', sshconstants.SSH_FX_OK) + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00'
        
        status_resp_len = 1 + len(status_payload)
        status_resp = struct.pack('>I', status_resp_len) + bytes([sshconstants.SSH_FXP_STATUS]) + status_payload
        
        # Chain responses
        self.mock_channel.recv.side_effect = [
            init_resp[:4], init_resp[4:],
            open_resp[:4], open_resp[4:],
            read_resp[:4], read_resp[4:],
            status_resp[:4], status_resp[4:]
        ]
        
        sftp = SshSFTPClient(self.mock_channel)
        handle = sftp.open("foo.txt")
        self.assertEqual(handle, b"handle1")
        
        data = sftp.read(handle, 0, 100)
        self.assertEqual(data, b"hello")
        
        sftp.close(handle)

    def test_write_and_listdir(self):
        # Setup Init
        init_resp = struct.pack('>I', 5) + bytes([sshconstants.SSH_FXP_VERSION]) + struct.pack('>I', 3)
        
        # Write setup:
        # Request: WRITE (id, handle, offset, data)
        # Response: STATUS OK
        status_ok_payload = struct.pack('>I', 1) + struct.pack('>I', sshconstants.SSH_FX_OK) + b'\x00'*8
        status_resp_len = 1 + len(status_ok_payload)
        status_resp = struct.pack('>I', status_resp_len) + bytes([sshconstants.SSH_FXP_STATUS]) + status_ok_payload
        
        # Listdir setup:
        # 1. OPENDIR -> HANDLE ("dirhandle")
        handle_payload = struct.pack('>I', 2) + b'\x00\x00\x00\x09dirhandle'
        handle_resp_len = 1 + len(handle_payload)
        handle_resp = struct.pack('>I', handle_resp_len) + bytes([sshconstants.SSH_FXP_HANDLE]) + handle_payload
        
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
        name_resp = struct.pack('>I', name_resp_len) + bytes([sshconstants.SSH_FXP_NAME]) + name_payload
        
        # 3. READDIR -> STATUS EOF
        status_eof_payload = struct.pack('>I', 4) + struct.pack('>I', sshconstants.SSH_FX_EOF) + b'\x00'*8
        status_eof_resp_len = 1 + len(status_eof_payload)
        status_eof_resp = struct.pack('>I', status_eof_resp_len) + bytes([sshconstants.SSH_FXP_STATUS]) + status_eof_payload

        # 4. CLOSE -> STATUS OK
        status_close_payload = struct.pack('>I', 5) + struct.pack('>I', sshconstants.SSH_FX_OK) + b'\x00'*8
        status_close_resp_len = 1 + len(status_close_payload)
        status_close_resp = struct.pack('>I', status_close_resp_len) + bytes([sshconstants.SSH_FXP_STATUS]) + status_close_payload

        self.mock_channel.recv.side_effect = [
            init_resp[:4], init_resp[4:], # Init
            status_resp[:4], status_resp[4:], # Write response
            handle_resp[:4], handle_resp[4:], # OpenDir response
            name_resp[:4], name_resp[4:], # ReadDir response 1
            status_eof_resp[:4], status_eof_resp[4:], # ReadDir response 2 (EOF)
            status_close_resp[:4], status_close_resp[4:] # Close response
        ]
        
        sftp = SshSFTPClient(self.mock_channel)
        
        # Test Write
        sftp.write(b"handle", 0, b"data")
        
        # Test Listdir
        items = sftp.listdir("/path")
        self.assertEqual(items, ["file1", "file2"])


def sftp_message(msg_type: int, payload: bytes) -> bytes:
    message = struct.pack('>I', 1 + len(payload)) + bytes([msg_type]) + payload
    return message


class TestSFTPOverChannel(unittest.TestCase):
    """
        Runs :class:`SshSFTPClient` over a real :class:`SshChannel`, so the SFTP framing depends on how
        :meth:`SshChannel.recv` hands out the bytes of the channel's data packets.
    """

    def setUp(self):
        self.transport = FakePeerTransport()
        self.connection = SshConnection(self.transport)
        self.transport.connection = self.connection
        self.channel = self.connection.open_channel("session")
        return

    def test_replies_split_across_and_merged_within_channel_packets(self):
        version_reply = sftp_message(sshconstants.SSH_FXP_VERSION, struct.pack('>I', 3))
        handle_reply = sftp_message(sshconstants.SSH_FXP_HANDLE, struct.pack('>I', 1) + b'\x00\x00\x00\x07handle1')
        data_reply = sftp_message(sshconstants.SSH_FXP_DATA, struct.pack('>I', 2) + b'\x00\x00\x00\x05hello')
        status_payload = struct.pack('>I', 3) + struct.pack('>I', sshconstants.SSH_FX_OK) + b'\x00' * 8
        status_reply = sftp_message(sshconstants.SSH_FXP_STATUS, status_payload)

        stream = version_reply + handle_reply + data_reply + status_reply

        # Cut the server's byte stream into channel data packets that split the first length prefix, merge the
        # rest of VERSION, all of HANDLE and the head of DATA into one packet, and carry the rest in a third.
        first_cut = 3
        second_cut = len(version_reply) + len(handle_reply) + 7
        packets = [stream[:first_cut], stream[first_cut:second_cut], stream[second_cut:]]
        for packet_data in packets:
            self.transport.dispatch_to_channel(sshconstants.SSH_MSG_CHANNEL_DATA, self.channel.local_id,
                                               packet_data)

        sftp = SshSFTPClient(self.channel)
        handle = sftp.open("foo.txt")
        data = sftp.read(handle, 0, 100)
        sftp.close(handle)

        self.assertEqual(handle, b"handle1")
        self.assertEqual(data, b"hello")
        self.assertFalse(self.channel.recv_ready(), "every byte of the replies should have been consumed")

        # The subsystem request went out as an SSH string and the INIT request was framed on the channel.
        requests = self.transport.sent_of_type(sshconstants.SSH_MSG_CHANNEL_REQUEST)
        self.assertEqual(len(requests), 1)
        requests[0]._position = 0
        self.assertEqual(requests[0].get_uint32(), PEER_CHANNEL_BASE + self.channel.local_id)
        self.assertEqual(requests[0].get_string(), b"subsystem")
        self.assertTrue(requests[0].get_boolean())
        self.assertEqual(requests[0].get_string(), b"sftp")
        return


if __name__ == '__main__':
    unittest.main()
