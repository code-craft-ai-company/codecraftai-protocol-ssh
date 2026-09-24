import struct
import time
import unittest
from unittest.mock import MagicMock

from ccai.protocols.ssh import sshconstants
from ccai.protocols.ssh.sshconnection import SshConnection
from ccai.protocols.ssh.sshconst import INTERACTIVE_PROMPT_BYTES
from ccai.protocols.ssh.sshhelpers import ssh_execute_command, ssh_execute_command_in_channel
from ccai.protocols.ssh.sshpacket import SshPacket

from ccai_tests.protocols.ssh.fakepeertransport import FakePeerTransport


class TestSshHelpersOverChannel(unittest.TestCase):
    """
        Runs the command helpers over real :class:`SshChannel` objects with a simulated server, so the helpers
        depend on the channel's request replies, stdout / stderr streams, exit status, EOF and close handling.
    """

    def setUp(self):
        self.transport = FakePeerTransport()
        self.connection = SshConnection(self.transport)
        self.transport.connection = self.connection

        self.ssh_client = MagicMock()
        self.ssh_client.connection = self.connection
        self.ssh_client.get_transport.return_value = self.transport
        return

    def _play_command(self, local_id: int, request_type: str):
        if request_type == "exec":
            self.transport.dispatch_to_channel(sshconstants.SSH_MSG_CHANNEL_DATA, local_id, b"out\n")

            stderr_body = struct.pack('>I', sshconstants.SSH_EXTENDED_DATA_STDERR)
            stderr_pkt = SshPacket()
            stderr_pkt.add_string(b"err\n")
            self.transport.dispatch_raw(sshconstants.SSH_MSG_CHANNEL_EXTENDED_DATA, local_id,
                                        stderr_body + bytes(stderr_pkt.payload))

            status_pkt = SshPacket()
            status_pkt.add_string("exit-status")
            status_pkt.add_boolean(False)
            status_pkt.add_uint32(3)
            self.transport.dispatch_raw(sshconstants.SSH_MSG_CHANNEL_REQUEST, local_id, bytes(status_pkt.payload))

            self.transport.dispatch_to_channel(sshconstants.SSH_MSG_CHANNEL_EOF, local_id)
            self.transport.dispatch_to_channel(sshconstants.SSH_MSG_CHANNEL_CLOSE, local_id)
        return

    def test_ssh_execute_command_returns_status_stdout_and_stderr(self):
        self.transport.request_handler = self._play_command

        status, stdout, stderr = ssh_execute_command(self.ssh_client, "some-command", inactivity_timeout=5,
                                                     inactivity_interval=0.05)

        self.assertEqual(status, 3)
        self.assertEqual(stdout, "out\n")
        self.assertEqual(stderr, "err\n")
        # The peer closed first; our CLOSE answered it exactly once.
        self.assertEqual(len(self.transport.sent_of_type(sshconstants.SSH_MSG_CHANNEL_CLOSE)), 1)
        return

    def test_interactive_command_collects_stderr_without_waiting_for_it(self):
        channel = self.connection.open_channel("session")
        output = b"ls\r\nfile1\r\n" + INTERACTIVE_PROMPT_BYTES
        self.transport.dispatch_to_channel(sshconstants.SSH_MSG_CHANNEL_DATA, channel.local_id, output)

        stderr_body = struct.pack('>I', sshconstants.SSH_EXTENDED_DATA_STDERR)
        stderr_pkt = SshPacket()
        stderr_pkt.add_string(b"warn")
        self.transport.dispatch_raw(sshconstants.SSH_MSG_CHANNEL_EXTENDED_DATA, channel.local_id,
                                    stderr_body + bytes(stderr_pkt.payload))

        start = time.monotonic()
        status, stdout, stderr = ssh_execute_command_in_channel(channel, "ls", read_timeout=2, inactivity_timeout=10,
                                                                status_check=True)
        elapsed = time.monotonic() - start

        self.assertEqual(status, 0)
        self.assertEqual(stdout, "file1")
        self.assertEqual(stderr, "warn")
        self.assertLess(elapsed, 1, "reading stderr should not wait for the read timeout")
        return


if __name__ == '__main__':
    unittest.main()
