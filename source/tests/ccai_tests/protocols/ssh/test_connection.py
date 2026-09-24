import threading
import time
import unittest
from unittest.mock import MagicMock
from ccai.errors.exceptions import SemanticError
from ccai.protocols.ssh.sshconnection import SshConnection, MAX_CHANNEL_WINDOW_SIZE
from ccai.protocols.ssh import sshconstants
from ccai.protocols.ssh.sshpacket import SshPacket

PEER_CHANNEL_ID = 100

class TestConnection(unittest.TestCase):
    def setUp(self):
        self.mock_transport = MagicMock()
        self.mock_transport.active = True
        self.connection = SshConnection(self.mock_transport)

        # The simulated peer answers SSH_MSG_CHANNEL_OPEN the way the tests configure it:
        # 'confirm' (synchronously), 'confirm-later' (from another thread, like the transport thread),
        # 'fail' (SSH_MSG_CHANNEL_OPEN_FAILURE) or 'silent' (no answer).
        self.peer_answer = "confirm"
        # How the simulated peer answers want-reply channel requests: 'success', 'failure', 'success-later'
        # (from another thread after a delay) or 'silent'.
        self.peer_request_answer = "success"
        self.peer_window = 1024 * 1024
        self.peer_max_packet = 32768
        self.peer_threads = []
        self.opens = []
        self.mock_transport.send_packet.side_effect = self._fake_peer
        return

    def tearDown(self):
        for thread in self.peer_threads:
            thread.join(timeout=5)
        return

    def _fake_peer(self, pkt):
        if pkt.message_id == sshconstants.SSH_MSG_CHANNEL_OPEN:
            pkt._position = 0
            kind = pkt.get_string()
            local_id = pkt.get_uint32()
            pkt.get_uint32() # initial window
            pkt.get_uint32() # max packet
            self.opens.append((kind, local_id, bytes(pkt.remaining)))

            if self.peer_answer == "confirm":
                self._confirm_open(local_id)
            elif self.peer_answer == "confirm-later":
                def confirm_later():
                    time.sleep(0.2)
                    self._confirm_open(local_id)
                    return
                thread = threading.Thread(target=confirm_later, daemon=True)
                self.peer_threads.append(thread)
                thread.start()
            elif self.peer_answer == "fail":
                fail_pkt = SshPacket(payload=bytes([sshconstants.SSH_MSG_CHANNEL_OPEN_FAILURE]))
                fail_pkt.add_uint32(local_id)
                fail_pkt.add_uint32(sshconstants.SSH_OPEN_CONNECT_FAILED)
                fail_pkt.add_string("connect to db.internal port 5432 failed")
                fail_pkt.add_string("") # language tag
                fail_pkt._position = 0
                self.connection.dispatch_message(fail_pkt)

        elif pkt.message_id == sshconstants.SSH_MSG_CHANNEL_REQUEST:
            pkt._position = 0
            recipient = pkt.get_uint32()
            pkt.get_string() # request type
            want_reply = pkt.get_boolean()
            local_id = recipient - PEER_CHANNEL_ID

            if want_reply is True:
                if self.peer_request_answer == "success":
                    self._dispatch_request_reply(local_id, succeeded=True)
                elif self.peer_request_answer == "failure":
                    self._dispatch_request_reply(local_id, succeeded=False)
                elif self.peer_request_answer == "success-later":
                    def answer_later():
                        time.sleep(0.2)
                        self._dispatch_request_reply(local_id, succeeded=True)
                        return
                    thread = threading.Thread(target=answer_later, daemon=True)
                    self.peer_threads.append(thread)
                    thread.start()
        return

    def _dispatch_request_reply(self, local_id: int, succeeded: bool):
        reply_id = sshconstants.SSH_MSG_CHANNEL_FAILURE
        if succeeded is True:
            reply_id = sshconstants.SSH_MSG_CHANNEL_SUCCESS

        pkt = SshPacket(payload=bytes([reply_id]))
        pkt.add_uint32(local_id)
        pkt._position = 0

        self.connection.dispatch_message(pkt)
        return

    def _confirm_open(self, local_id: int):
        pkt = SshPacket(payload=bytes([sshconstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION]))
        pkt.add_uint32(local_id)
        pkt.add_uint32(PEER_CHANNEL_ID + local_id) # remote id
        pkt.add_uint32(self.peer_window) # window
        pkt.add_uint32(self.peer_max_packet) # max packet
        pkt._position = 0

        self.connection.dispatch_message(pkt)
        return

    def _open_confirmed_channel(self, remote_max_packet: int, remote_window: int = 1024 * 1024):
        self.peer_max_packet = remote_max_packet
        self.peer_window = remote_window
        chan = self.connection.open_channel()
        return chan

    def _sent_packets(self, message_id: int) -> list:
        sent = []
        for call in self.mock_transport.send_packet.call_args_list:
            sent_pkt = call[0][0]
            if sent_pkt.message_id == message_id:
                sent.append(sent_pkt)
        return sent

    def _sent_close_recipients(self) -> list:
        recipients = []
        for sent_pkt in self._sent_packets(sshconstants.SSH_MSG_CHANNEL_CLOSE):
            sent_pkt._position = 0
            recipients.append(sent_pkt.get_uint32())
        return recipients

    def test_open_channel(self):
        chan = self.connection.open_channel()
        self.assertIsNotNone(chan)
        self.assertEqual(chan.local_id, 0)
        
        # Verify packet sent
        self.mock_transport.send_packet.assert_called()
        args = self.mock_transport.send_packet.call_args[0][0]
        self.assertEqual(args.message_id, sshconstants.SSH_MSG_CHANNEL_OPEN)

    def test_data_transfer(self):
        # The peer's confirmation is processed before open_channel() returns.
        chan = self._open_confirmed_channel(remote_max_packet=1000, remote_window=1000)
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

    def _sent_data_chunk_sizes(self) -> list:
        chunk_sizes = []
        for call in self.mock_transport.send_packet.call_args_list:
            sent_pkt = call[0][0]
            if sent_pkt.message_id == sshconstants.SSH_MSG_CHANNEL_DATA:
                sent_pkt._position = 0
                sent_pkt.get_uint32() # remote id
                chunk = sent_pkt.get_string()
                chunk_sizes.append(len(chunk))
        return chunk_sizes

    def test_open_confirmation_records_peer_max_packet_size(self):
        chan = self._open_confirmed_channel(remote_max_packet=1000)

        self.assertEqual(chan.remote_max_packet_size, 1000)
        return

    def test_send_chunks_by_peer_max_packet_size_when_smaller(self):
        chan = self._open_confirmed_channel(remote_max_packet=1000)

        chan.send(b"x" * 2500)

        self.assertEqual(self._sent_data_chunk_sizes(), [1000, 1000, 500])
        return

    def test_send_chunks_by_local_max_packet_size_when_peer_larger(self):
        chan = self._open_confirmed_channel(remote_max_packet=65536)

        chan.send(b"x" * 40000)

        self.assertEqual(self._sent_data_chunk_sizes(), [32768, 40000 - 32768])
        return

    # --- RFC 4254 section 5.2 flow control ---

    def _dispatch_window_adjust(self, chan, bytes_to_add: int):
        pkt = SshPacket(payload=bytes([sshconstants.SSH_MSG_CHANNEL_WINDOW_ADJUST]))
        pkt.add_uint32(chan.local_id)
        pkt.add_uint32(bytes_to_add)
        pkt._position = 0

        self.connection.dispatch_message(pkt)
        return

    def _dispatch_data(self, chan, data: bytes):
        pkt = SshPacket(payload=bytes([sshconstants.SSH_MSG_CHANNEL_DATA]))
        pkt.add_uint32(chan.local_id)
        pkt.add_string(data)
        pkt._position = 0

        self.connection.dispatch_message(pkt)
        return

    def _dispatch_extended_data(self, chan, data: bytes, data_type_code: int = 1):
        pkt = SshPacket(payload=bytes([sshconstants.SSH_MSG_CHANNEL_EXTENDED_DATA]))
        pkt.add_uint32(chan.local_id)
        pkt.add_uint32(data_type_code) # 1 is SSH_EXTENDED_DATA_STDERR
        pkt.add_string(data)
        pkt._position = 0

        self.connection.dispatch_message(pkt)
        return

    def _dispatch_close(self, chan):
        pkt = SshPacket(payload=bytes([sshconstants.SSH_MSG_CHANNEL_CLOSE]))
        pkt.add_uint32(chan.local_id)
        pkt._position = 0

        self.connection.dispatch_message(pkt)
        return

    def _sent_window_adjusts(self) -> list:
        adjusts = []
        for call in self.mock_transport.send_packet.call_args_list:
            sent_pkt = call[0][0]
            if sent_pkt.message_id == sshconstants.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                sent_pkt._position = 0
                recipient = sent_pkt.get_uint32()
                bytes_to_add = sent_pkt.get_uint32()
                adjusts.append((recipient, bytes_to_add))
        return adjusts

    def _start_sender(self, chan, data: bytes, timeout: float) -> tuple:
        outcome = {}

        def sender():
            try:
                outcome["sent"] = chan.send(data, timeout=timeout)
            except Exception as xcpt:
                outcome["error"] = xcpt
            return

        thread = threading.Thread(target=sender, daemon=True)
        thread.start()
        return thread, outcome

    def _wait_for_chunk_sizes(self, expected: list, timeout: float = 5.0):
        deadline = time.monotonic() + timeout
        chunk_sizes = self._sent_data_chunk_sizes()
        while chunk_sizes != expected and time.monotonic() < deadline:
            time.sleep(0.01)
            chunk_sizes = self._sent_data_chunk_sizes()
        self.assertEqual(chunk_sizes, expected)
        return

    def test_open_confirmation_records_peer_window(self):
        chan = self._open_confirmed_channel(remote_max_packet=1000, remote_window=5000)

        self.assertEqual(chan.remote_window, 5000)
        return

    def test_send_accounts_window_across_chunks(self):
        chan = self._open_confirmed_channel(remote_max_packet=1000, remote_window=3000)

        sent = chan.send(b"x" * 1200)
        self.assertEqual(sent, 1200)
        self.assertEqual(chan.remote_window, 1800)

        chan.send(b"x" * 1000)
        self.assertEqual(chan.remote_window, 800)

        # A str is sent as UTF-8 and charged to the window in bytes, not characters.
        sent = chan.send("h\u00e9")
        self.assertEqual(sent, 3)
        self.assertEqual(chan.remote_window, 797)

        self.assertEqual(self._sent_data_chunk_sizes(), [1000, 200, 1000, 3])
        return

    def test_send_blocks_when_window_exhausted_and_resumes_after_window_adjust(self):
        chan = self._open_confirmed_channel(remote_max_packet=1000, remote_window=1500)

        thread, outcome = self._start_sender(chan, b"x" * 2500, timeout=10)

        # Only the 1500 bytes the window allows go out; the last chunk is cut to what is left of the window.
        self._wait_for_chunk_sizes([1000, 500])
        time.sleep(0.2)
        self.assertTrue(thread.is_alive(), "send() should block while the peer's window is exhausted")
        self.assertEqual(self._sent_data_chunk_sizes(), [1000, 500])
        self.assertEqual(chan.remote_window, 0)
        self.assertFalse(chan.send_ready())

        self._dispatch_window_adjust(chan, 700)
        self._wait_for_chunk_sizes([1000, 500, 700])
        self.assertTrue(thread.is_alive(), "send() should block again once the adjusted window is used up")

        self._dispatch_window_adjust(chan, 4000)
        thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", outcome)
        self.assertEqual(outcome["sent"], 2500)
        self.assertEqual(self._sent_data_chunk_sizes(), [1000, 500, 700, 300])
        self.assertEqual(chan.remote_window, 3700)
        self.assertTrue(chan.send_ready())
        return

    def test_send_times_out_with_context_when_window_is_not_adjusted(self):
        chan = self._open_confirmed_channel(remote_max_packet=1000, remote_window=100)

        with self.assertRaises(TimeoutError) as ctx:
            chan.send(b"x" * 300, timeout=0.2)

        err_msg = str(ctx.exception)
        self.assertIn("SSH_MSG_CHANNEL_WINDOW_ADJUST", err_msg)
        self.assertIn("sent 100 of 300 bytes", err_msg)
        self.assertIn("local_id=0 remote_id=100", err_msg)
        self.assertEqual(self._sent_data_chunk_sizes(), [100])
        return

    def test_send_uses_channel_send_timeout_by_default(self):
        chan = self._open_confirmed_channel(remote_max_packet=1000, remote_window=0)
        chan.send_timeout = 0.1

        with self.assertRaises(TimeoutError):
            chan.send(b"x")

        self.assertEqual(self._sent_data_chunk_sizes(), [])
        return

    def test_blocked_send_fails_when_channel_closes(self):
        chan = self._open_confirmed_channel(remote_max_packet=1000, remote_window=100)

        thread, outcome = self._start_sender(chan, b"x" * 300, timeout=10)
        self._wait_for_chunk_sizes([100])

        self._dispatch_close(chan)
        thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertIsInstance(outcome.get("error"), ConnectionError)
        self.assertIn("sent 100 of 300 bytes", str(outcome["error"]))
        self.assertEqual(self._sent_data_chunk_sizes(), [100])
        return

    def test_window_adjust_is_clamped_to_rfc_maximum(self):
        chan = self._open_confirmed_channel(remote_max_packet=1000, remote_window=MAX_CHANNEL_WINDOW_SIZE - 10)

        with self.assertLogs("ccai.protocols.ssh.sshconnection", level="WARNING"):
            self._dispatch_window_adjust(chan, 100)

        self.assertEqual(chan.remote_window, MAX_CHANNEL_WINDOW_SIZE)

        # An adjust that stays within the maximum is added as is.
        chan.send(b"x" * 1000)
        self._dispatch_window_adjust(chan, 400)
        self.assertEqual(chan.remote_window, MAX_CHANNEL_WINDOW_SIZE - 600)
        return

    def test_recv_sends_window_adjust_after_half_the_window_is_consumed(self):
        chan = self._open_confirmed_channel(remote_max_packet=32768)
        initial_window = chan.window_size
        packet_count = (initial_window // 2) // 32768

        for _ in range(packet_count):
            self._dispatch_data(chan, b"d" * 32768)

        # Receiving alone does not give the window back; only consumption by the application does.
        self.assertEqual(self._sent_window_adjusts(), [])
        self.assertEqual(chan.local_window, initial_window - packet_count * 32768)

        for _ in range(packet_count - 1):
            chan.recv(32768, timeout=1)
        self.assertEqual(self._sent_window_adjusts(), [])

        # Only the bytes recv() returns count as consumed.
        chan.recv(32767, timeout=1)
        self.assertEqual(self._sent_window_adjusts(), [])
        chan.recv(32768, timeout=1)
        self.assertEqual(self._sent_window_adjusts(), [(100, packet_count * 32768)])
        self.assertEqual(chan.local_window, initial_window)
        return

    def test_stderr_consumes_the_window_until_it_is_read(self):
        chan = self._open_confirmed_channel(remote_max_packet=32768)
        initial_window = chan.window_size
        packet_count = (initial_window // 2) // 32768

        for _ in range(packet_count):
            self._dispatch_extended_data(chan, b"e" * 32768)

        # Stderr shares the window with ordinary data and is given back as recv_stderr() reads it.
        self.assertEqual(self._sent_window_adjusts(), [])
        self.assertEqual(chan.local_window, initial_window - packet_count * 32768)

        for _ in range(packet_count):
            self.assertEqual(chan.recv_stderr(32768, timeout=1), b"e" * 32768)

        self.assertEqual(self._sent_window_adjusts(), [(100, packet_count * 32768)])
        self.assertEqual(chan.local_window, initial_window)
        return

    def test_unsupported_extended_data_is_discarded_and_restores_the_window(self):
        chan = self._open_confirmed_channel(remote_max_packet=32768)
        initial_window = chan.window_size
        packet_count = (initial_window // 2) // 32768

        for _ in range(packet_count):
            self._dispatch_extended_data(chan, b"e" * 32768, data_type_code=2)

        self.assertEqual(self._sent_window_adjusts(), [(100, packet_count * 32768)])
        self.assertEqual(chan.local_window, initial_window)
        self.assertFalse(chan.recv_stderr_ready())
        return

    # --- Channel open waits for the peer (RFC 4254 section 5.1) ---

    def test_open_channel_waits_for_confirmation_from_transport_thread(self):
        self.peer_answer = "confirm-later"

        chan = self.connection.open_channel()

        # The channel is usable as soon as open_channel() returns.
        self.assertTrue(chan.active)
        self.assertEqual(chan.remote_id, PEER_CHANNEL_ID)
        chan.request_pty()
        requests = self._sent_packets(sshconstants.SSH_MSG_CHANNEL_REQUEST)
        self.assertEqual(len(requests), 1)
        requests[0]._position = 0
        self.assertEqual(requests[0].get_uint32(), PEER_CHANNEL_ID)
        return

    def test_open_channel_raises_connection_error_on_open_failure(self):
        self.peer_answer = "fail"

        with self.assertRaises(ConnectionError) as ctx:
            self.connection.open_channel("direct-tcpip", dest_addr=("db.internal", 5432),
                                         src_addr=("127.0.0.1", 40000))

        err_msg = str(ctx.exception)
        self.assertIn("refused to open a 'direct-tcpip' channel", err_msg)
        self.assertIn("SSH_OPEN_CONNECT_FAILED (2)", err_msg)
        self.assertIn("connect to db.internal port 5432 failed", err_msg)
        self.assertNotIn(0, self.connection.channels)
        return

    def test_open_channel_times_out_and_closes_a_late_confirmation(self):
        self.peer_answer = "silent"

        with self.assertRaises(TimeoutError) as ctx:
            self.connection.open_channel(timeout=0.2)

        err_msg = str(ctx.exception)
        self.assertIn("SSH_MSG_CHANNEL_OPEN_CONFIRMATION", err_msg)
        self.assertIn("kind=session local_id=0", err_msg)

        # The abandoned channel is closed when the peer finally confirms it, instead of being orphaned.
        with self.assertLogs("ccai.protocols.ssh.sshconnection", level="WARNING"):
            self._confirm_open(0)
        self.assertEqual(self._sent_close_recipients(), [PEER_CHANNEL_ID])
        self.assertFalse(self.connection.channels[0].active)
        return

    def test_open_channel_uses_connection_channel_timeout_by_default(self):
        self.peer_answer = "silent"
        self.connection.channel_timeout = 0.1

        with self.assertRaises(TimeoutError):
            self.connection.open_channel()
        return

    def test_open_channel_fails_fast_when_transport_is_closed(self):
        self.peer_answer = "silent"
        self.mock_transport.active = False

        start = time.monotonic()
        with self.assertRaises(ConnectionError) as ctx:
            self.connection.open_channel(timeout=30)

        self.assertLess(time.monotonic() - start, 5)
        self.assertIn("transport closed", str(ctx.exception))
        return

    def test_open_direct_tcpip_channel_sends_addresses(self):
        chan = self.connection.open_channel("direct-tcpip", dest_addr=("db.internal", 5432),
                                            src_addr=("127.0.0.1", 40000))

        self.assertTrue(chan.active)
        kind, _, extra = self.opens[0]
        self.assertEqual(kind, b"direct-tcpip")
        extra_pkt = SshPacket(payload=extra)
        self.assertEqual(extra_pkt.get_string(), b"db.internal")
        self.assertEqual(extra_pkt.get_uint32(), 5432)
        self.assertEqual(extra_pkt.get_string(), b"127.0.0.1")
        self.assertEqual(extra_pkt.get_uint32(), 40000)
        return

    def test_open_direct_tcpip_channel_requires_addresses(self):
        with self.assertRaises(SemanticError):
            self.connection.open_channel("direct-tcpip")
        self.assertEqual(self.opens, [])
        return

    def test_open_channel_refuses_to_block_the_transport_thread(self):
        outcome = {}

        def on_transport_thread():
            try:
                self.connection.open_channel()
            except SemanticError as xcpt:
                outcome["error"] = xcpt
            return

        transport_thread = threading.Thread(target=on_transport_thread, daemon=True)
        self.connection.transport = transport_thread
        transport_thread.start()
        transport_thread.join(timeout=5)

        self.assertIn("error", outcome)
        self.assertIn("reader thread", str(outcome["error"]))
        return

    # --- CHANNEL_CLOSE is sent exactly once (RFC 4254 section 5.3) ---

    def test_peer_close_is_answered_once_and_local_close_does_not_repeat_it(self):
        chan = self.connection.open_channel()

        self._dispatch_close(chan)
        self.assertEqual(self._sent_close_recipients(), [PEER_CHANNEL_ID])

        chan.close()
        self.assertEqual(self._sent_close_recipients(), [PEER_CHANNEL_ID])
        return

    def test_local_close_is_sent_once_and_not_repeated_when_peer_answers(self):
        chan = self.connection.open_channel()

        chan.close()
        self.assertEqual(self._sent_close_recipients(), [PEER_CHANNEL_ID])

        self._dispatch_close(chan)
        chan.close()
        self.assertEqual(self._sent_close_recipients(), [PEER_CHANNEL_ID])
        return

    def test_data_received_before_peer_close_stays_readable(self):
        chan = self.connection.open_channel()

        self._dispatch_data(chan, b"last words")
        self._dispatch_close(chan)

        self.assertEqual(chan.recv(timeout=1), b"last words")
        self.assertEqual(chan.recv(timeout=1), b"")
        return

    # --- Channel request wire format (RFC 4254 sections 5.4 and 6) ---

    def _last_channel_request(self):
        requests = self._sent_packets(sshconstants.SSH_MSG_CHANNEL_REQUEST)
        request = requests[-1]
        request._position = 0
        recipient = request.get_uint32()
        request_type = request.get_string()
        want_reply = request.get_boolean()
        return recipient, request_type, want_reply, request

    def _dispatch_channel_request(self, chan, request_type: str, want_reply: bool, data: bytes = b""):
        pkt = SshPacket(payload=bytes([sshconstants.SSH_MSG_CHANNEL_REQUEST]))
        pkt.add_uint32(chan.local_id)
        pkt.add_string(request_type)
        pkt.add_boolean(want_reply)
        pkt.add_bytes(data)
        pkt._position = 0

        self.connection.dispatch_message(pkt)
        return

    def test_request_exec_sends_command_as_length_prefixed_string(self):
        chan = self.connection.open_channel()

        chan.request_exec("echo h\u00e9llo")

        recipient, request_type, want_reply, request = self._last_channel_request()
        self.assertEqual(recipient, PEER_CHANNEL_ID)
        self.assertEqual(request_type, b"exec")
        self.assertTrue(want_reply)
        self.assertEqual(request.get_string(), "echo h\u00e9llo".encode("utf-8"))
        self.assertEqual(bytes(request.remaining), b"")
        return

    def test_request_exec_sends_bytes_command_as_is(self):
        chan = self.connection.open_channel()

        # Not valid UTF-8: bytes must go out untouched.
        chan.request_exec(b"cat /tmp/\xff")

        _, _, _, request = self._last_channel_request()
        self.assertEqual(request.get_string(), b"cat /tmp/\xff")
        self.assertEqual(bytes(request.remaining), b"")
        return

    def test_request_subsystem_sends_name_as_length_prefixed_string(self):
        chan = self.connection.open_channel()

        chan.request_subsystem("sftp")

        recipient, request_type, want_reply, request = self._last_channel_request()
        self.assertEqual(recipient, PEER_CHANNEL_ID)
        self.assertEqual(request_type, b"subsystem")
        self.assertTrue(want_reply)
        self.assertEqual(request.get_string(), b"sftp")
        self.assertEqual(bytes(request.remaining), b"")
        return

    def test_request_shell_has_no_type_specific_data(self):
        chan = self.connection.open_channel()

        chan.request_shell()

        _, request_type, want_reply, request = self._last_channel_request()
        self.assertEqual(request_type, b"shell")
        self.assertTrue(want_reply)
        self.assertEqual(bytes(request.remaining), b"")
        return

    def test_send_request_rejects_unencoded_data(self):
        chan = self.connection.open_channel()

        with self.assertRaises(SemanticError):
            chan._send_request("exec", want_reply=True, data="uname -a")
        self.assertEqual(self._sent_packets(sshconstants.SSH_MSG_CHANNEL_REQUEST), [])
        return

    def test_exit_status_request_sets_exit_status(self):
        chan = self.connection.open_channel()
        self.assertFalse(chan.exit_status_ready())

        status_data = SshPacket()
        status_data.add_uint32(3)
        self._dispatch_channel_request(chan, "exit-status", want_reply=False, data=bytes(status_data.payload))

        self.assertTrue(chan.exit_status_ready())
        self.assertEqual(chan.recv_exit_status(), 3)
        # RFC 4254 section 6.10: no acknowledgement is sent for exit-status.
        self.assertEqual(self._sent_packets(sshconstants.SSH_MSG_CHANNEL_SUCCESS), [])
        self.assertEqual(self._sent_packets(sshconstants.SSH_MSG_CHANNEL_FAILURE), [])
        return

    def test_exit_signal_request_records_signal(self):
        chan = self.connection.open_channel()

        signal_data = SshPacket()
        signal_data.add_string("KILL")
        signal_data.add_boolean(True)
        signal_data.add_string("Killed")
        signal_data.add_string("") # language tag
        with self.assertLogs("ccai.protocols.ssh.sshconnection", level="WARNING"):
            self._dispatch_channel_request(chan, "exit-signal", want_reply=False, data=bytes(signal_data.payload))

        self.assertTrue(chan.exit_status_ready())
        self.assertEqual(chan.recv_exit_status(), -1)
        self.assertEqual(chan.exit_signal, "KILL")
        self.assertTrue(chan.exit_signal_core_dumped)
        self.assertEqual(chan.exit_signal_message, "Killed")
        return

    def test_unsupported_channel_request_wanting_reply_is_answered_with_failure(self):
        chan = self.connection.open_channel()

        self._dispatch_channel_request(chan, "keepalive@openssh.com", want_reply=True)

        failures = self._sent_packets(sshconstants.SSH_MSG_CHANNEL_FAILURE)
        self.assertEqual(len(failures), 1)
        failures[0]._position = 0
        self.assertEqual(failures[0].get_uint32(), PEER_CHANNEL_ID)
        return

    def test_unsupported_channel_request_without_reply_is_not_answered(self):
        chan = self.connection.open_channel()

        self._dispatch_channel_request(chan, "xon-xoff", want_reply=False, data=b"\x01")

        self.assertEqual(self._sent_packets(sshconstants.SSH_MSG_CHANNEL_FAILURE), [])
        self.assertEqual(self._sent_packets(sshconstants.SSH_MSG_CHANNEL_SUCCESS), [])
        return

    def test_exit_status_is_ready_when_peer_closes_without_one(self):
        chan = self.connection.open_channel()

        self._dispatch_close(chan)

        self.assertTrue(chan.exit_status_ready())
        self.assertEqual(chan.recv_exit_status(), -1)
        return

    def test_global_request_wanting_reply_is_answered_with_request_failure(self):
        pkt = SshPacket(payload=bytes([sshconstants.SSH_MSG_GLOBAL_REQUEST]))
        pkt.add_string("keepalive@openssh.com")
        pkt.add_boolean(True)
        pkt._position = 0
        self.connection.dispatch_message(pkt)

        pkt = SshPacket(payload=bytes([sshconstants.SSH_MSG_GLOBAL_REQUEST]))
        pkt.add_string("hostkeys-00@openssh.com")
        pkt.add_boolean(False)
        pkt.add_string(b"key-blob")
        pkt._position = 0
        self.connection.dispatch_message(pkt)

        failures = self._sent_packets(sshconstants.SSH_MSG_REQUEST_FAILURE)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0].to_bytes(), bytes([sshconstants.SSH_MSG_REQUEST_FAILURE]))
        return

    # --- recv() honours size (keeps leftovers) ---

    def _dispatch_eof(self, chan):
        pkt = SshPacket(payload=bytes([sshconstants.SSH_MSG_CHANNEL_EOF]))
        pkt.add_uint32(chan.local_id)
        pkt._position = 0

        self.connection.dispatch_message(pkt)
        return

    def test_recv_returns_at_most_size_and_keeps_the_rest(self):
        chan = self.connection.open_channel()

        self._dispatch_data(chan, b"abcdefgh")
        self.assertEqual(chan.recv(3, timeout=1), b"abc")
        self.assertTrue(chan.recv_ready())
        self.assertEqual(chan.recv(3, timeout=1), b"def")
        self.assertEqual(chan.recv(10, timeout=1), b"gh")
        self.assertFalse(chan.recv_ready())

        self._dispatch_data(chan, b"ij")
        self._dispatch_data(chan, b"kl")
        self.assertEqual(chan.recv(1, timeout=1), b"i")
        self.assertEqual(chan.recv(10, timeout=1), b"j")
        self.assertEqual(chan.recv(10, timeout=1), b"kl")
        return

    def test_recv_stderr_returns_at_most_size_and_keeps_the_rest(self):
        chan = self.connection.open_channel()

        self._dispatch_extended_data(chan, b"oops")
        self.assertTrue(chan.recv_stderr_ready())
        self.assertFalse(chan.recv_ready())
        self.assertEqual(chan.recv_stderr(2, timeout=1), b"oo")
        self.assertEqual(chan.recv_stderr(10, timeout=1), b"ps")
        self.assertFalse(chan.recv_stderr_ready())
        return

    def test_concurrent_readers_neither_lose_nor_duplicate_bytes(self):
        chan = self.connection.open_channel()
        payload = bytes(range(256)) * 40
        for offset in range(0, len(payload), 1000):
            self._dispatch_data(chan, payload[offset:offset + 1000])
        self._dispatch_eof(chan)

        received = [[], []]

        def reader(index):
            chunk = chan.recv(7, timeout=5)
            while len(chunk) > 0:
                received[index].append(chunk)
                chunk = chan.recv(7, timeout=5)
            return

        threads = [threading.Thread(target=reader, args=(index,), daemon=True) for index in (0, 1)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        chunk_sizes = [len(chunk) for chunk in received[0] + received[1]]
        self.assertLessEqual(max(chunk_sizes), 7)
        all_bytes = b"".join(received[0]) + b"".join(received[1])
        self.assertEqual(sorted(all_bytes), sorted(payload))
        return

    def test_empty_data_packet_is_not_end_of_stream(self):
        chan = self.connection.open_channel()

        self._dispatch_data(chan, b"")
        self._dispatch_data(chan, b"x")

        self.assertEqual(chan.recv(10, timeout=1), b"x")
        return

    def test_recv_rejects_size_below_one(self):
        chan = self.connection.open_channel()

        with self.assertRaises(SemanticError):
            chan.recv(0)
        return

    # --- The peer's CHANNEL_EOF (RFC 4254 section 5.3) ---

    def test_peer_eof_ends_the_stream_once_buffered_data_is_read(self):
        chan = self.connection.open_channel()

        self._dispatch_data(chan, b"tail")
        self._dispatch_eof(chan)

        self.assertTrue(chan.eof_received)
        self.assertFalse(chan.closed)
        self.assertEqual(chan.recv(10, timeout=5), b"tail")

        start = time.monotonic()
        self.assertEqual(chan.recv(10, timeout=5), b"")
        self.assertEqual(chan.recv(10, timeout=5), b"")
        self.assertEqual(chan.recv_stderr(10, timeout=5), b"")
        self.assertLess(time.monotonic() - start, 1, "recv() should not wait for data after the peer's EOF")
        return

    def test_peer_eof_wakes_a_blocked_reader(self):
        chan = self.connection.open_channel()
        outcome = {}

        def reader():
            outcome["data"] = chan.recv(10)
            return

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        time.sleep(0.1)
        self._dispatch_eof(chan)
        thread.join(timeout=5)

        self.assertFalse(thread.is_alive(), "a reader blocked in recv() should wake at the peer's EOF")
        self.assertEqual(outcome["data"], b"")
        return

    def test_sending_is_still_allowed_after_peer_eof(self):
        chan = self.connection.open_channel()

        self._dispatch_eof(chan)
        sent = chan.send(b"still talking")

        self.assertEqual(sent, 13)
        self.assertEqual(self._sent_data_chunk_sizes(), [13])
        return

    def test_shutdown_write_sends_eof_once_and_blocks_further_sends(self):
        chan = self.connection.open_channel()

        chan.shutdown_write()
        chan.shutdown_write()

        eofs = self._sent_packets(sshconstants.SSH_MSG_CHANNEL_EOF)
        self.assertEqual(len(eofs), 1)
        eofs[0]._position = 0
        self.assertEqual(eofs[0].get_uint32(), PEER_CHANNEL_ID)
        self.assertTrue(chan.eof_sent)

        with self.assertRaises(ConnectionError) as ctx:
            chan.send(b"too late")
        self.assertIn("shutdown_write", str(ctx.exception))
        self.assertEqual(self._sent_data_chunk_sizes(), [])
        return

    def test_shutdown_write_after_close_sends_nothing(self):
        chan = self.connection.open_channel()

        chan.close()
        chan.shutdown_write()

        self.assertEqual(self._sent_packets(sshconstants.SSH_MSG_CHANNEL_EOF), [])
        return

    # --- Replies to our want-reply channel requests (RFC 4254 section 5.4) ---

    def test_request_waits_for_the_peers_success(self):
        chan = self.connection.open_channel()
        self.peer_request_answer = "success-later"

        start = time.monotonic()
        chan.request_pty()

        self.assertGreaterEqual(time.monotonic() - start, 0.15, "request_pty() should wait for the peer's answer")
        self.assertTrue(chan.active)
        self.assertFalse(chan.closed)
        return

    def test_refused_request_raises_with_context_and_closes_the_channel(self):
        chan = self.connection.open_channel()
        self.peer_request_answer = "failure"

        with self.assertRaises(ConnectionError) as ctx:
            chan.request_subsystem("sftp")

        err_msg = str(ctx.exception)
        self.assertIn("refused the 'subsystem' request", err_msg)
        self.assertIn("local_id=0 remote_id=100", err_msg)
        self.assertIn("Subsystem sftp", err_msg)
        self.assertTrue(chan.closed)
        self.assertEqual(self._sent_close_recipients(), [PEER_CHANNEL_ID])
        return

    def test_each_request_type_raises_when_refused(self):
        calls = {
            "pty-req": lambda chan: chan.request_pty(),
            "shell": lambda chan: chan.request_shell(),
            "exec": lambda chan: chan.request_exec("uname -a"),
            "subsystem": lambda chan: chan.request_subsystem("sftp"),
        }
        self.peer_request_answer = "failure"

        for request_type, call in calls.items():
            chan = self.connection.open_channel()
            with self.assertRaises(ConnectionError) as ctx:
                call(chan)
            self.assertIn("refused the '{}' request".format(request_type), str(ctx.exception))
        return

    def test_request_times_out_and_a_late_answer_stays_matched_to_it(self):
        chan = self.connection.open_channel()
        self.peer_request_answer = "silent"

        with self.assertRaises(TimeoutError) as ctx:
            chan.request_exec("sleep 60", timeout=0.2)
        self.assertIn("SSH_MSG_CHANNEL_SUCCESS / SSH_MSG_CHANNEL_FAILURE", str(ctx.exception))
        self.assertIn("REQUEST: exec", str(ctx.exception))

        # The peer answers requests in order: its late answer belongs to the abandoned 'exec', not to the next
        # request.
        with self.assertLogs("ccai.protocols.ssh.sshconnection", level="WARNING"):
            self._dispatch_request_reply(chan.local_id, succeeded=False)

        self.peer_request_answer = "success"
        chan.request_shell(timeout=1)
        self.assertFalse(chan.closed)
        return

    def test_request_uses_connection_channel_timeout_by_default(self):
        chan = self.connection.open_channel()
        self.peer_request_answer = "silent"
        self.connection.channel_timeout = 0.1

        with self.assertRaises(TimeoutError):
            chan.request_shell()
        return

    def test_request_fails_when_channel_closes_while_waiting(self):
        chan = self.connection.open_channel()
        self.peer_request_answer = "silent"
        outcome = {}

        def requester():
            try:
                chan.request_exec("uname -a", timeout=10)
            except ConnectionError as xcpt:
                outcome["error"] = xcpt
            return

        thread = threading.Thread(target=requester, daemon=True)
        thread.start()
        time.sleep(0.1)
        self._dispatch_close(chan)
        thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertIn("closed before the peer answered the 'exec' request", str(outcome.get("error")))
        return

    def test_window_change_does_not_wait_for_a_reply(self):
        chan = self.connection.open_channel()
        self.peer_request_answer = "silent"

        start = time.monotonic()
        chan.resize_pty(120, 40)

        self.assertLess(time.monotonic() - start, 1)
        _, request_type, want_reply, _ = self._last_channel_request()
        self.assertEqual(request_type, b"window-change")
        self.assertFalse(want_reply)
        return

    def test_unexpected_request_reply_is_ignored(self):
        chan = self.connection.open_channel()

        with self.assertLogs("ccai.protocols.ssh.sshconnection", level="WARNING"):
            self._dispatch_request_reply(chan.local_id, succeeded=True)
        self.assertFalse(chan.closed)
        return

if __name__ == '__main__':
    unittest.main()
