"""
SSH Connection Layer
"""
import os
import threading
import logging
import time

from collections import deque
from queue import Empty, Queue
from typing import Optional, Union

from ccai.errors.exceptions import SemanticError

from ccai.protocols.ssh import sshconstants
from ccai.protocols.ssh.sshconst import DEFAULT_SSH_TIMEOUT
from ccai.protocols.ssh.sshpacket import SshPacket

logger = logging.getLogger(__name__)

# RFC 4254 section 5.2: implementations must handle channel windows of up to 2^32 - 1 bytes and a window
# must never be increased above that value.
MAX_CHANNEL_WINDOW_SIZE = 0xFFFFFFFF

# How often, in seconds, a sender that is blocked on an exhausted remote window, or an opener that is waiting for
# the peer to confirm a channel, wakes up to check that the transport underneath the channel is still alive.
# The message it is waiting for, or a channel close, wakes it immediately.
WINDOW_WAIT_POLL_INTERVAL = 1.0

# Channel types whose SSH_MSG_CHANNEL_OPEN carries the connect-to and originator addresses (RFC 4254 section 7).
TCPIP_CHANNEL_KINDS = ("direct-tcpip", "forwarded-tcpip")

# Expert hints added to the error when the peer refuses a channel request with SSH_MSG_CHANNEL_FAILURE.
CHANNEL_REQUEST_FAILURE_HINTS = {
    "pty-req": "The server may not allow pseudo-terminals for this user (sshd_config 'PermitTTY', or 'no-pty' in "
               "authorized_keys).",
    "shell": "The server may not allow interactive shells for this user (for example 'ForceCommand' or a "
             "restricted shell).",
    "exec": "The server may restrict the commands this user can run (for example 'ForceCommand' in sshd_config or "
            "'command=' in authorized_keys).",
    "subsystem": "The server may not have this subsystem configured (for example 'Subsystem sftp ...' in "
                 "sshd_config).",
}

class SshChannel(threading.Thread):
    """
    Represents a logical channel within the SSH connection.
    Implements a file-like interface/socket-like interface.
    """
    def __init__(self, connection, local_id: int):
        super().__init__()
        self.connection = connection
        self.local_id = local_id
        self.remote_id = None
        self.max_packet_size = 32768
        # The maximum packet size the peer will accept, from SSH_MSG_CHANNEL_OPEN_CONFIRMATION.
        # RFC 4254 section 5.1: data sent to the peer must not exceed this size.
        self.remote_max_packet_size = None
        # The initial receive window advertised to the peer in SSH_MSG_CHANNEL_OPEN (RFC 4254 section 5.2).
        self.window_size = 1024 * 1024
        # The number of bytes the peer may still send before it must wait for an SSH_MSG_CHANNEL_WINDOW_ADJUST
        # from us.  It only goes negative if the peer overruns the window, which is logged.
        self.local_window = self.window_size
        # The number of bytes the peer is still willing to receive: the initial window from
        # SSH_MSG_CHANNEL_OPEN_CONFIRMATION plus every SSH_MSG_CHANNEL_WINDOW_ADJUST, minus the data sent since.
        # 'None' until the peer has announced a window, in which case sends are not window limited.
        self.remote_window = None
        # The default number of seconds 'send' waits for the peer to open an exhausted window before it
        # raises a TimeoutError.  'None' waits for as long as the channel and the transport stay open.
        self.send_timeout = DEFAULT_SSH_TIMEOUT
        self.active = False
        self.closed = False
        # Received data chunks for recv(), and stderr chunks (SSH_MSG_CHANNEL_EXTENDED_DATA of type
        # SSH_EXTENDED_DATA_STDERR) for recv_stderr().  An empty chunk is the end-of-stream marker that wakes a
        # blocked reader when the peer sends EOF or the channel closes.
        self.in_buffer = Queue()
        self.in_stderr_buffer = Queue()
        # The bytes of a received chunk that did not fit in the caller's 'size'; the next read returns them first.
        # Only touched while holding the stream's reader lock, which also keeps concurrent readers in order.
        self._in_pending = bytearray()
        self._in_stderr_pending = bytearray()
        self._recv_lock = threading.Lock()
        self._recv_stderr_lock = threading.Lock()
        # True once the peer sent SSH_MSG_CHANNEL_EOF: it sends no more data, but may still receive (RFC 4254
        # section 5.3).  True once we sent SSH_MSG_CHANNEL_EOF with shutdown_write(): we send no more data.
        self.eof_received = False
        self.eof_sent = False
        # Our want-reply channel requests that are waiting for SSH_MSG_CHANNEL_SUCCESS / FAILURE, oldest first.
        # The peer answers requests in order (RFC 4254 section 5.4); '_request_lock' keeps the queue in the order
        # the requests are put on the wire.
        self._pending_requests = deque()
        self._request_lock = threading.Lock()
        # The command's exit status from the peer's "exit-status" request, or -1 once the peer reported that the
        # command was killed by a signal ("exit-signal", RFC 4254 section 6.10).
        self.exit_status = None
        # The details of an "exit-signal" request: the signal name without the "SIG" prefix, whether a core was
        # dumped, and the peer's error message.
        self.exit_signal = None
        self.exit_signal_core_dumped = None
        self.exit_signal_message = None
        # RFC 4254 section 5.3: each side sends SSH_MSG_CHANNEL_CLOSE exactly once, whichever side closes first.
        self._close_sent = False
        self._close_received = False
        # The (reason code, description) from SSH_MSG_CHANNEL_OPEN_FAILURE, if the peer refused the channel.
        self._open_failure = None
        # The number of received bytes the application has consumed since the last WINDOW_ADJUST we sent.
        self._local_window_consumed = 0
        # Guards the window accounting and the 'closed' flag, and wakes senders that are blocked on an
        # exhausted remote window when a WINDOW_ADJUST arrives or the channel closes.
        self._window_condition = threading.Condition(threading.Lock())
        return

    def open(self):
        # Already opened by Connection?
        self.active = True

    def send(self, data: Union[bytes, str], *, timeout: Optional[float] = None) -> int:
        """
            Sends data to the peer on this channel, honoring the RFC 4254 section 5.2 flow control.

            The data is split into SSH_MSG_CHANNEL_DATA packets that are no larger than the smaller of the local
            and the peer's maximum packet size, and never larger than what remains of the peer's window.  When the
            peer's window is exhausted the call blocks until the peer sends SSH_MSG_CHANNEL_WINDOW_ADJUST, the
            channel closes, or the timeout expires.

            :param data: The data to send.  A ``str`` is encoded as UTF-8 so the window accounting is in bytes.
            :param timeout: The maximum number of seconds to wait each time the peer's window is exhausted.  When
                            ``None`` the channel's ``send_timeout`` is used.

            :returns: The number of bytes sent, which is always the full length of the data.
            :raises: ConnectionError, TimeoutError
        """
        if not self.active or self.closed:
            raise ConnectionError("Channel closed")

        if self.eof_sent is True:
            err_msg_lines = [
                "Cannot send on SSH channel local_id={} remote_id={} after shutdown_write().".format(
                    self.local_id, self.remote_id),
                "shutdown_write() sent SSH_MSG_CHANNEL_EOF, after which no more data may be sent (RFC 4254 "
                "section 5.3).",
            ]
            err_msg = os.linesep.join(err_msg_lines)
            raise ConnectionError(err_msg)

        if isinstance(data, str):
            data = data.encode('utf-8')

        wait_timeout = timeout
        if wait_timeout is None:
            wait_timeout = self.send_timeout

        # Split into chunks no larger than the smaller of the local and the peer's
        # maximum packet size (RFC 4254 section 5.1).
        chunk_size = self.max_packet_size
        if self.remote_max_packet_size is not None and self.remote_max_packet_size < chunk_size:
            chunk_size = self.remote_max_packet_size

        total_length = len(data)
        sent_length = 0
        while sent_length < total_length:
            wanted_length = total_length - sent_length
            if wanted_length > chunk_size:
                wanted_length = chunk_size

            # Reserve the window for this packet under the lock, but put the packet on the wire outside of the
            # lock so the transport thread can always deliver a WINDOW_ADJUST or data while we are writing.
            packet_length = self._reserve_remote_window(wanted_length, wait_timeout, sent_length, total_length)

            chunk = data[sent_length:sent_length + packet_length]
            pkt = SshPacket(sshconstants.SSH_MSG_CHANNEL_DATA)
            pkt.add_uint32(self.remote_id)
            pkt.add_string(chunk)
            self.connection.transport.send_packet(pkt)

            sent_length += packet_length

        return sent_length

    def _reserve_remote_window(self, wanted_length: int, timeout: Optional[float], sent_length: int,
                               total_length: int) -> int:
        """
            Waits until the peer's window has room and then takes up to ``wanted_length`` bytes out of it.

            :param wanted_length: The number of bytes the caller would like to send in the next packet.
            :param timeout: The maximum number of seconds to wait for an exhausted window, ``None`` to wait for as
                            long as the channel and the transport stay open.
            :param sent_length: The number of bytes of the current send that are already on the wire (for errors).
            :param total_length: The total number of bytes in the current send (for errors).

            :returns: The number of bytes reserved, between 1 and ``wanted_length``.
            :raises: ConnectionError, TimeoutError
        """
        reserved_length = wanted_length

        with self._window_condition:
            wait_start = time.monotonic()

            while True:
                if self.closed is True:
                    err_msg = self._format_window_wait_error(
                        "The SSH channel closed while sending data.", timeout, wait_start, sent_length, total_length)
                    raise ConnectionError(err_msg)

                if self.remote_window is None:
                    # The peer has not announced a window (the channel was activated without an
                    # SSH_MSG_CHANNEL_OPEN_CONFIRMATION), so there is no window to enforce.
                    return reserved_length

                if self.remote_window > 0:
                    break

                transport_active = self.connection.transport.active
                if transport_active is False:
                    err_msg = self._format_window_wait_error(
                        "The SSH transport closed while waiting for the peer to open its channel window.",
                        timeout, wait_start, sent_length, total_length)
                    raise ConnectionError(err_msg)

                wait_time = WINDOW_WAIT_POLL_INTERVAL
                if timeout is not None:
                    waited = time.monotonic() - wait_start
                    remaining = timeout - waited
                    if remaining <= 0:
                        err_msg = self._format_window_wait_error(
                            "Timed out waiting for the SSH peer to open its channel window "
                            "(SSH_MSG_CHANNEL_WINDOW_ADJUST).", timeout, wait_start, sent_length, total_length)
                        raise TimeoutError(err_msg)
                    if remaining < wait_time:
                        wait_time = remaining

                self._window_condition.wait(timeout=wait_time)

            if self.remote_window < reserved_length:
                reserved_length = self.remote_window
            self.remote_window -= reserved_length

        return reserved_length

    def _format_window_wait_error(self, headline: str, timeout: Optional[float], wait_start: float,
                                  sent_length: int, total_length: int) -> str:
        """
            Builds the error message for a send that could not complete because of the channel's flow control.

            :param headline: The first line of the message, describing what went wrong.
            :param timeout: The timeout that was in effect for the wait.
            :param wait_start: The ``time.monotonic()`` value when the wait started.
            :param sent_length: The number of bytes of the send that are already on the wire.
            :param total_length: The total number of bytes in the send.

            :returns: The multi-line error message.
        """
        waited = time.monotonic() - wait_start

        err_msg_lines = [
            headline,
            "CHANNEL: local_id={} remote_id={}".format(self.local_id, self.remote_id),
            "PROGRESS: sent {} of {} bytes".format(sent_length, total_length),
            "REMOTE WINDOW: {} bytes (peer max packet size={})".format(self.remote_window,
                                                                      self.remote_max_packet_size),
            "TIMEOUT: {} seconds (waited {:.3f} seconds)".format(timeout, waited),
            "",
            "RFC 4254 section 5.2: once the peer's window is exhausted no more data may be sent until the peer",
            "sends SSH_MSG_CHANNEL_WINDOW_ADJUST.  The remote side is not consuming the data sent to it; check that",
            "the remote process is reading its input, or pass a larger 'timeout' / set the channel's 'send_timeout'.",
        ]

        err_msg = os.linesep.join(err_msg_lines)
        return err_msg

    def recv(self, size: int = 1024, timeout: Optional[float] = None) -> bytes:
        """
            Reads up to ``size`` bytes of data from the channel.  The bytes of a received packet that do not fit are
            kept and returned first by the next call, so callers can read exact amounts (for example SFTP framing).

            :param size: The maximum number of bytes to return.
            :param timeout: The maximum number of seconds to wait for data, ``None`` to wait until data arrives or
                            the stream ends.

            :returns: Between 1 and ``size`` bytes, or ``b""`` if the timeout expired or the stream ended (the peer
                      sent EOF or the channel closed; check ``eof_received`` / ``closed`` to tell them apart).
            :raises: SemanticError if ``size`` is less than 1.
        """
        data = self._read_stream(self.in_buffer, self._in_pending, self._recv_lock, size, timeout)
        return data

    def recv_stderr(self, size: int = 1024, timeout: Optional[float] = None) -> bytes:
        """
            Reads up to ``size`` bytes of the peer's stderr (SSH_MSG_CHANNEL_EXTENDED_DATA of type
            SSH_EXTENDED_DATA_STDERR).  Stderr shares the channel window with ordinary data (RFC 4254 section 5.2),
            so as in paramiko a caller that lets stderr pile up unread eventually stalls the peer.

            :param size: The maximum number of bytes to return.
            :param timeout: The maximum number of seconds to wait for data, ``None`` to wait until data arrives or
                            the stream ends.

            :returns: Between 1 and ``size`` bytes, or ``b""`` if the timeout expired or the stream ended.
            :raises: SemanticError if ``size`` is less than 1.
        """
        data = self._read_stream(self.in_stderr_buffer, self._in_stderr_pending, self._recv_stderr_lock, size,
                                 timeout)
        return data

    def _read_stream(self, stream_buffer: Queue, pending: bytearray, reader_lock: threading.Lock, size: int,
                     timeout: Optional[float]) -> bytes:
        """
            Reads up to ``size`` bytes from one of the channel's receive streams and gives the consumed bytes back
            to the peer's window.

            :param stream_buffer: The queue of received chunks.
            :param pending: The leftover bytes of the last chunk taken from the queue.
            :param reader_lock: The lock that serializes readers of this stream.
            :param size: The maximum number of bytes to return.
            :param timeout: The maximum number of seconds to wait, ``None`` to wait for data or the end of stream.

            :returns: Between 1 and ``size`` bytes, or ``b""`` on timeout or at the end of the stream.
            :raises: SemanticError if ``size`` is less than 1.
        """
        if size < 1:
            err_msg = "The 'size' passed to recv() / recv_stderr() must be at least 1, not {}.".format(size)
            raise SemanticError(err_msg)

        wait_start = time.monotonic()
        if timeout is None:
            acquired = reader_lock.acquire()
        else:
            acquired = reader_lock.acquire(timeout=timeout)

        data = b""
        if acquired is True:
            try:
                remaining = None
                if timeout is not None:
                    remaining = timeout - (time.monotonic() - wait_start)
                    if remaining < 0:
                        remaining = 0

                data = self._read_stream_locked(stream_buffer, pending, size, remaining)
            finally:
                reader_lock.release()

        data_length = len(data)
        if data_length > 0:
            # The application has consumed this data, so the peer may be given room to send more.
            self._consume_local_window(data_length)

        return data

    def _read_stream_locked(self, stream_buffer: Queue, pending: bytearray, size: int,
                            timeout: Optional[float]) -> bytes:
        """
            The body of :meth:`_read_stream`, called while holding the stream's reader lock.

            :returns: Between 1 and ``size`` bytes, or ``b""`` on timeout or at the end of the stream.
        """
        if len(pending) == 0:
            receive_finished = self.closed is True or self.eof_received is True
            if receive_finished is True and stream_buffer.empty():
                return b""

            try:
                chunk = stream_buffer.get(timeout=timeout)
            except Empty:
                return b""

            if len(chunk) == 0:
                # The end-of-stream marker queued by handle_eof() / handle_close().
                return b""

            pending.extend(chunk)

        data = bytes(pending[:size])
        del pending[:size]
        return data

    def _signal_end_of_stream(self):
        """
            Wakes readers that are blocked on either receive stream so they see the end of the stream.
        """
        self.in_buffer.put(b"")
        self.in_stderr_buffer.put(b"")
        return

    def close(self):
        """
            Closes the channel.  SSH_MSG_CHANNEL_CLOSE is sent to the peer exactly once (RFC 4254 section 5.3): not
            at all if it was already sent in reply to the peer's close, and deferred until the peer confirms the
            channel if the channel was abandoned before its SSH_MSG_CHANNEL_OPEN_CONFIRMATION arrived.
        """
        with self._window_condition:
            self.closed = True
            # Wake any sender that is blocked on an exhausted remote window so it can fail fast.
            self._window_condition.notify_all()
            remote_id = self._claim_close_locked()

        if remote_id is not None:
            self._send_close(remote_id)
        return

    def _claim_close_locked(self) -> Optional[int]:
        """
            Decides, while holding the channel lock, whether this caller is the one that sends our
            SSH_MSG_CHANNEL_CLOSE.  It is sent only once, and only once the peer's channel number is known.

            :returns: The peer's channel number if the caller must send the close, otherwise None.
        """
        remote_id = None
        if self._close_sent is False and self.remote_id is not None:
            self._close_sent = True
            remote_id = self.remote_id
        return remote_id

    def _send_close(self, remote_id: int):
        """
            Sends SSH_MSG_CHANNEL_CLOSE to the peer.

            :param remote_id: The peer's channel number.
        """
        pkt = SshPacket(sshconstants.SSH_MSG_CHANNEL_CLOSE)
        pkt.add_uint32(remote_id)
        self.connection.transport.send_packet(pkt)
        return

    def request_shell(self, *, timeout: Optional[float] = None):
        """
            Asks the peer to start a shell on this channel (RFC 4254 section 6.5) and waits for its answer.

            :param timeout: The maximum number of seconds to wait for the answer, ``None`` for the connection's
                            ``channel_timeout``.

            :raises: ConnectionError if the peer refuses (the channel is then closed, as in paramiko),
                     TimeoutError if it does not answer in time.
        """
        self._send_request("shell", want_reply=True, timeout=timeout)
        return

    def request_exec(self, command: Union[str, bytes], *, timeout: Optional[float] = None):
        """
            Asks the peer to run a command on this channel (RFC 4254 section 6.5) and waits for its answer: the
            command is sent as an SSH ``string``, a uint32 length followed by the bytes.

            :param command: The command line.  A ``str`` is encoded as UTF-8, ``bytes`` are sent as they are.
            :param timeout: The maximum number of seconds to wait for the answer, ``None`` for the connection's
                            ``channel_timeout``.

            :raises: ConnectionError if the peer refuses (the channel is then closed, as in paramiko),
                     TimeoutError if it does not answer in time.
        """
        data = SshPacket()
        data.add_string(command)

        self._send_request("exec", want_reply=True, data=data.payload, timeout=timeout)
        return

    def request_subsystem(self, subsystem: Union[str, bytes], *, timeout: Optional[float] = None):
        """
            Asks the peer to start a subsystem, for example ``sftp``, on this channel (RFC 4254 section 6.5) and waits
            for its answer: the subsystem name is sent as an SSH ``string``, a uint32 length followed by the bytes.

            :param subsystem: The subsystem name.  A ``str`` is encoded as UTF-8, ``bytes`` are sent as they are.
            :param timeout: The maximum number of seconds to wait for the answer, ``None`` for the connection's
                            ``channel_timeout``.

            :raises: ConnectionError if the peer refuses (the channel is then closed, as in paramiko),
                     TimeoutError if it does not answer in time.
        """
        data = SshPacket()
        data.add_string(subsystem)

        self._send_request("subsystem", want_reply=True, data=data.payload, timeout=timeout)
        return

    def request_pty(self, term: str = 'vt100', width: int = 80, height: int = 24, 
                    pixel_width: int = 0, pixel_height: int = 0, modes: dict = None, *,
                    timeout: Optional[float] = None):
        """
            Asks the peer for a pseudo-terminal on this channel (RFC 4254 section 6.2) and waits for its answer.

            :param timeout: The maximum number of seconds to wait for the answer, ``None`` for the connection's
                            ``channel_timeout``.

            :raises: ConnectionError if the peer refuses (the channel is then closed, as in paramiko),
                     TimeoutError if it does not answer in time.
        """
        if modes is None:
            modes = {}
            
        data = SshPacket()
        data.add_string(term)
        data.add_uint32(width)
        data.add_uint32(height)
        data.add_uint32(pixel_width)
        data.add_uint32(pixel_height)
        data.add_string(self._encode_terminal_modes(modes))
        
        self._send_request("pty-req", want_reply=True, data=data.payload, timeout=timeout)
        return

    def resize_pty(self, width: int, height: int, pixel_width: int = 0, pixel_height: int = 0):
        """
        Send a window-change request.
        """
        data = SshPacket()
        data.add_uint32(width)
        data.add_uint32(height)
        data.add_uint32(pixel_width)
        data.add_uint32(pixel_height)
        
        self._send_request("window-change", want_reply=False, data=data.payload)

    def _encode_terminal_modes(self, modes: dict) -> bytes:
        """
        Encode terminal modes dictionary into bytes.
        """
        pkt = SshPacket()
        for opcode, argument in modes.items():
            pkt.add_byte(opcode)
            pkt.add_uint32(argument)
        pkt.add_byte(sshconstants.TTY_OP_END)
        return pkt.payload

    def _send_request(self, request_type: str, want_reply: bool, data: Optional[Union[bytes, bytearray]] = None,
                      *, timeout: Optional[float] = None):
        """
            Sends SSH_MSG_CHANNEL_REQUEST (RFC 4254 section 5.4).  When ``want_reply`` is set it waits for the
            peer's SSH_MSG_CHANNEL_SUCCESS / FAILURE; the peer answers requests in the order they were sent.

            :param request_type: The request type, for example ``exec``.
            :param want_reply: Whether the peer should answer with SSH_MSG_CHANNEL_SUCCESS / FAILURE.
            :param data: The type-specific data, already encoded in SSH wire format (strings carry their uint32
                         length prefix).  It is appended to the message as is.
            :param timeout: The maximum number of seconds to wait for the answer, ``None`` for the connection's
                            ``channel_timeout``.

            :raises: SemanticError if ``data`` is not already encoded bytes, ConnectionError if the peer refuses the
                     request (the channel is then closed, as in paramiko) or the channel or transport closes,
                     TimeoutError if the peer does not answer in time.
        """
        if data is not None and not isinstance(data, (bytes, bytearray)):
            err_msg_lines = [
                "The type-specific data of a '{}' channel request must be SSH-encoded bytes, not {}.".format(
                    request_type, type(data).__name__),
                "Encode it with SshPacket (for example add_string) so strings carry their uint32 length prefix.",
            ]
            err_msg = os.linesep.join(err_msg_lines)
            raise SemanticError(err_msg)

        pkt = SshPacket(sshconstants.SSH_MSG_CHANNEL_REQUEST)
        pkt.add_uint32(self.remote_id)
        pkt.add_string(request_type)
        pkt.add_boolean(want_reply)
        if data is not None:
            pkt.add_bytes(data)

        if want_reply is False:
            self.connection.transport.send_packet(pkt)
            return

        wait_timeout = timeout
        if wait_timeout is None:
            wait_timeout = self.connection.channel_timeout

        # Queue the request before it goes on the wire: the transport thread may deliver the answer before this
        # thread starts waiting for it.
        pending_request = {"request_type": request_type, "succeeded": None, "abandoned": False}
        with self._request_lock:
            with self._window_condition:
                self._pending_requests.append(pending_request)
            try:
                self.connection.transport.send_packet(pkt)
            except Exception:
                # Nothing was sent, so no answer will come; keep the queue aligned with the peer's answers.
                with self._window_condition:
                    self._pending_requests.remove(pending_request)
                raise

        self._wait_for_request_reply(pending_request, wait_timeout)
        return

    def _wait_for_request_reply(self, pending_request: dict, timeout: Optional[float]):
        """
            Waits for the peer's SSH_MSG_CHANNEL_SUCCESS / FAILURE to a request queued by :meth:`_send_request`.

            :param pending_request: The queued request.
            :param timeout: The maximum number of seconds to wait, ``None`` for as long as the channel is open.

            :raises: ConnectionError if the peer refuses the request (the channel is then closed, as in paramiko)
                     or the channel or transport closes, TimeoutError if the peer does not answer in time.
        """
        request_type = pending_request["request_type"]

        with self._window_condition:
            wait_start = time.monotonic()

            while pending_request["succeeded"] is None:
                if self.closed is True:
                    err_msg = self._format_request_error(
                        "The SSH channel closed before the peer answered the '{}' request.".format(request_type),
                        request_type, timeout, wait_start)
                    raise ConnectionError(err_msg)

                transport_active = self.connection.transport.active
                if transport_active is False:
                    err_msg = self._format_request_error(
                        "The SSH transport closed before the peer answered the '{}' request.".format(request_type),
                        request_type, timeout, wait_start)
                    raise ConnectionError(err_msg)

                wait_time = WINDOW_WAIT_POLL_INTERVAL
                if timeout is not None:
                    waited = time.monotonic() - wait_start
                    remaining = timeout - waited
                    if remaining <= 0:
                        # The request stays queued so a late answer is still matched to it and not to the next one.
                        pending_request["abandoned"] = True
                        err_msg = self._format_request_error(
                            "Timed out waiting for the SSH peer to answer the '{}' request "
                            "(SSH_MSG_CHANNEL_SUCCESS / SSH_MSG_CHANNEL_FAILURE).".format(request_type),
                            request_type, timeout, wait_start)
                        raise TimeoutError(err_msg)
                    if remaining < wait_time:
                        wait_time = remaining

                self._window_condition.wait(timeout=wait_time)

            succeeded = pending_request["succeeded"]
            refused_msg = None
            if succeeded is False:
                refused_msg = self._format_request_error(
                    "The SSH peer refused the '{}' request (SSH_MSG_CHANNEL_FAILURE); the channel has been "
                    "closed.".format(request_type), request_type, timeout, wait_start)

        if refused_msg is not None:
            # paramiko closes the channel when one of these requests fails; the channel cannot be used as intended.
            self.close()
            raise ConnectionError(refused_msg)

        return

    def _format_request_error(self, headline: str, request_type: str, timeout: Optional[float],
                              wait_start: float) -> str:
        """
            Builds the error message for a channel request that did not succeed.

            :param headline: The first line of the message, describing what went wrong.
            :param request_type: The request type.
            :param timeout: The timeout that was in effect for the wait.
            :param wait_start: The ``time.monotonic()`` value when the wait started.

            :returns: The multi-line error message.
        """
        waited = time.monotonic() - wait_start

        err_msg_lines = [
            headline,
            "CHANNEL: local_id={} remote_id={}".format(self.local_id, self.remote_id),
            "REQUEST: {}".format(request_type),
            "TIMEOUT: {} seconds (waited {:.3f} seconds)".format(timeout, waited),
        ]
        hint = CHANNEL_REQUEST_FAILURE_HINTS.get(request_type)
        if hint is not None:
            err_msg_lines.append("")
            err_msg_lines.append(hint)

        err_msg = os.linesep.join(err_msg_lines)
        return err_msg

    def handle_request_reply(self, succeeded: bool):
        """
            Handles SSH_MSG_CHANNEL_SUCCESS / SSH_MSG_CHANNEL_FAILURE: the answer to our oldest want-reply request
            (RFC 4254 section 5.4 answers requests in order).

            :param succeeded: True for SSH_MSG_CHANNEL_SUCCESS, False for SSH_MSG_CHANNEL_FAILURE.
        """
        pending_request = None
        with self._window_condition:
            if len(self._pending_requests) > 0:
                pending_request = self._pending_requests.popleft()
                pending_request["succeeded"] = succeeded
                self._window_condition.notify_all()

        if pending_request is None:
            reply_name = "SSH_MSG_CHANNEL_FAILURE"
            if succeeded is True:
                reply_name = "SSH_MSG_CHANNEL_SUCCESS"
            logger.warning("Ignoring an %s on channel local_id=%s: no request is waiting for an answer.",
                           reply_name, self.local_id)
        elif pending_request["abandoned"] is True and succeeded is False:
            logger.warning("The SSH peer refused the '%s' request on channel local_id=%s after the caller stopped "
                           "waiting for the answer.", pending_request["request_type"], self.local_id)
        return

    def handle_request(self, request_type: str, want_reply: bool, packet: SshPacket):
        """
            Handles an SSH_MSG_CHANNEL_REQUEST from the peer (RFC 4254 section 5.4).  The command's "exit-status"
            and "exit-signal" (section 6.10) are recorded.  Any other request is not supported by this client and,
            if the peer wants a reply (for example OpenSSH's ``keepalive@openssh.com``), is answered with
            SSH_MSG_CHANNEL_FAILURE as the RFC requires.

            :param request_type: The request type.
            :param want_reply: Whether the peer expects SSH_MSG_CHANNEL_SUCCESS / FAILURE.
            :param packet: The message, positioned at the type-specific data.
        """
        handled = False

        if request_type == "exit-status":
            exit_status = packet.get_uint32()
            with self._window_condition:
                self.exit_status = exit_status
            handled = True

        elif request_type == "exit-signal":
            signal_name = packet.get_string().decode('utf-8', errors='replace')
            core_dumped = packet.get_boolean()
            error_message = packet.get_string().decode('utf-8', errors='replace')
            logger.warning("The command on channel local_id=%s was killed by signal %s (core dumped=%s): %s",
                           self.local_id, signal_name, core_dumped, error_message)
            with self._window_condition:
                self.exit_signal = signal_name
                self.exit_signal_core_dumped = core_dumped
                self.exit_signal_message = error_message
                # No exit status is returned for a signalled command; -1 is the value recv_exit_status() uses
                # for a missing status (as in paramiko).
                self.exit_status = -1
            handled = True

        else:
            logger.debug("Unsupported channel request '%s' (want_reply=%s) on channel local_id=%s.",
                         request_type, want_reply, self.local_id)

        if want_reply is True:
            reply_id = sshconstants.SSH_MSG_CHANNEL_SUCCESS
            if handled is False:
                reply_id = sshconstants.SSH_MSG_CHANNEL_FAILURE

            with self._window_condition:
                # Nothing more may be sent on the channel once our SSH_MSG_CHANNEL_CLOSE is out.
                remote_id = None
                if self._close_sent is False:
                    remote_id = self.remote_id

            if remote_id is not None:
                reply = SshPacket(reply_id)
                reply.add_uint32(remote_id)
                self.connection.transport.send_packet(reply)

        return

    def handle_open_confirmation(self, remote_id: int, window_size: int, max_packet_size: int):
        """
            Handles SSH_MSG_CHANNEL_OPEN_CONFIRMATION: records the peer's channel number, its maximum packet size
            and the initial window it is willing to receive (RFC 4254 sections 5.1 and 5.2), then opens the channel.

            :param remote_id: The peer's channel number.
            :param window_size: The peer's initial window size in bytes.
            :param max_packet_size: The largest data packet the peer will accept.
        """
        close_remote_id = None

        with self._window_condition:
            self.remote_id = remote_id
            self.remote_max_packet_size = max_packet_size
            self.remote_window = window_size

            if self.closed is True:
                # The channel was abandoned (its open timed out, or it was closed) before the peer confirmed it.
                # The peer now has an open channel, so close it rather than leaving it orphaned.
                close_remote_id = self._claim_close_locked()
            else:
                self.active = True

            self._window_condition.notify_all()

        if close_remote_id is not None:
            logger.warning("Closing channel local_id=%s remote_id=%s because the peer confirmed it after it was "
                           "abandoned.", self.local_id, remote_id)
            self._send_close(close_remote_id)
        return

    def handle_open_failure(self, reason_code: int, description: str):
        """
            Handles SSH_MSG_CHANNEL_OPEN_FAILURE: records why the peer refused the channel and wakes the opener.

            :param reason_code: The RFC 4254 section 5.1 reason code.
            :param description: The peer's description of the failure.
        """
        with self._window_condition:
            self._open_failure = (reason_code, description)
            self.closed = True
            self._window_condition.notify_all()

        self._signal_end_of_stream()
        return

    def wait_for_open(self, timeout: Optional[float], kind: str = "session"):
        """
            Waits for the peer to confirm the channel with SSH_MSG_CHANNEL_OPEN_CONFIRMATION.

            :param timeout: The maximum number of seconds to wait, ``None`` to wait for as long as the transport is
                            open.
            :param kind: The channel type that was requested (for errors).

            :raises: ConnectionError if the peer refuses the channel or the channel or transport closes,
                     TimeoutError if the peer does not answer in time.  A channel that times out is abandoned: it is
                     closed as soon as the peer confirms it.
        """
        with self._window_condition:
            wait_start = time.monotonic()

            while self.active is not True:
                if self._open_failure is not None:
                    reason_code, description = self._open_failure
                    reason_name = sshconstants.SSH_OPEN_FAILURE_REASON_NAMES.get(reason_code, "UNKNOWN")
                    err_msg = self._format_open_wait_error(
                        "The SSH peer refused to open a '{}' channel.".format(kind), kind, timeout, wait_start,
                        ["REASON: {} ({})".format(reason_name, reason_code),
                         "DESCRIPTION: {}".format(description)])
                    raise ConnectionError(err_msg)

                if self.closed is True:
                    err_msg = self._format_open_wait_error(
                        "The SSH channel closed before the peer confirmed it.", kind, timeout, wait_start, [])
                    raise ConnectionError(err_msg)

                transport_active = self.connection.transport.active
                if transport_active is False:
                    err_msg = self._format_open_wait_error(
                        "The SSH transport closed while waiting for the peer to confirm the channel.",
                        kind, timeout, wait_start, [])
                    raise ConnectionError(err_msg)

                wait_time = WINDOW_WAIT_POLL_INTERVAL
                if timeout is not None:
                    waited = time.monotonic() - wait_start
                    remaining = timeout - waited
                    if remaining <= 0:
                        # Abandon the channel so a late confirmation is answered with SSH_MSG_CHANNEL_CLOSE.
                        self.closed = True
                        err_msg = self._format_open_wait_error(
                            "Timed out waiting for the SSH peer to confirm the channel "
                            "(SSH_MSG_CHANNEL_OPEN_CONFIRMATION).", kind, timeout, wait_start, [])
                        raise TimeoutError(err_msg)
                    if remaining < wait_time:
                        wait_time = remaining

                self._window_condition.wait(timeout=wait_time)

        return

    def _format_open_wait_error(self, headline: str, kind: str, timeout: Optional[float], wait_start: float,
                                detail_lines: list) -> str:
        """
            Builds the error message for a channel that could not be opened.

            :param headline: The first line of the message, describing what went wrong.
            :param kind: The channel type that was requested.
            :param timeout: The timeout that was in effect for the wait.
            :param wait_start: The ``time.monotonic()`` value when the wait started.
            :param detail_lines: Additional lines describing the failure.

            :returns: The multi-line error message.
        """
        waited = time.monotonic() - wait_start

        err_msg_lines = [
            headline,
            "CHANNEL: kind={} local_id={}".format(kind, self.local_id),
        ]
        err_msg_lines.extend(detail_lines)
        err_msg_lines.append("TIMEOUT: {} seconds (waited {:.3f} seconds)".format(timeout, waited))

        err_msg = os.linesep.join(err_msg_lines)
        return err_msg

    def handle_window_adjust(self, bytes_to_add: int):
        """
            Handles SSH_MSG_CHANNEL_WINDOW_ADJUST: adds ``bytes_to_add`` to the peer's window and wakes any sender
            that is blocked on an exhausted window.  RFC 4254 section 5.2 says the window must never be increased
            above 2^32 - 1 bytes; a peer that tries is logged and the window is clamped to that maximum.

            :param bytes_to_add: The number of bytes the peer added to its window.
        """
        with self._window_condition:
            if self.remote_window is None:
                logger.warning("Ignoring SSH_MSG_CHANNEL_WINDOW_ADJUST of %d bytes for channel local_id=%s "
                               "because the peer has not confirmed the channel open yet.",
                               bytes_to_add, self.local_id)
            else:
                new_window = self.remote_window + bytes_to_add
                if new_window > MAX_CHANNEL_WINDOW_SIZE:
                    logger.warning("SSH peer adjusted the window of channel local_id=%s remote_id=%s by %d bytes "
                                   "to %d, above the RFC 4254 maximum of %d bytes; clamping it to the maximum.",
                                   self.local_id, self.remote_id, bytes_to_add, new_window,
                                   MAX_CHANNEL_WINDOW_SIZE)
                    new_window = MAX_CHANNEL_WINDOW_SIZE

                self.remote_window = new_window
                self._window_condition.notify_all()

        return

    def handle_data(self, data: bytes):
        """
            Handles SSH_MSG_CHANNEL_DATA: charges the data to the window we granted the peer and queues it for
            :meth:`recv`.  The window is given back to the peer as :meth:`recv` consumes the data.

            :param data: The data the peer sent.
        """
        data_length = len(data)
        self._charge_local_window(data_length)

        # An empty packet carries nothing, and queueing it would look like the end-of-stream marker.
        if data_length > 0:
            if self.eof_received is True:
                logger.warning("SSH peer sent %d bytes on channel local_id=%s after SSH_MSG_CHANNEL_EOF "
                               "(RFC 4254 section 5.3); keeping them.", data_length, self.local_id)
            self.in_buffer.put(data)
        return

    def handle_extended_data(self, data_type_code: int, data: bytes):
        """
            Handles SSH_MSG_CHANNEL_EXTENDED_DATA.  Stderr (SSH_EXTENDED_DATA_STDERR) is queued for
            :meth:`recv_stderr` and, like ordinary data, given back to the peer's window as it is read (RFC 4254
            section 5.2: extended data consumes the same window).  Other types are not defined by the RFC and are
            discarded; they are counted as consumed at once so they cannot close the window.

            :param data_type_code: The extended data type.
            :param data: The data the peer sent.
        """
        data_length = len(data)
        self._charge_local_window(data_length)

        if data_length > 0:
            if data_type_code == sshconstants.SSH_EXTENDED_DATA_STDERR:
                self.in_stderr_buffer.put(data)
            else:
                logger.debug("Discarding %d bytes of extended data of unsupported type %d on channel local_id=%s.",
                             data_length, data_type_code, self.local_id)
                self._consume_local_window(data_length)
        return

    def handle_eof(self):
        """
            Handles SSH_MSG_CHANNEL_EOF: the peer sends no more data (RFC 4254 section 5.3).  Once the data already
            received has been read, :meth:`recv` and :meth:`recv_stderr` return ``b""``.  The channel stays open and
            data can still be sent to the peer (half-close).
        """
        with self._window_condition:
            self.eof_received = True

        self._signal_end_of_stream()
        return

    def handle_close(self):
        """
            Handles SSH_MSG_CHANNEL_CLOSE from the peer.  RFC 4254 section 5.3 requires us to send back
            SSH_MSG_CHANNEL_CLOSE unless we already have, so it is answered here; a later :meth:`close` does not
            send it again.  Data that was already received stays readable with :meth:`recv`.
        """
        with self._window_condition:
            self._close_received = True
            self.closed = True
            # Wake any sender that is blocked on an exhausted remote window so it can fail fast.
            self._window_condition.notify_all()
            remote_id = self._claim_close_locked()

        self._signal_end_of_stream()

        if remote_id is not None:
            self._send_close(remote_id)
        return

    def _charge_local_window(self, data_length: int):
        """
            Takes received data out of the window we granted the peer.

            :param data_length: The number of bytes received.
        """
        with self._window_condition:
            self.local_window -= data_length
            local_window = self.local_window

        if local_window < 0:
            # RFC 4254 section 5.2 allows the extra data to be ignored, but dropping it would silently lose output,
            # so keep it and record the protocol violation.
            logger.warning("SSH peer overran the receive window of channel local_id=%s remote_id=%s by %d bytes.",
                           self.local_id, self.remote_id, -local_window)
        return

    def _consume_local_window(self, data_length: int):
        """
            Records that the application consumed received data and, once at least half of the initial window
            has been consumed, gives it back to the peer with SSH_MSG_CHANNEL_WINDOW_ADJUST (RFC 4254 section 5.2).

            :param data_length: The number of bytes consumed.
        """
        adjust_length = 0
        remote_id = None

        with self._window_condition:
            self._local_window_consumed += data_length

            adjust_threshold = self.window_size // 2
            if self.closed is False and self.remote_id is not None and self._local_window_consumed > 0:
                if self._local_window_consumed >= adjust_threshold:
                    adjust_length = self._local_window_consumed
                    # Never grow the window above the RFC 4254 maximum.
                    window_headroom = MAX_CHANNEL_WINDOW_SIZE - self.local_window
                    if adjust_length > window_headroom:
                        adjust_length = window_headroom

                    self._local_window_consumed -= adjust_length
                    self.local_window += adjust_length
                    remote_id = self.remote_id

        if adjust_length > 0:
            pkt = SshPacket(sshconstants.SSH_MSG_CHANNEL_WINDOW_ADJUST)
            pkt.add_uint32(remote_id)
            pkt.add_uint32(adjust_length)
            self.connection.transport.send_packet(pkt)
        return

    def recv_ready(self) -> bool:
        """
            Returns True if :meth:`recv` has something to return without waiting: data, or the end of the stream.

            :returns: True if a call to :meth:`recv` will not block.
        """
        ready = len(self._in_pending) > 0 or self.in_buffer.empty() is False
        return ready

    def recv_stderr_ready(self) -> bool:
        """
            Returns True if :meth:`recv_stderr` has something to return without waiting: data, or the end of the
            stream.

            :returns: True if a call to :meth:`recv_stderr` will not block.
        """
        ready = len(self._in_stderr_pending) > 0 or self.in_stderr_buffer.empty() is False
        return ready

    def exit_status_ready(self) -> bool:
        """
            Returns True once the peer has reported the command's exit status or signal, or the channel has closed.
            Like ``paramiko.Channel.exit_status_ready`` a closed channel is ready, because the RFC only recommends
            that the peer reports an exit status, and a peer that closes without one would otherwise leave callers
            waiting for a status that never comes.

            :returns: True if :meth:`recv_exit_status` has its final value.
        """
        ready = self.exit_status is not None or self.closed is True
        return ready

    def recv_exit_status(self):
        return self.exit_status if self.exit_status is not None else -1

    def send_ready(self) -> bool:
        """
            Returns True if :meth:`send` can put at least one byte on the wire without waiting for the peer to open
            its window.  Like ``paramiko.Channel.send_ready`` a channel that is not open reports ready, because
            :meth:`send` then fails immediately instead of blocking.

            :returns: False only while the channel is open and the peer's window is exhausted.
        """
        ready = True
        with self._window_condition:
            if self.active is True and self.closed is False and self.remote_window is not None:
                if self.remote_window <= 0:
                    ready = False
        return ready

    def shutdown_write(self):
        """
            Sends SSH_MSG_CHANNEL_EOF: tells the peer that no more data will be sent (RFC 4254 section 5.3).
            Receiving is not affected.  EOF is sent once and never after our SSH_MSG_CHANNEL_CLOSE; :meth:`send`
            fails afterwards.
        """
        remote_id = None
        with self._window_condition:
            if self.eof_sent is False and self._close_sent is False and self.remote_id is not None:
                self.eof_sent = True
                remote_id = self.remote_id

        if remote_id is not None:
            pkt = SshPacket(sshconstants.SSH_MSG_CHANNEL_EOF)
            pkt.add_uint32(remote_id)
            self.connection.transport.send_packet(pkt)
        return

class SshConnection:
    """
    Handles multiplexing of channels.
    """
    def __init__(self, transport):
        self.transport = transport
        self.channels = {} # local_id -> SshChannel
        self.next_channel_id = 0
        self.lock = threading.Lock()
        # The default number of seconds 'open_channel' waits for the peer to confirm a channel (the meaning of
        # paramiko's 'channel_timeout').  'None' waits for as long as the transport is open.
        self.channel_timeout = DEFAULT_SSH_TIMEOUT
        
        # Register as handler (Assuming Transport supports it, or we manually pump)
        # For now, we assume Transport calls dispatch_message
        
    def dispatch_message(self, packet: SshPacket):
        bytes_copy = packet.payload[:] 
        msg_id = bytes_copy[0]
        
        # Helper to read from packet while preserving message_id byte if not consumed
        # Actually my Packet interface consumes.
        packet._position = 0
        packet.get_byte() # Skip msg ID
        
        # Channel handlers are called outside of the connection lock: they take the channel's own lock and may
        # send packets, which must not stall other threads that are opening channels.
        if msg_id == sshconstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
            local_id = packet.get_uint32()
            remote_id = packet.get_uint32()
            window_size = packet.get_uint32()
            max_packet = packet.get_uint32()

            chan = self._find_channel(local_id)
            if chan is not None:
                chan.handle_open_confirmation(remote_id, window_size, max_packet)

        elif msg_id == sshconstants.SSH_MSG_CHANNEL_OPEN_FAILURE:
            local_id = packet.get_uint32()
            reason_code = packet.get_uint32()
            description = packet.get_string().decode('utf-8', errors='replace')

            chan = self._find_channel(local_id)
            if chan is not None:
                chan.handle_open_failure(reason_code, description)
                # The peer never allocated its side of the channel, so our channel number is free again.
                with self.lock:
                    self.channels.pop(local_id, None)

        elif msg_id == sshconstants.SSH_MSG_CHANNEL_WINDOW_ADJUST:
            local_id = packet.get_uint32()
            bytes_to_add = packet.get_uint32()

            chan = self._find_channel(local_id)
            if chan is not None:
                chan.handle_window_adjust(bytes_to_add)

        elif msg_id == sshconstants.SSH_MSG_CHANNEL_DATA:
            local_id = packet.get_uint32()
            data = packet.get_string()

            chan = self._find_channel(local_id)
            if chan is not None:
                chan.handle_data(data)

        elif msg_id == sshconstants.SSH_MSG_CHANNEL_EXTENDED_DATA:
            local_id = packet.get_uint32()
            data_type_code = packet.get_uint32()
            data = packet.get_string()

            chan = self._find_channel(local_id)
            if chan is not None:
                chan.handle_extended_data(data_type_code, data)

        elif msg_id == sshconstants.SSH_MSG_CHANNEL_EOF:
            local_id = packet.get_uint32()

            chan = self._find_channel(local_id)
            if chan is not None:
                chan.handle_eof()

        elif msg_id == sshconstants.SSH_MSG_CHANNEL_SUCCESS or msg_id == sshconstants.SSH_MSG_CHANNEL_FAILURE:
            local_id = packet.get_uint32()
            succeeded = msg_id == sshconstants.SSH_MSG_CHANNEL_SUCCESS

            chan = self._find_channel(local_id)
            if chan is not None:
                chan.handle_request_reply(succeeded)

        elif msg_id == sshconstants.SSH_MSG_CHANNEL_REQUEST:
            local_id = packet.get_uint32()
            request_type = packet.get_string().decode('ascii', errors='replace')
            want_reply = packet.get_boolean()

            chan = self._find_channel(local_id)
            if chan is not None:
                chan.handle_request(request_type, want_reply, packet)

        elif msg_id == sshconstants.SSH_MSG_GLOBAL_REQUEST:
            request_name = packet.get_string().decode('ascii', errors='replace')
            want_reply = packet.get_boolean()

            # RFC 4254 section 4: a request the recipient does not support is answered with
            # SSH_MSG_REQUEST_FAILURE when the sender wants a reply.  This client supports no global requests.
            logger.debug("Unsupported global request '%s' (want_reply=%s).", request_name, want_reply)
            if want_reply is True:
                reply = SshPacket(sshconstants.SSH_MSG_REQUEST_FAILURE)
                self.transport.send_packet(reply)

        elif msg_id == sshconstants.SSH_MSG_CHANNEL_CLOSE:
            local_id = packet.get_uint32()

            chan = self._find_channel(local_id)
            if chan is not None:
                chan.handle_close()
        # Handle others...
        return

    def _find_channel(self, local_id: int) -> Optional[SshChannel]:
        """
            Looks up a channel by its local channel number.

            :param local_id: The local channel number the peer addressed.

            :returns: The channel, or None (logged) if no channel has that number.
        """
        with self.lock:
            chan = self.channels.get(local_id)

        if chan is None:
            logger.debug("Ignoring a channel message for unknown local channel %s.", local_id)
        return chan

    def open_channel(self, kind: str = "session", dest_addr: Optional[tuple] = None, src_addr: Optional[tuple] = None,
                     *, timeout: Optional[float] = None) -> SshChannel:
        """
            Opens a channel and waits for the peer to confirm it, so the returned channel already knows the peer's
            channel number, window and maximum packet size and requests can be sent on it immediately.

            :param kind: The channel type, for example ``session`` or ``direct-tcpip``.
            :param dest_addr: For ``direct-tcpip`` / ``forwarded-tcpip``: the ``(host, port)`` the peer connects to.
            :param src_addr: For ``direct-tcpip`` / ``forwarded-tcpip``: the ``(address, port)`` of the originator.
            :param timeout: The maximum number of seconds to wait for the peer's confirmation.  When ``None`` the
                            connection's ``channel_timeout`` is used.

            :returns: The open channel.
            :raises: ConnectionError, TimeoutError, SemanticError
        """
        tcpip_kind = kind in TCPIP_CHANNEL_KINDS
        if tcpip_kind is True:
            if dest_addr is None or src_addr is None:
                err_msg = "A '{}' channel requires both 'dest_addr' and 'src_addr' (RFC 4254 section 7).".format(kind)
                raise SemanticError(err_msg)
        elif dest_addr is not None or src_addr is not None:
            err_msg = "'dest_addr' and 'src_addr' only apply to {} channels, not to '{}' channels.".format(
                TCPIP_CHANNEL_KINDS, kind)
            raise SemanticError(err_msg)

        if threading.current_thread() is self.transport:
            err_msg_lines = [
                "open_channel() was called on the SSH transport's reader thread.",
                "It waits for SSH_MSG_CHANNEL_OPEN_CONFIRMATION, which only that thread can deliver, so it would hang",
                "until it timed out.  Open channels from another thread, not from a message handler.",
            ]
            err_msg = os.linesep.join(err_msg_lines)
            raise SemanticError(err_msg)

        wait_timeout = timeout
        if wait_timeout is None:
            wait_timeout = self.channel_timeout

        with self.lock:
            local_id = self.next_channel_id
            self.next_channel_id += 1
            chan = SshChannel(self, local_id)
            self.channels[local_id] = chan
            
        pkt = SshPacket(sshconstants.SSH_MSG_CHANNEL_OPEN)
        pkt.add_string(kind)
        pkt.add_uint32(local_id)
        pkt.add_uint32(chan.window_size)
        pkt.add_uint32(chan.max_packet_size)

        if tcpip_kind is True:
            dest_host, dest_port = dest_addr
            src_host, src_port = src_addr
            pkt.add_string(dest_host)
            pkt.add_uint32(dest_port)
            pkt.add_string(src_host)
            pkt.add_uint32(src_port)

        self.transport.send_packet(pkt)

        # The confirmation is delivered by the transport thread; it may already have arrived.
        chan.wait_for_open(wait_timeout, kind=kind)
        return chan
