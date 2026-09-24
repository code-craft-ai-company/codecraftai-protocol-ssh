"""
    A stand-in for :class:`SshTransport` that plays the SSH server side of the connection protocol for tests.
"""

import threading

from ccai.protocols.ssh import sshconstants
from ccai.protocols.ssh.sshpacket import SshPacket

# The peer's channel number for our channel N is PEER_CHANNEL_BASE + N.
PEER_CHANNEL_BASE = 200


class FakePeerTransport:
    """
        Stands in for :class:`SshTransport`: records the packets the connection layer sends, answers
        SSH_MSG_CHANNEL_OPEN with a confirmation, and answers want-reply channel requests with
        SSH_MSG_CHANNEL_SUCCESS ('success'), SSH_MSG_CHANNEL_FAILURE ('failure') or not at all ('silent'),
        as set in ``request_answer``.
    """

    def __init__(self):
        self.active = True
        self.connection = None
        self.request_answer = "success"
        # Optional callable(local_id, request_type) run after a channel request has been answered, to play the
        # server's side of the request (for example the output and exit status of an 'exec').
        self.request_handler = None
        self.sent = []
        self._lock = threading.Lock()
        return

    def is_active(self) -> bool:
        active = self.active
        return active

    def send_packet(self, pkt: SshPacket):
        with self._lock:
            self.sent.append(pkt)

        if pkt.message_id == sshconstants.SSH_MSG_CHANNEL_OPEN:
            pkt._position = 0
            pkt.get_string() # channel type
            local_id = pkt.get_uint32()

            confirm = SshPacket(payload=bytes([sshconstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION]))
            confirm.add_uint32(local_id)
            confirm.add_uint32(PEER_CHANNEL_BASE + local_id)
            confirm.add_uint32(1024 * 1024) # window
            confirm.add_uint32(32768) # max packet
            confirm._position = 0
            self.connection.dispatch_message(confirm)

        elif pkt.message_id == sshconstants.SSH_MSG_CHANNEL_REQUEST:
            pkt._position = 0
            recipient = pkt.get_uint32()
            request_type = pkt.get_string().decode()
            want_reply = pkt.get_boolean()
            local_id = recipient - PEER_CHANNEL_BASE

            if want_reply is True and self.request_answer != "silent":
                reply_id = sshconstants.SSH_MSG_CHANNEL_SUCCESS
                if self.request_answer == "failure":
                    reply_id = sshconstants.SSH_MSG_CHANNEL_FAILURE
                self.dispatch_to_channel(reply_id, local_id)

            if self.request_handler is not None:
                self.request_handler(local_id, request_type)
        return

    def dispatch_to_channel(self, message_id: int, local_id: int, data: bytes = None):
        """
            Delivers a message addressed to our channel ``local_id`` to the connection layer, as the transport
            thread does.  ``data`` (if any) is added as an SSH string.
        """
        pkt = SshPacket(payload=bytes([message_id]))
        pkt.add_uint32(local_id)
        if data is not None:
            pkt.add_string(data)
        pkt._position = 0
        self.connection.dispatch_message(pkt)
        return

    def dispatch_raw(self, message_id: int, local_id: int, body: bytes):
        """
            Delivers a message addressed to our channel ``local_id`` whose fields after the recipient channel are
            already encoded in ``body``.
        """
        pkt = SshPacket(payload=bytes([message_id]))
        pkt.add_uint32(local_id)
        pkt.add_bytes(body)
        pkt._position = 0
        self.connection.dispatch_message(pkt)
        return

    def sent_of_type(self, message_id: int) -> list:
        with self._lock:
            sent = [pkt for pkt in self.sent if pkt.message_id == message_id]
        return sent
