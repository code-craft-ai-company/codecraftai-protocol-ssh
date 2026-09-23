"""
SSH Connection Layer
"""
import threading
import logging

from queue import Queue

from ccai.protocols.ssh import sshconstants
from ccai.protocols.ssh.sshpacket import SshPacket

logger = logging.getLogger(__name__)

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
        self.window_size = 1024 * 1024
        self.active = False
        self.closed = False
        self.in_buffer = Queue()
        self.exit_status = None
        
    def open(self):
        # Already opened by Connection?
        self.active = True
        
    def send(self, data: bytes):
        if not self.active or self.closed:
            raise ConnectionError("Channel closed")
        
        # Split into chunks no larger than the smaller of the local and the peer's
        # maximum packet size (RFC 4254 section 5.1).
        # And respect window size (TODO)

        chunk_size = self.max_packet_size
        if self.remote_max_packet_size is not None and self.remote_max_packet_size < chunk_size:
            chunk_size = self.remote_max_packet_size

        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            pkt = SshPacket(sshconstants.SSH_MSG_CHANNEL_DATA)
            pkt.add_uint32(self.remote_id)
            pkt.add_string(chunk)
            self.connection.transport.send_packet(pkt)
            
    def recv(self, size: int = 1024, timeout: float = None) -> bytes:
        if self.closed and self.in_buffer.empty():
            return b""
            
        # Block until data
        import queue
        try:
            data = self.in_buffer.get(timeout=timeout)
        except queue.Empty:
            return b""
            
        # TODO: Handle size limit and buffering (we return whole chunk for now)
        return data

    def close(self):
        if not self.closed:
            self.closed = True
            pkt = SshPacket(sshconstants.SSH_MSG_CHANNEL_CLOSE)
            pkt.add_uint32(self.remote_id)
            self.connection.transport.send_packet(pkt)

    def request_shell(self):
        self._send_request("shell", want_reply=True)
        
    def request_exec(self, command: str):
        self._send_request("exec", want_reply=True, data=command)

    def request_subsystem(self, subsystem: str):
        self._send_request("subsystem", want_reply=True, data=subsystem)

    def request_pty(self, term: str = 'vt100', width: int = 80, height: int = 24, 
                    pixel_width: int = 0, pixel_height: int = 0, modes: dict = None):
        """
        Request a pseudo-terminal.
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
        
        self._send_request("pty-req", want_reply=True, data=data.payload)

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

    def _send_request(self, request_type, want_reply, data=None):
        pkt = SshPacket(sshconstants.SSH_MSG_CHANNEL_REQUEST)
        pkt.add_uint32(self.remote_id)
        pkt.add_string(request_type)
        pkt.add_boolean(want_reply)
        if data:
            pkt.payload.extend(data)
        self.connection.transport.send_packet(pkt)

    def handle_data(self, data):
        self.in_buffer.put(data)
        
    def handle_close(self):
        self.closed = True
        self.in_buffer.put(b"") # EOF signal

    def recv_ready(self):
        return not self.in_buffer.empty()

    def recv_stderr_ready(self):
        return False # TODO: Implement stderr

    def recv_stderr(self, size=1024, timeout=None):
        return b"" # TODO: Implement stderr

    def exit_status_ready(self):
        return self.exit_status is not None

    def recv_exit_status(self):
        return self.exit_status if self.exit_status is not None else -1

    def send_ready(self):
        return True # Buffer check?

    def shutdown_write(self):
        # Send EOF
        pkt = SshPacket(sshconstants.SSH_MSG_CHANNEL_EOF)
        pkt.add_uint32(self.remote_id)
        self.connection.transport.send_packet(pkt)

class SshConnection:
    """
    Handles multiplexing of channels.
    """
    def __init__(self, transport):
        self.transport = transport
        self.channels = {} # local_id -> SshChannel
        self.next_channel_id = 0
        self.lock = threading.Lock()
        
        # Register as handler (Assuming Transport supports it, or we manually pump)
        # For now, we assume Transport calls dispatch_message
        
    def dispatch_message(self, packet: SshPacket):
        bytes_copy = packet.payload[:] 
        msg_id = bytes_copy[0]
        
        # Helper to read from packet while preserving message_id byte if not consumed
        # Actually my Packet interface consumes.
        packet._position = 0
        packet.get_byte() # Skip msg ID
        
        if msg_id == sshconstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
            local_id = packet.get_uint32()
            remote_id = packet.get_uint32()
            window_size = packet.get_uint32()
            max_packet = packet.get_uint32()
            
            with self.lock:
                if local_id in self.channels:
                    chan = self.channels[local_id]
                    chan.remote_id = remote_id
                    chan.remote_max_packet_size = max_packet
                    chan.open()
                    
        elif msg_id == sshconstants.SSH_MSG_CHANNEL_DATA:
            local_id = packet.get_uint32()
            data = packet.get_string()
            with self.lock:
                if local_id in self.channels:
                    self.channels[local_id].handle_data(data)
                    
        elif msg_id == sshconstants.SSH_MSG_CHANNEL_CLOSE:
            local_id = packet.get_uint32()
            with self.lock:
                if local_id in self.channels:
                    self.channels[local_id].handle_close()
        # Handle others...

    def open_channel(self, kind="session") -> SshChannel:
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
        
        self.transport.send_packet(pkt)
        return chan
