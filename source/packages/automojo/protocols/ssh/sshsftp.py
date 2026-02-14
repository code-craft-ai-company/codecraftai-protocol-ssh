"""
SFTP Protocol Implementation (Version 3)
"""
import struct
import logging
import threading
from automojo.protocols.ssh import sshconstants
from automojo.protocols.ssh.sshpacket import SshPacket

logger = logging.getLogger(__name__)

class SshSFTPAttributes:
    def __init__(self, size=None, uid=None, gid=None, mode=None, atime=None, mtime=None):
        self.st_size = size
        self.st_uid = uid
        self.st_gid = gid
        self.st_mode = mode
        self.st_atime = atime
        self.st_mtime = mtime
        
    @classmethod
    def from_attrs(cls, attrs):
        # Helper to create from parsed attributes dict (TODO)
        return cls()

class SshSFTPError(Exception):
    pass

class SshSFTPClient:
    """
    SFTP Client implementation.
    """
    def __init__(self, channel):
        self.channel = channel
        self.request_id = 0
        self.lock = threading.Lock()
        self.channel.request_subsystem("sftp")
        self._init_sftp()

    def _init_sftp(self):
        """
        Send INIT and wait for VERSION.
        """
        pkt = SshPacket()
        pkt.add_uint32(3) # Version 3
        self._send_packet(sshconstants.SSH_FXP_INIT, pkt.payload)
        
        msg_id, payload = self._recv_packet()
        if msg_id != sshconstants.SSH_FXP_VERSION:
            raise SshSFTPError(f"Expected SSH_FXP_VERSION, got {msg_id}")
        
        # Parse version
        version = struct.unpack('>I', payload[:4])[0]
        logger.info(f"SFTP Version: {version}")

    def open(self, filename: str, pflags: int = 0, attrs: dict = None) -> bytes:
        """
        Open a file. Returns handle.
        pflags: SSH_FXF_READ, SSH_FXF_WRITE, etc. (Need mapped constants, assuming valid int passed)
        """
        req_id = self._next_id()
        pkt = SshPacket()
        pkt.add_uint32(req_id)
        pkt.add_string(filename)
        pkt.add_uint32(0) # Pflags placeholder (TODO: Add mapping) - wait using raw int 
        # Actually pflags logic. 
        # READ=1, WRITE=2, APPEND=4, CREAT=8, TRUNC=16, EXCL=32
        if pflags == 0:
            pflags = 1 # READ default
            
        pkt = SshPacket()
        pkt.add_uint32(req_id)
        pkt.add_string(filename)
        pkt.add_uint32(pflags)
        pkt.add_uint32(0) # Attrs (0)
        
        self._send_packet(sshconstants.SSH_FXP_OPEN, pkt.payload)
        msg_id, payload = self._recv_packet()
        return self._parse_handle_response(msg_id, payload, req_id)

    def close(self, handle: bytes):
        req_id = self._next_id()
        pkt = SshPacket()
        pkt.add_uint32(req_id)
        pkt.add_string(handle)
        self._send_packet(sshconstants.SSH_FXP_CLOSE, pkt.payload)
        msg_id, payload = self._recv_packet()
        self._parse_status_response(msg_id, payload, req_id)

    def read(self, handle: bytes, offset: int, length: int) -> bytes:
        req_id = self._next_id()
        pkt = SshPacket()
        pkt.add_uint32(req_id)
        pkt.add_string(handle)
        pkt.add_uint64(offset)
        pkt.add_uint32(length)
        
        self._send_packet(sshconstants.SSH_FXP_READ, pkt.payload)
        msg_id, payload = self._recv_packet()
        
        if msg_id == sshconstants.SSH_FXP_DATA:
            pkt = SshPacket(payload=payload)
            pkt.get_uint32() # Req ID
            return pkt.get_string()
        elif msg_id == sshconstants.SSH_FXP_STATUS:
            self._check_status(payload, req_id)
            return b"" # Should raise EOF if status is EOF
        else:
             raise SshSFTPError(f"Unexpected message {msg_id}")

    def write(self, handle: bytes, offset: int, data: bytes):
        """
        Write to a file.
        """
        req_id = self._next_id()
        pkt = SshPacket()
        pkt.add_uint32(req_id)
        pkt.add_string(handle)
        pkt.add_uint64(offset)
        pkt.add_string(data)
        
        self._send_packet(sshconstants.SSH_FXP_WRITE, pkt.payload)
        msg_id, payload = self._recv_packet()
        self._parse_status_response(msg_id, payload, req_id)

    def listdir(self, path: str) -> list:
        """
        List directory contents.
        """
        # Open directory
        req_id = self._next_id()
        pkt = SshPacket()
        pkt.add_uint32(req_id)
        pkt.add_string(path)
        self._send_packet(sshconstants.SSH_FXP_OPENDIR, pkt.payload)
        msg_id, payload = self._recv_packet()
        handle = self._parse_handle_response(msg_id, payload, req_id)
        
        items = []
        try:
            while True:
                req_id = self._next_id()
                pkt = SshPacket()
                pkt.add_uint32(req_id)
                pkt.add_string(handle)
                self._send_packet(sshconstants.SSH_FXP_READDIR, pkt.payload)
                
                msg_id, payload = self._recv_packet()
                if msg_id == sshconstants.SSH_FXP_NAME:
                    pkt = SshPacket(payload=payload)
                    rid = pkt.get_uint32()
                    if rid != req_id:
                        raise SshSFTPError("Request ID mismatch")
                    
                    count = pkt.get_uint32()
                    for _ in range(count):
                        filename = pkt.get_string().decode('utf-8')
                        longname = pkt.get_string().decode('utf-8')
                        self._parse_attrs(pkt) # consume attrs
                        items.append(filename)
                elif msg_id == sshconstants.SSH_FXP_STATUS:
                     self._check_status(payload, req_id) # Will raise EOF or error
                     break
                else:
                    raise SshSFTPError(f"Unexpected message {msg_id}")
        except EOFError:
            pass
        finally:
            self.close_handle(handle)
            
        return items

    def stat(self, path: str) -> SshSFTPAttributes:
        """
        Get attributes for a path (follows symlinks).
        """
        return self._request_stat(path, sshconstants.SSH_FXP_STAT)

    def lstat(self, path: str) -> SshSFTPAttributes:
        """
        Get attributes for a path (does not follow symlinks).
        """
        return self._request_stat(path, sshconstants.SSH_FXP_LSTAT)

    def _request_stat(self, path: str, msg_code: int) -> SshSFTPAttributes:
        req_id = self._next_id()
        pkt = SshPacket()
        pkt.add_uint32(req_id)
        pkt.add_string(path)
        self._send_packet(msg_code, pkt.payload)
        
        msg_id, payload = self._recv_packet()
        if msg_id == sshconstants.SSH_FXP_ATTRS:
            pkt = SshPacket(payload=payload)
            rid = pkt.get_uint32()
            if rid != req_id:
                raise SshSFTPError("Request ID mismatch")
            return self._parse_attrs(pkt)
        elif msg_id == sshconstants.SSH_FXP_STATUS:
            self._check_status(payload, req_id)
            # Should raise error
            return None
        else:
             raise SshSFTPError(f"Unexpected message {msg_id}")

    def _parse_attrs(self, pkt: SshPacket) -> SshSFTPAttributes:
        """
        Parse SFTP Attributes from packet.
        """
        flags = pkt.get_uint32()
        size = None
        uid = None
        gid = None
        mode = None
        atime = None
        mtime = None
        
        if flags & sshconstants.SSH_FILEXFER_ATTR_SIZE:
            size = pkt.get_uint64()
        if flags & sshconstants.SSH_FILEXFER_ATTR_UIDGID:
            uid = pkt.get_uint32()
            gid = pkt.get_uint32()
        if flags & sshconstants.SSH_FILEXFER_ATTR_PERMISSIONS:
            mode = pkt.get_uint32()
        if flags & sshconstants.SSH_FILEXFER_ATTR_ACMODTIME:
            atime = pkt.get_uint32()
            mtime = pkt.get_uint32()
        if flags & sshconstants.SSH_FILEXFER_ATTR_EXTENDED:
            count = pkt.get_uint32()
            for _ in range(count):
                pkt.get_string()
                pkt.get_string()
                
        return SshSFTPAttributes(size, uid, gid, mode, atime, mtime)

    def _next_id(self):
        with self.lock:
            self.request_id += 1
            return self.request_id

    def _send_packet(self, msg_type: int, payload: bytes):
        # Frame: Length (4) + Type (1) + Payload
        length = 1 + len(payload)
        out = struct.pack('>I', length) + bytes([msg_type]) + payload
        self.channel.send(out)

    def _recv_packet(self):
        # Read length
        data = self._read_exactly(4)
        length = struct.unpack('>I', data)[0]
        
        # Read type + payload
        data = self._read_exactly(length)
        msg_type = data[0]
        payload = data[1:]
        return msg_type, payload

    def _read_exactly(self, n):
        data = b""
        while len(data) < n:
            chunk = self.channel.recv(n - len(data))
            if not chunk:
                raise SshSFTPError("Connection closed")
            data += chunk
        return data

    def _parse_handle_response(self, msg_id, payload, req_id):
        if msg_id == sshconstants.SSH_FXP_HANDLE:
            pkt = SshPacket(payload=payload)
            rid = pkt.get_uint32()
            if rid != req_id:
                raise SshSFTPError("Request ID mismatch")
            return pkt.get_string()
        elif msg_id == sshconstants.SSH_FXP_STATUS:
            self._check_status(payload, req_id)
        else:
            raise SshSFTPError(f"Unexpected message {msg_id}")

    def _parse_status_response(self, msg_id, payload, req_id):
        if msg_id == sshconstants.SSH_FXP_STATUS:
            self._check_status(payload, req_id)
        else:
             raise SshSFTPError(f"Unexpected message {msg_id}")

    def _check_status(self, payload, req_id):
        pkt = SshPacket(payload=payload)
        rid = pkt.get_uint32()
        status_code = pkt.get_uint32()
        if rid != req_id:
             raise SshSFTPError("Request ID mismatch in status")
        if status_code != sshconstants.SSH_FX_OK:
            if status_code == sshconstants.SSH_FX_EOF:
                raise EOFError("SFTP EOF")
            raise SshSFTPError(f"SFTP Error Code: {status_code}")
