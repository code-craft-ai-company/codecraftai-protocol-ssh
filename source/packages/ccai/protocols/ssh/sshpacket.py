"""
SSH Packet Handling
"""

import struct
from typing import Union, List

class SshPacket:
    """
    Repsrefents an SSH Packet and provides methods for packing/unpacking data types.
    """

    def __init__(self, message_id: int = None, payload: bytes = b''):
        self.message_id = message_id
        self.payload = bytearray(payload)
        self._position = 0

    @property
    def remaining(self) -> bytes:
        return self.payload[self._position:]

    def get_bytes(self, length: int) -> bytes:
        if self._position + length > len(self.payload):
            raise IndexError("Not enough data in packet")
        data = self.payload[self._position : self._position + length]
        self._position += length
        return bytes(data)

    def get_byte(self) -> int:
        return self.get_bytes(1)[0]

    def get_boolean(self) -> bool:
        return bool(self.get_byte())

    def get_uint32(self) -> int:
        return struct.unpack('>I', self.get_bytes(4))[0]

    def get_uint64(self) -> int:
        return struct.unpack('>Q', self.get_bytes(8))[0]

    def get_string(self) -> bytes:
        """
        SSH string: uint32 length + content
        """
        length = self.get_uint32()
        return self.get_bytes(length)
    
    def get_mpint(self) -> int:
        """
        SSH mpint: Two's complement integer, stored as a string.
        """
        data = self.get_string()
        if not data:
            return 0
        return int.from_bytes(data, byteorder='big', signed=True)

    def get_name_list(self) -> List[str]:
        """
        SSH name-list: comma-separated list of strings
        """
        data = self.get_string().decode('utf-8')
        if not data:
            return []
        return data.split(',')
    
    # --- Packing Methods ---

    def add_byte(self, b: int):
        self.payload.append(b & 0xFF)

    def add_bytes(self, data: bytes):
        """
        Append raw bytes with no length prefix (e.g. the KEXINIT cookie).
        """
        self.payload.extend(data)

    def add_boolean(self, b: bool):
        self.add_byte(1 if b else 0)

    def add_uint32(self, n: int):
        self.payload.extend(struct.pack('>I', n))

    def add_uint64(self, n: int):
        self.payload.extend(struct.pack('>Q', n))

    def add_string(self, s: Union[str, bytes]):
        if isinstance(s, str):
            s = s.encode('utf-8')
        self.add_uint32(len(s))
        self.payload.extend(s)

    def add_mpint(self, n: int):
        if n == 0:
            self.add_uint32(0)
            return
        
        # Calculate number of bytes needed
        # bit_length() excludes sign, so we might need an extra bit/byte
        length = (n.bit_length() + 7) // 8
        try:
            b = n.to_bytes(length, byteorder='big', signed=True)
        except OverflowError:
            length += 1
            b = n.to_bytes(length, byteorder='big', signed=True)
            
        self.add_string(b) # mpint is stored as a string

    def add_name_list(self, names: List[str]):
        self.add_string(",".join(names))

    def to_bytes(self) -> bytes:
        """
        Returns the full payload with message ID if set.
        Usually the message ID is the first byte of the payload.
        """
        if self.message_id is not None:
             # Prepend message ID if not already in payload? 
             # Standard practice: explicit message ID + payloads.
             # but often we build the packet linearly.
             # If message_id is set in constructor, we assume it's the first byte.
             return struct.pack('B', self.message_id) + self.payload
        return bytes(self.payload)

    @classmethod
    def create_disconnect(cls, reason_code: int, description: str):
        from ccai.protocols.ssh import sshconstants as constants
        pkt = cls(constants.SSH_MSG_DISCONNECT)
        pkt.add_uint32(reason_code)
        pkt.add_string(description)
        pkt.add_string("") # Language tag
        return pkt

    @classmethod
    def create_ignore(cls, data: bytes):
        from ccai.protocols.ssh import sshconstants as constants
        pkt = cls(constants.SSH_MSG_IGNORE)
        pkt.add_string(data)
        return pkt
