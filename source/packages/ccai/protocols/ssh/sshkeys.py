"""
SSH Keys Interface
"""
from abc import ABC, abstractmethod
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, padding
from cryptography.exceptions import InvalidSignature

class HostKey(ABC):
    """
    Abstract base class for Host Keys.
    """
    
    @abstractmethod
    def get_name(self) -> str:
        """
        Return algorithm name (e.g. ssh-rsa)
        """
        pass
        
    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """
        Sign data.
        """
        pass
        
    @abstractmethod
    def verify(self, data: bytes, signature: bytes) -> bool:
        """
        Verify signature.
        """
        pass
        
    @abstractmethod
    def as_bytes(self) -> bytes:
        """
        Return public key as bytes for transmission (OpenSSH format).
        """
        pass

class SshRSAKey(HostKey):
    """
    RSA Key Implementation using cryptography.
    """
    def __init__(self, key: rsa.RSAPrivateKey = None, pub_key: rsa.RSAPublicKey = None):
        if key:
            self.private_key = key
            self.public_key = key.public_key()
        elif pub_key:
            self.private_key = None
            self.public_key = pub_key
        else:
            # Generate a new key for testing if none provided? 
            # Or raise error? For now, let's generate 2048-bit key if nothing passed.
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.public_key = self.private_key.public_key()
            
    @classmethod
    def from_private_key_file(cls, filename, password=None):
        with open(filename, "rb") as f:
            data = f.read()
        return cls.from_private_key(data, password)

    @classmethod
    def from_private_key(cls, data, password=None):
        # Handle file-like object
        if hasattr(data, "read"):
            data = data.read()
            
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        p_key = serialization.load_pem_private_key(
            data,
            password=password.encode() if isinstance(password, str) else password
        )
        if not isinstance(p_key, rsa.RSAPrivateKey):
            raise ValueError("Not an RSA key")
            
        return cls(key=p_key)
        
    def get_name(self) -> str:
        return "ssh-rsa"
        
    def sign(self, data: bytes) -> bytes:
        if not self.private_key:
            raise ValueError("Private key not available for signing")
            
        return self.private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA1()
        )

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA1()
            )
            return True
        except InvalidSignature:
            return False

    def as_bytes(self) -> bytes:
        """
        Format: string "ssh-rsa", mpint e, mpint n
        """
        # We need to manually construct the blob because cryptography's PublicFormat.OpenSSH 
        # includes the header "ssh-rsa <b64> <comment>", but we just want the inner blob 
        # or we want the wire format components.
        # The wire format is: string algorithm, mpint e, mpint n.
        
        numbers = self.public_key.public_numbers()
        
        from ccai.protocols.ssh.sshpacket import SshPacket
        pkt = SshPacket()
        pkt.add_string(self.get_name())
        pkt.add_mpint(numbers.e)
        pkt.add_mpint(numbers.n)
        return pkt.payload

class SshEd25519Key(HostKey):
    """
    Ed25519 Key Implementation.
    """
    def __init__(self, key: ed25519.Ed25519PrivateKey = None, pub_key: ed25519.Ed25519PublicKey = None):
        if key:
            self.private_key = key
            self.public_key = key.public_key()
        elif pub_key:
            self.private_key = None
            self.public_key = pub_key
        else:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()

    @classmethod
    def from_private_key_file(cls, filename, password=None):
        with open(filename, "rb") as f:
            data = f.read()
        return cls.from_private_key(data, password)

    @classmethod
    def from_private_key(cls, data, password=None):
        # Handle file-like object
        if hasattr(data, "read"):
            data = data.read()

        if isinstance(data, str):
            data = data.encode('utf-8')

        p_key = serialization.load_pem_private_key(
            data,
            password=password.encode() if isinstance(password, str) else password
        )
        if not isinstance(p_key, ed25519.Ed25519PrivateKey):
             raise ValueError("Not an Ed25519 key")

        return cls(key=p_key)

    def get_name(self) -> str:
        return "ssh-ed25519"

    def sign(self, data: bytes) -> bytes:
        if not self.private_key:
             raise ValueError("Private key not available for signing")
        return self.private_key.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self.public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    def as_bytes(self) -> bytes:
        """
        Format: string "ssh-ed25519", string key_bytes
        """
        # Get raw bytes
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        from ccai.protocols.ssh.sshpacket import SshPacket
        pkt = SshPacket()
        pkt.add_string(self.get_name())
        pkt.add_string(pub_bytes)
        return pkt.payload
