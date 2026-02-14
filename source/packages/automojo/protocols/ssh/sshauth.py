"""
SSH Authentication Layer
"""
import logging
import threading
from automojo.protocols.ssh import sshconstants
from automojo.protocols.ssh.sshpacket import SshPacket

logger = logging.getLogger(__name__)

class SshAuthError(Exception):
    pass

class SshAuthAgent:
    """
    Handles Client-side User Authentication.
    """
    def __init__(self, transport):
        self.transport = transport
        self.username = None
        self.service = "ssh-connection"
        self.auth_methods = []
        self.authenticated = False
        self.event = threading.Event()
        self.last_exception = None

    def authenticate_none(self, username: str):
        """
        Attempt 'none' authentication to get list of allowed methods.
        """
        self.username = username
        self._send_auth_request("none")
        self._wait_for_response()
        return self.auth_methods

    def authenticate_password(self, username: str, password: str):
        """
        Attempt password authentication.
        """
        self.username = username
        self._send_auth_request("password", password=password)
        self._wait_for_response()
        
    def _send_auth_request(self, method: str, password: str = None):
        pkt = SshPacket(sshconstants.SSH_MSG_USERAUTH_REQUEST)
        pkt.add_string(self.username)
        pkt.add_string(self.service)
        pkt.add_string(method)
        
        if method == "password":
            pkt.add_boolean(False) # Change password?
            pkt.add_string(password)
        
        self.event.clear()
        self.transport.send_packet(pkt)

    def dispatch_message(self, packet: SshPacket):
        """
        Called by Transport when an auth-related packet receives.
        """
        if not packet.payload:
            return
            
        msg_id = packet.get_byte()
        if msg_id == sshconstants.SSH_MSG_USERAUTH_SUCCESS:
            self.authenticated = True
            self.event.set()
        elif msg_id == sshconstants.SSH_MSG_USERAUTH_FAILURE:
            # Parse allowed methods
            methods = packet.get_name_list()
            partial = packet.get_boolean()
            self.auth_methods = methods
            self.authenticated = False
            self.last_exception = SshAuthError(f"Authentication failed. Allowed: {methods}")
            self.event.set()
        elif msg_id == sshconstants.SSH_MSG_USERAUTH_BANNER:
            banner = packet.get_string().decode('utf-8')
            logger.info(f"Auth Banner: {banner}")
        else:
            logger.warning(f"Unknown auth packet: {msg_id}")

    def _wait_for_response(self):
        self.event.wait(timeout=30)
        if not self.event.is_set():
             raise TimeoutError("Auth request timed out")
        if not self.authenticated:
             if self.last_exception:
                 raise self.last_exception
             raise SshAuthError("Authentication failed")
