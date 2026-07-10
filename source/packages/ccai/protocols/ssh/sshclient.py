"""
SSH Client Implementation
"""
import socket
import logging
from ccai.protocols.ssh.sshtransport import SshTransport
from ccai.protocols.ssh.sshconnection import SshConnection
from ccai.protocols.ssh.sshsftp import SshSFTPClient
from ccai.protocols.ssh.sshauth import SshAuthAgent

logger = logging.getLogger(__name__)


class AutoAddPolicy:
    """
    Host-key policy that trusts and records any host key not already known.
    Convenient for first-use / test environments; not for untrusted networks.
    """
    auto_add = True


class RejectPolicy:
    """
    Host-key policy that rejects any host key that is not already known.
    """
    auto_add = False


class SshClient:
    """
    High-level SSH Client.
    Mimics paramiko.SSHClient interaction where possible.
    """
    def __init__(self):
        self.transport = None
        self.connection = None
        self._policy = None  # Missing host key policy
        self._host_keys = {}  # hostname -> set of trusted host-key blobs

    def set_missing_host_key_policy(self, policy):
        self._policy = policy
        return

    def load_system_host_keys(self, filename=None):
        # Loading persisted known_hosts is not yet implemented; trust is
        # governed by the configured missing-host-key policy and any keys
        # added via add_host_key.
        return

    def add_host_key(self, hostname, key_blob):
        """
        Record a trusted host-key blob for a host.
        """
        known = self._host_keys.get(hostname)
        if known is None:
            known = set()
            self._host_keys[hostname] = known
        known.add(bytes(key_blob))
        return

    def _verify_host_key(self, hostname, key_type, key_blob):
        """
        Host-key trust verifier handed to the transport. Returns True only if
        the key is already trusted for the host, or the policy auto-adds it.
        """
        blob = bytes(key_blob)
        known = self._host_keys.get(hostname)
        if known is not None and blob in known:
            rtnval = True
            return rtnval

        auto_add = getattr(self._policy, "auto_add", False)
        if auto_add is True:
            self.add_host_key(hostname, blob)
            logger.warning("Auto-added untrusted host key for %s (%s)", hostname, key_type)
            rtnval = True
            return rtnval

        logger.error("Rejecting unknown host key for %s (%s)", hostname, key_type)
        rtnval = False
        return rtnval

    def connect(self, hostname, port=22, username=None, password=None, pkey=None,
                key_filename=None, timeout=None, allow_agent=True, look_for_keys=True,
                compress=False, sock=None, gss_auth=False, gss_kex=False,
                gss_deleg_creds=False, gss_host=None, banner_timeout=None,
                auth_timeout=None, channel_timeout=None, disabled_algorithms=None):

        # 1. Create Socket if not provided
        if sock is None:
            sock = socket.create_connection((hostname, port), timeout=timeout)

        # 2. Start Transport and wire host-key trust before the handshake runs.
        self.transport = SshTransport(sock)
        self.transport.hostname = hostname
        self.transport.host_key_verifier = self._verify_host_key
        self.transport.connect()  # sends version + starts KEX

        # 3. Wait for key exchange to complete (both directions encrypted) before
        # sending any authentication traffic.
        kex_timeout = auth_timeout if auth_timeout is not None else 30
        completed = self.transport.kex_complete.wait(timeout=kex_timeout)
        if self.transport.kex_error is not None:
            kex_error = self.transport.kex_error
            self.close()
            raise kex_error
        if completed is not True:
            self.close()
            raise TimeoutError("SSH key exchange did not complete")
        if self.transport.active is not True:
            self.close()
            raise ConnectionError("SSH transport closed during key exchange")

        # 4. Authenticate. Register the auth agent so the transport delivers
        # SERVICE_ACCEPT / USERAUTH_* responses to it.
        auth_agent = SshAuthAgent(self.transport)
        self.transport.register_handler(auth_agent.dispatch_message)

        try:
            if password:
                auth_agent.authenticate_password(username, password)
            else:
                # 'none' probes for the list of allowed methods.
                auth_agent.authenticate_none(username)
        except Exception as e:
            self.close()
            raise e

        # 5. Start the connection layer and route subsequent packets to it.
        self.connection = SshConnection(self.transport)
        self.transport.register_handler(self.connection.dispatch_message)
        return

    def get_transport(self):
        return self.transport

    def open_sftp(self):
        """
        Open SFTP Client.
        """
        chan = self.connection.open_channel("session")
        rtnval = SshSFTPClient(chan)
        return rtnval

    def exec_command(self, command, bufsize=-1, timeout=None, get_pty=False, environment=None):
        """
        Execute a command.
        Returns (stdin, stdout, stderr).
        """
        chan = self.connection.open_channel("session")
        if get_pty:
            chan.request_pty()
        chan.request_exec(command)

        rtnval = (None, chan, None)
        return rtnval

    def invoke_shell(self, term='vt100', width=80, height=24, width_pixels=0, height_pixels=0, environment=None):
        chan = self.connection.open_channel("session")
        chan.request_pty(term=term, width=width, height=height)
        chan.request_shell()
        return chan

    def close(self):
        if self.transport:
            self.transport.close()
        return
