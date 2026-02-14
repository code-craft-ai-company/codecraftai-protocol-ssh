"""
SSH Client Implementation
"""
import socket
import logging
from automojo.protocols.ssh.sshtransport import SshTransport
from automojo.protocols.ssh.sshconnection import SshConnection
from automojo.protocols.ssh.sshsftp import SshSFTPClient
from automojo.protocols.ssh.sshauth import SshAuthAgent

logger = logging.getLogger(__name__)

class SshClient:
    """
    High-level SSH Client.
    Mimics paramiko.SSHClient interaction where possible.
    """
    def __init__(self):
        self.transport = None
        self.connection = None
        self._policy = None # Missing host key policy

    def set_missing_host_key_policy(self, policy):
        self._policy = policy

    def load_system_host_keys(self, filename=None):
        pass # TODO

    def connect(self, hostname, port=22, username=None, password=None, pkey=None, 
                key_filename=None, timeout=None, allow_agent=True, look_for_keys=True,
                compress=False, sock=None, gss_auth=False, gss_kex=False,
                gss_deleg_creds=False, gss_host=None, banner_timeout=None,
                auth_timeout=None, channel_timeout=None, disabled_algorithms=None):
        
        # 1. Create Socket if not provided
        if sock is None:
             sock = socket.create_connection((hostname, port), timeout=timeout)
             
        # 2. Start Transport
        self.transport = SshTransport(sock)
        self.transport.connect() # Handles handshake + KEX
        
        # 3. Authenticate
        auth_agent = SshAuthAgent(self.transport)
        
        # Register auth agent as handler for auth packets?
        # Check how Transport dispatches.
        # Transport puts packets in queue if not handled internal.
        # We need a loop/dispatcher? 
        # For now, let's assume Transport is modified or AuthAgent handles it by polling queue?
        # My Transport puts unknown packets in self.packet_queue.
        
        # We need to hook up dispatching properly.
        # In this simplified version, let's just make sure we can auth.
        
        # TODO: Implement proper dispatch loop or callback registration in Transport.
        # For now, let's assume we can auth.
        try:
            if password:
                auth_agent.authenticate_password(username, password)
            # elif pkey: ...
            else:
                # Try none to get methods?
                auth_agent.authenticate_none(username) 
                
        except Exception as e:
            self.close()
            raise e
            
        # 4. Start Connection Layer
        self.connection = SshConnection(self.transport)
        # We need to start a thread to pump packets from transport queue to connection/auth?
        self._start_packet_pump()
        
    def _start_packet_pump(self):
        # Background thread to move packets from transport.packet_queue to Connection
        import threading
        t = threading.Thread(target=self._pump_loop, daemon=True)
        t.start()
        
    def _pump_loop(self):
        # Poll transport queue
        # This is inefficient, in real app Transport calls callbacks.
        import time
        while self.transport and self.transport.active:
             # Pop from queue
             with self.transport.lock:
                 if self.transport.packet_queue:
                     pkt = self.transport.packet_queue.pop(0)
                 else:
                     pkt = None
             
             if pkt:
                 self.connection.dispatch_message(pkt)
             else:
                 time.sleep(0.01)

    def get_transport(self):
        return self.transport
        
    def open_sftp(self):
        """
        Open SFTP Client.
        """
        chan = self.connection.open_channel("session")
        return SshSFTPClient(chan)
        
    def exec_command(self, command, bufsize=-1, timeout=None, get_pty=False, environment=None):
        """
        Execute a command.
        Returns (stdin, stdout, stderr) - but we might need to conform to what paramiko returns.
        Paramiko returns ChannelFile objects.
        """
        chan = self.connection.open_channel("session")
        if get_pty:
            chan.request_pty()
        chan.request_exec(command)
        
        # Return file-like objects wrapping the channel
        # TODO: Implement ChannelFile
        # For now, return the channel itself three times? No, that breaks API.
        # Or just return channel to simplify?
        return None, chan, None # Mock

    def invoke_shell(self, term='vt100', width=80, height=24, width_pixels=0, height_pixels=0, environment=None):
        chan = self.connection.open_channel("session")
        chan.request_pty(term=term, width=width, height=height)
        chan.request_shell()
        return chan

    def close(self):
        if self.transport:
            self.transport.close()
