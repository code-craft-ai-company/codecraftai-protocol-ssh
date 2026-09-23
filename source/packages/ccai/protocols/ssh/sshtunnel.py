"""
    .. module:: sshtunnel
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Module containing the :class:`SshTunnel` class.
    
    .. moduleauthor:: Myron Walker <myron.walker@gmail.com>
    
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2025, Code Craft AI LLC"
__credits__ = []


from types import TracebackType
import socket
import select
import threading

from ccai.protocols.ssh.sshclient import SshClient
from ccai.protocols.ssh.sshconnection import SshConnection, SshChannel

from ccai.xmodules.xlogging.enhancedloggers import getEnhancedLogger

logger = getEnhancedLogger()


class SshTunnel:
    """
        The :class:`SshTunnel` represents a single SSH port forwarding tunnel for connecting to a remote service
        through an SSH connection. Each SshTunnel instance manages exactly one port forward.
        
        Note: SshTunnel instances should only be created through SshAgent.open_tunnel() method.
    """

    def __init__(self, ssh_client: SshClient, local_port: int, remote_host: str, remote_port: int, _internal_create: bool = False):
        """
            Initialize an :class:`SshTunnel` instance with an existing SSH client and tunnel parameters.
            
            Note: This constructor should not be called directly. Use SshAgent.open_tunnel() instead.

            :param ssh_client: An established SshClient connection.
            :param local_port: Local port to bind for forwarding. If 0, an available port will be chosen.
            :param remote_host: Remote host to forward to.
            :param remote_port: Remote port to forward to.
            :param _internal_create: Internal flag to prevent direct instantiation.
        """
        if not _internal_create:
            raise RuntimeError("SshTunnel instances should only be created through SshAgent.open_tunnel() method")
        
        self._ssh_client = ssh_client
        self._local_port = local_port
        self._remote_host = remote_host
        self._remote_port = remote_port
        self._actual_local_port = None
        self._local_socket = None
        self._forward_thread = None
        self._active = False
        self._owns_ssh_client = True  # This tunnel owns the SSH client and should close it
        self._connection_threads = []  # Track active connection threads
        self._connection_lock = threading.Lock()  # Protect connection thread list
        
        # Start the tunnel immediately
        self._start_tunnel()
        return

    @classmethod
    def _create_internal(cls, ssh_client: SshClient, local_port: int, remote_host: str, remote_port: int) -> 'SshTunnel':
        """
            Internal method for creating SshTunnel instances. Only used by SshAgent.

            :param ssh_client: An established SshClient connection.
            :param local_port: Local port to bind for forwarding. If 0, an available port will be chosen.
            :param remote_host: Remote host to forward to.
            :param remote_port: Remote port to forward to.

            :returns: A new SshTunnel instance.
        """
        return cls(ssh_client, local_port, remote_host, remote_port, _internal_create=True)

    def __enter__(self):
        """
            Method that implements the __enter__ semantics used for 'with' statements.
        """
        return self

    def __exit__(self, ex_type: type, ex_val: Exception, ex_tb: TracebackType) -> bool:
        """
            Method that implements the __exit__ semantics used for 'with' statements.
            Shuts down the tunnel and cleans up all threads and resources.

            :returns: Returns false indicating that exceptions are not handled.
        """
        self.shutdown()
        handled = False
        return handled

    def close(self):
        """
            Closes all port forwards and cleans up resources. Also closes the SSH client.
            This is an alias for shutdown() for backward compatibility.
        """
        self.shutdown()
        return

    def shutdown(self):
        """
            Shuts down the tunnel by stopping the port forward and cleaning up all threads and resources.
            Also closes the SSH client since this tunnel owns it.
        """
        logger.info(f"Shutting down SSH tunnel 127.0.0.1:{self._actual_local_port} -> {self._remote_host}:{self._remote_port}")
        
        # Mark as inactive
        self._active = False
        
        # Close the listening socket to stop accepting new connections
        if self._local_socket:
            try:
                self._local_socket.close()
            except Exception as e:
                logger.debug(f"Error closing socket: {e}")
            finally:
                self._local_socket = None
        
        # Wait for the forwarding thread to complete
        if self._forward_thread and self._forward_thread.is_alive():
            logger.debug("Waiting for forwarding thread to complete...")
            self._forward_thread.join(timeout=10.0)
            if self._forward_thread.is_alive():
                logger.warning("Forwarding thread did not complete within timeout")
        
        # Wait for connection handler threads to complete
        with self._connection_lock:
            active_connections = [t for t in self._connection_threads if t.is_alive()]
        
        if active_connections:
            logger.debug(f"Waiting for {len(active_connections)} connection handler threads to complete...")
            for thread in active_connections:
                thread.join(timeout=5.0)
                if thread.is_alive():
                    logger.warning(f"Connection handler thread did not complete within timeout")
        
        # Close the SSH client since this tunnel owns it
        if self._owns_ssh_client and self._ssh_client:
            try:
                self._ssh_client.close()
                logger.debug("SSH client closed")
            except Exception as e:
                logger.warning(f"Error closing SSH client: {e}")
            finally:
                self._ssh_client = None
        
        logger.info("SSH tunnel shutdown complete")
        return

    def _start_tunnel(self):
        """
            Private method that starts the port forwarding tunnel.
        """
        # Create a local socket to listen on
        self._local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # If local_port is 0, let the OS choose an available port
        self._local_socket.bind(('127.0.0.1', self._local_port))
        self._actual_local_port = self._local_socket.getsockname()[1]
        self._local_socket.listen(5)
        
        # Mark as active
        self._active = True
        
        # Start the forwarding loop in a separate daemon thread
        self._forward_thread = threading.Thread(
            target=self._forward_loop,
            daemon=True
        )
        self._forward_thread.start()
        
        logger.info(f"SSH tunnel port forward started: 127.0.0.1:{self._actual_local_port} -> {self._remote_host}:{self._remote_port}")
        return

    def _forward_loop(self):
        """
            Private method that handles the port forwarding loop by accepting connections and forwarding
            traffic over the SSH transport.
        """
        try:
            while self._active:
                try:
                    transport = self._ssh_client.get_transport()
                    if transport is None or not transport.is_active():
                        logger.error("SSH transport is no longer active, stopping tunnel")
                        break
                    
                    connection = self._ssh_client.connection

                    # Accept incoming connections
                    conn, addr = self._local_socket.accept()
                    logger.debug(f"Accepted connection from {addr} for tunnel to {self._remote_host}:{self._remote_port}")
                    
                    # Clean up finished connection threads before creating new ones
                    self._cleanup_finished_threads()
                    
                    # Create and track connection handler thread
                    conn_thread = threading.Thread(
                        target=self._handle_connection,
                        args=(conn, connection),
                        daemon=True
                    )
                    
                    with self._connection_lock:
                        self._connection_threads.append(conn_thread)
                    
                    conn_thread.start()
                    
                except socket.error as e:
                    # Socket errors during accept() are expected when shutting down
                    if self._active:
                        logger.error(f"Socket error in port forward: {e}")
                    else:
                        logger.debug(f"Socket error during shutdown (expected): {e}")
                    break
                except Exception as e:
                    logger.error(f"Unexpected error in port forward: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Port forward thread error: {e}")
        finally:
            try:
                if self._local_socket:
                    self._local_socket.close()
            except Exception:
                # Best-effort cleanup at forwarding thread exit; the listener is being discarded and there is
                # no caller to report a close failure to.
                pass

    def _handle_connection(self, conn: socket.socket, connection: SshConnection):
        """
            Handle a single connection through the tunnel.
            
            :param conn: The client connection socket.
            :param connection: The SSH connection to use for forwarding.
        """
        chan = None
        try:
            chan = connection.open_channel(
                "direct-tcpip",
                (self._remote_host, self._remote_port),
                conn.getsockname()
            )

            self._pump_channel(conn, chan)
        except Exception as e:
            logger.debug(f"Connection handler error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                # Best-effort cleanup; a failure to close the local socket must not prevent the channel from being closed.
                pass
            if chan is not None:
                try:
                    chan.close()
                except Exception:
                    # Best-effort cleanup; the forwarded connection is finished and the channel is being discarded.
                    pass

    def _pump_channel(self, conn: socket.socket, chan: SshChannel):
        """
            Forward data between a local socket connection and an SSH channel until one side closes.
        """
        sockets = [conn, chan]

        while self._active:
            read_ready, _, _ = select.select(sockets, [], [], 1.0)
            if not read_ready:
                continue

            if conn in read_ready:
                data = conn.recv(1024)
                if not data:
                    break
                chan.send(data)

            if chan in read_ready:
                data = chan.recv(1024)
                if not data:
                    break
                conn.sendall(data)

    def _cleanup_finished_threads(self):
        """
            Remove finished threads from the connection thread list.
        """
        with self._connection_lock:
            self._connection_threads = [t for t in self._connection_threads if t.is_alive()]

    @property
    def local_port(self) -> int:
        """
            Returns the actual local port being used for the tunnel.

            :returns: The local port number.
            
            :raises: RuntimeError if the tunnel is not properly initialized.
        """
        if self._actual_local_port is None:
            raise RuntimeError("Tunnel is not properly initialized - no local port assigned")
        return self._actual_local_port

    @property
    def remote_host(self) -> str:
        """
            Returns the remote host being forwarded to.

            :returns: The remote host.
        """
        return self._remote_host

    @property
    def remote_port(self) -> int:
        """
            Returns the remote port being forwarded to.

            :returns: The remote port number.
        """
        return self._remote_port

    @property
    def is_active(self) -> bool:
        """
            Returns whether the tunnel is currently active.

            :returns: True if active, False otherwise.
        """
        return self._active

    def get_connection_string(self, database: str = None, username: str = None, password: str = None, db_type: str = 'postgresql') -> str:
        """
            Helper method to generate database connection strings for use with SQLAlchemy or other ORMs.

            :param database: Optional database name.
            :param username: Optional username for the connection string.
            :param password: Optional password for the connection string.
            :param db_type: Database type (postgresql, mysql, etc.).

            :returns: A connection string template for the tunneled connection.
            
            :raises: RuntimeError if the tunnel is not properly initialized.
        """
        local_port = self.local_port  # This will raise RuntimeError if not initialized
        base_url = f"127.0.0.1:{local_port}"
        
        conn_str: str

        # Build authentication part
        auth_part = ""
        if username:
            if password:
                auth_part = f"{username}:{password}@"
            else:
                auth_part = f"{username}@"
        
        # Build connection string
        if database:
            conn_str = f"{db_type}://{auth_part}{base_url}/{database}"
        elif auth_part or db_type != 'postgresql':
            # Include protocol if we have auth or non-default db_type
            conn_str = f"{db_type}://{auth_part}{base_url}"
        else:
            conn_str = base_url

        return conn_str
