"""
    .. module:: sshsession
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Module containing the :class:`SshSession` class.
    
    .. moduleauthor:: Myron Walker <myron.walker@gmail.com>
    
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2025, Code Craft AI LLC"
__credits__ = []


from typing import Dict, Optional, Sequence, Union, Tuple

from types import TracebackType
import socket
import time

from ccai.protocols.ssh.sshclient import SshClient

from ccai.errors.exceptions import UnExpectedSessionClosureError

from ccai.xmodules.xlogging.enhancedloggers import getEnhancedLogger

from ccai.credentials.sshcredential import SshCredential

from ccai.interop.aspects import AspectsCmd, DEFAULT_CMD_ASPECTS
from ccai.protocols.ssh.sshconst import (
    SshJumpParams,
    DEFAULT_SSH_TIMEOUT,
    DEFAULT_SSH_RETRY_INTERVAL,
    INTERACTIVE_PROMPT
)
from ccai.protocols.ssh.sshhelpers import (
    ssh_execute_command,
    ssh_execute_command_in_channel
)
from ccai.protocols.ssh.sshbase import SshBase

logger = getEnhancedLogger()

class SshSession(SshBase):
    """
        The :class:`SshSession` provides an extension of the :class:`SshBase` class interface and api(s).  The :class:`SshSession` serves to
        act as a session scoping object that establishes a set of SSH credentials, settings and patterns that are to be used for a series of
        SSH operations.  The :class:`SshSession` also holds open the SSHClient for its entire scope and ensures the SSHClient is closed and
        cleaned up properly when the :class:`SshSession` goes out of scope.
    """
    def __init__(self, host: str, primary_credential: SshCredential, users: Optional[Dict[str, SshCredential]] = None, port:int=22, jump: Union[str, SshJumpParams, None] = None,
                 pty_params: Optional[dict] = None, session_user=None, interactive=False, basis_session: Optional["SshSession"]=None,
                 called_id: Optional[str]=None, look_for_keys: bool = False, primitive: Optional[bool] = None, aspects: AspectsCmd=DEFAULT_CMD_ASPECTS):
        """
            Create a new :class:`SshSession` instance.

            :param host: Target host name.
            :param primary_credential: Primary credential for authentication.
            :param users: Additional credential mappings.
            :param port: SSH port number.
            :param jump: Optional jump host settings.
            :param pty_params: Default PTY parameters for command execution.
            :param session_user: Username to use for the session.
            :param interactive: Flag indicating an interactive shell is desired.
            :param basis_session: Optional session to base this one on.
            :param called_id: Friendly identifier used in logs.
            :param look_for_keys: Search for SSH keys in default locations.
            :param primitive: Override primitive mode for this session. If None, uses credential's primitive setting.
            :param aspects: Default command aspects for operations.
        """
        SshBase.__init__(self, host, primary_credential, users=users, port=port, jump=jump,
                         pty_params=pty_params, called_id=called_id, look_for_keys=look_for_keys, aspects=aspects)

        self._session_user = session_user
        self._interactive = interactive
        self._read_timeout = 2

        # Override primitive mode if specified for this session
        if primitive is not None:
            self._primitive = primitive

        self._ssh_client = None
        self._ssh_runner = None
        self._basis_session = basis_session
        return

    def __enter__(self):
        """
            Method that implements the __enter__ symantics used for 'with' statements.
        """
        self._ssh_client = self._create_client()

        if self._interactive:
            inactivity_timeout = self._aspects.inactivity_timeout

            channel = None
            try:
                channel = self._ssh_client.connection.open_channel("session")

                if self._pty_params is not None:
                    channel.request_pty(**self._pty_params)
                else:
                    channel.request_pty()

                channel.request_shell()
                channel.send("export PS1=%s\n" % INTERACTIVE_PROMPT)

                leader = b""
                max_leader_size = 8192  # Limit accumulated data to prevent memory issues
                start_time = time.time()

                prompt_received = False
                try:
                    while True:
                        # Check for overall timeout using aspects inactivity_timeout
                        if time.time() - start_time > inactivity_timeout:
                            logger.error("Interactive shell initialization timeout after %s seconds", inactivity_timeout)
                            break
                            
                        out = channel.recv(1028, timeout=self._read_timeout)
                        if not out:
                            if not channel.closed:
                                # Timeout means we are likely at the prompt
                                prompt_received = True
                            break

                        leader += out
                        
                        # Prevent unlimited memory growth
                        if len(leader) > max_leader_size:
                            # Keep only the last portion of the data
                            leader = leader[-max_leader_size//2:]
                            
                        # Check if we've received the prompt we're looking for
                        if INTERACTIVE_PROMPT.encode('utf-8') in leader:
                            prompt_received = True
                            break
                            
                except Exception as e:
                    logger.error("Exception during interactive shell initialization: %s", e)
                    # Clean up resources on failure
                    if channel:
                        try:
                            channel.close()
                        except Exception:
                            # Best-effort cleanup; a failure to close the channel must not mask the initialization error raised below.
                            pass
                    self._cleanup_ssh_client()
                    raise RuntimeError(f"Failed to initialize interactive shell: {e}") from e

                # Verify that initialization was successful
                if not prompt_received:
                    # Clean up resources on failure
                    if channel:
                        try:
                            channel.close()
                        except Exception:
                            # Best-effort cleanup; a failure to close the channel must not mask the initialization failure raised below.
                            pass
                    self._cleanup_ssh_client()
                    raise RuntimeError("Interactive shell initialization failed - prompt not received within timeout")

                self._ssh_runner = channel
                
            except Exception as e:
                # If any exception occurs during channel setup, clean up the SSH client
                if channel:
                    try:
                        channel.close()
                    except Exception:
                        # Best-effort cleanup; a failure to close the channel must not mask the original error re-raised below.
                        pass
                self._cleanup_ssh_client()
                raise
        else:
            self._ssh_runner = self._ssh_client

        return self

    def __exit__(self, ex_type: type, ex_val: Exception, ex_tb: TracebackType) -> bool:
        """
            Method that implements the __exit__ symantics used for 'with' statements.

            :returns: Returns false indicating that exceptions are not handled.
        """
        self.close()
        handled = False
        return handled

    def close(self):
        """
            Closes the SSH session and the associated SSH connection.
        """
        # Close interactive channel if it exists and is different from the client
        if hasattr(self, '_ssh_runner') and self._ssh_runner is not None and self._ssh_runner != self._ssh_client:
            try:
                if hasattr(self._ssh_runner, 'close'):
                    self._ssh_runner.close()
            except Exception:
                # Ignore errors when closing the channel
                pass
            finally:
                self._ssh_runner = None
        
        # Only close the client if this session owns the client and it exists
        if self._basis_session is None and hasattr(self, '_ssh_client') and self._ssh_client is not None:
            try:
                self._ssh_client.close()
            except Exception:
                # Ignore errors when closing the client (might already be closed)
                pass
            finally:
                self._ssh_client = None
        
        return

    def directory(self, root_dir: str) -> dict:
        """
            Method that creates a directory listing for the folder.

            :param root_dir: The directory to scan when creating the tree.

            :returns: A dictionary that contains information about the items in the target directory.
        """
        dir_info = self._directory(self._ssh_client, root_dir)

        return dir_info

    def directory_exists(self, remotedir: str) -> bool:
        """
            Method used to pull a remote directory to check for existence.

            :param remotedir: The remote directory path to check for existence.

            :returns: A boolean value indicating if the remote file exists.
        """
        exists = self._directory_exists(self._ssh_client, remotedir)

        return exists

    def directory_tree(self, root_dir: str, depth: int = 1) -> dict:
        """
            Method that creates a directory tree for the folder.

            :param root_dir: The root directory to scan when creating the tree.
            :param depth: The depth to scan to

            :returns: A dictionary with a tree of information about the directory tree found on the remote system.
        """
        dir_info = self._directory_tree(self._ssh_client, root_dir, depth=depth)

        return dir_info

    def file_exists(self, remotepath: str) -> bool:
        """
            Method used to pull a remote file to check for existence.

            :param remotepath: The remote file path to check for existence.

            :returns: A boolean value indicating if the remote file exists.
        """
        exists = self._file_exists(self._ssh_client, remotepath)

        return exists

    def file_pull(self, remotepath: str, localpath: str):
        """
            Method used to pull a remote file to a local file path.

            :param remotepath: The remote file path to pull to the local file.
            :param localpath: The local file path to pull the content to.
        """
        self._file_pull(self._ssh_client, remotepath, localpath)

        return

    def file_push(self, localpath: str, remotepath: str):
        """
            Method used to push a local file to a remote file path.

            :param localpath: The local file path to push the content of to the remote file.
            :param remotepath: The remote file path to push content to.
        """
        self._file_push(self._ssh_client, localpath, remotepath)

        return

    def get_home_directory(self, aspects: Optional[AspectsCmd] = None) -> str:
        """
            Method used to get the home directory of the credentialed user from a remote machine.
        """
        home_dir = self._get_home_directory(aspects=aspects)
        return home_dir

    def open_session(self, user: str = None, primitive: bool = False, pty_params: Optional[dict] = None, interactive=False, basis_session: Optional["SshSession"] = None,
                     aspects: Optional[AspectsCmd] = None, **kwargs) -> "SshSession":
        """
            Provies a mechanism to create a :class:`SshSession` object with derived settings.  This method allows various parameters for the session
            to be overridden.  This allows for the performing of a series of SSH operations under a particular set of shared settings and or credentials.

            :param user: open the session under a different user credential.
            :param primitive: Use primitive mode for FTP operations for the session.
            :param pty_params: The default pty parameters to use to request a PTY when running commands through the session.
            :param interactive: Creates an interactive session which holds open an interactive shell so commands can interact in the shell.
            :param basis_session: An optional SshSession instance to use as a session basis.  This allows re-use of sessions.
            :param aspects: The default run aspects to use for the operations performed by the session.

            :returns: A new :class:`SshSession` instance with the requested parameters.
        """

        if aspects is None:
            aspects = self._aspects

        session_credential = self._primary_credential
        if user is not None:
            session_credential = self._users[user]

        session = None
        if basis_session is not None:
            bs: SshSession = basis_session
            session = SshSession(bs._host, session_credential, users=bs._users, port=bs._port,
                                 jump=bs._jump, pty_params=pty_params, interactive=interactive,
                                 basis_session=bs, look_for_keys=bs._look_for_keys, primitive=primitive, aspects=aspects)
        else:
            session = SshSession(self._host, session_credential, users=self._users, port=self._port,
                                 jump=self._jump, pty_params=pty_params, interactive=interactive,
                                 look_for_keys=self._look_for_keys, primitive=primitive, aspects=aspects)
        return session

    def reboot(self, aspects: Optional[AspectsCmd] = None):
        """
            Reboots the designated host by running the 'reboot' command on the host.
            
            ..note: This method is not a typical SSH functionality, but it was added so that
                    automatic reconnects can be implemented as required on session objects.

        """
        reboot_cmd = 'reboot'
        try:
            self.run_cmd(reboot_cmd, aspects=aspects)
        except (ConnectionError, socket.error, EOFError) as e:
            # We might see a connection dropout exception here during reboot, which is expected
            logger.debug(f"Expected connection error during reboot: {e}")
        except KeyboardInterrupt:
            # Allow keyboard interrupts to propagate
            raise
        except SystemExit:
            # Allow system exits to propagate
            raise
        except Exception as e:
            # Log unexpected exceptions but continue with session closure
            logger.warning(f"Unexpected exception during reboot command: {e}")

        # Since we are a session, we need to reconnect to the remote machine after the reboot.
        errmsg = "Session closed due to reboot."
        raise UnExpectedSessionClosureError(errmsg)

    def run_cmd(self, command: str, exp_status: Union[int, Sequence]=0, user: Optional[str] = None, pty_params: dict = None, aspects: Optional[AspectsCmd] = None) -> Tuple[int, str, str]:
        """
            Runs a command on the designated host using the current session SSH session and client.

            :param command: The command to run.
            :param exp_status: An integer or sequence of integers that specify the set of expected status codes from the command.
            :param pty_params: The pty parameters to use to request a PTY when running the command.
            :param aspects: The run aspects to use when running the command.

            :returns: The status, stderr and stdout from the command that was run.
        """

        status, stdout, stderr = self._run_cmd(self._ssh_runner, command, exp_status=exp_status, user=user, pty_params=pty_params, aspects=aspects)

        return status, stdout, stderr

    def _cleanup_ssh_client(self):
        """
            Helper method to clean up the SSH client when initialization fails.
        """
        if hasattr(self, '_ssh_client') and self._ssh_client is not None:
            # Only close if this session owns the client (not a basis session)
            if self._basis_session is None:
                try:
                    self._ssh_client.close()
                except Exception:
                    # Best-effort cleanup; this runs while an initialization failure is being handled and a failure
                    # to close the client must not mask that original error.
                    pass
            self._ssh_client = None

    def _create_client(self, session_user: Optional[str] = None) -> SshClient:
        """
            Create an SSHClient to use for running commands and performing FTP operations.

            :param session_user: The user role and associated credentials to use when creating the SSHClient.

            :returns: An SSHClient object connected to the remote machine under the default or specified user credential.
            
            :raises: RuntimeError if the basis session client is invalid or no longer active.
        """
        ssh_client = None
        if self._basis_session is not None and session_user is None:
            # Only reuse basis session client if no specific session_user is requested
            basis_client = self._basis_session._ssh_client
            if basis_client is None:
                raise RuntimeError("Basis session SSH client is None - the basis session may not have been properly initialized")
            
            # Check if the basis session client is still connected
            transport = basis_client.get_transport()
            if transport is None or not transport.is_active():
                raise RuntimeError("Basis session SSH client is no longer active - the connection has been closed or lost")
            
            ssh_client = basis_client
        else:
            # Create new client with specified session_user or default credentials
            ssh_client = super()._create_client(session_user=session_user)
        return ssh_client

    def _ssh_execute_command(self, ssh_runner, command: str, pty_params=None, inactivity_timeout: float=DEFAULT_SSH_TIMEOUT, inactivity_interval: float=DEFAULT_SSH_RETRY_INTERVAL, chunk_size: int=1024) -> Tuple[int, str, str]:
        """
            Private helper method used to route the command running parameters to the correct routine based on whether the command is being run interactively
            through a session or is a single run command from an SshAgent.

            :param ssh_runner: A :class:`SshClient` or :class:`SshChannel` object that can be used to run a command on a remote machine.
            :param command: The command that is to be run.
            :param pty_params: A dictionary of parameters that are passed to paramiko to get a pty when running commands.
            :param inactivity_timeout: A timeout for inactivity between the local machine and remote machine.
            :param inactivity_interval: The interval to wait between attempts to interact or read from the remote machine.
            :param chunk_size: The size of the buffer to use when reading results from the remote machine.
        """
        if self._interactive:
            status, stdout, stderr = ssh_execute_command_in_channel(ssh_runner, command, read_timeout=self._read_timeout, inactivity_timeout=inactivity_timeout, inactivity_interval=inactivity_interval)
        else:
            status, stdout, stderr = ssh_execute_command(ssh_runner, command, pty_params=pty_params, inactivity_timeout=inactivity_timeout, inactivity_interval=inactivity_interval)
        return status, stdout, stderr
