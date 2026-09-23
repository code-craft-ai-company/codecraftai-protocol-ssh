"""
    .. module:: sshagent
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Module containing the :class:`SshAgent` class.
    
    .. moduleauthor:: Myron Walker <myron.walker@gmail.com>
    
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2025, Code Craft AI LLC"
__credits__ = []


from typing import Dict, Optional, Sequence, Union, Tuple

from ccai.xmodules.xlogging.enhancedloggers import getEnhancedLogger

from ccai.protocols.ssh.sshclient import SshClient
import socket
import time

from ccai.interop.aspects import  AspectsCmd, DEFAULT_CMD_ASPECTS
from ccai.credentials.sshcredential import SshCredential

from ccai.protocols.ssh.sshbase import SshBase
from ccai.protocols.ssh.sshconst import (
    SshJumpParams
)
from ccai.protocols.ssh.sshsession import SshSession
from ccai.protocols.ssh.sshtunnel import SshTunnel


logger = getEnhancedLogger()


class SshAgent(SshBase):
    """
        The :class:`SshAgent` provides an extension of the :class:`SshBase` class interface and api(s).  The :class:`SshAgent` manages connection
        and interop settings that are used to perform operations and interact with a remote SSH service.  The :class:`SshAgent` provides standard
        APIs for running command and transferring files along with code that helps ensure commands are logged cleanly.  The :class:`SshAgent` also
        provides run patterning to help eliminate duplication of code associated with running SSH commands in loops.
    """
    def __init__(self, host: str, primary_credential: SshCredential, users: Optional[Dict[str, SshCredential]] = None, port: int = 22, jump: Union[str, SshJumpParams, None] = None,
                 pty_params: Optional[dict] = None, called_id: Optional[str]=None, look_for_keys: bool = False, aspects: AspectsCmd = DEFAULT_CMD_ASPECTS):
        """
            Initialize an :class:`SshAgent` instance.

            :param host: Hostname or IP address of the target.
            :param primary_credential: Primary SSH credential.
            :param users: Optional dictionary of additional credentials.
            :param port: SSH port number.
            :param jump: Optional jump host settings.
            :param pty_params: Parameters used when requesting a PTY.
            :param called_id: Friendly identifier for logging purposes.
            :param look_for_keys: Search for SSH keys in default locations.
            :param aspects: Default command aspects for operations.
        """
        SshBase.__init__(self, host, primary_credential, users=users, port=port, jump=jump,
                         pty_params=pty_params, called_id=called_id, look_for_keys=look_for_keys, aspects=aspects)
        return

    def open_session(self, user: str = None, primitive: bool = False, pty_params: Optional[dict] = None, interactive=False, basis_session: Optional[SshSession] = None,
                     aspects: Optional[AspectsCmd] = None) -> SshSession:
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
            bs = basis_session
            session = SshSession(bs._host, session_credential, users=bs._users, port=bs._port,
                                 jump=bs._jump, pty_params=pty_params, interactive=interactive,
                                 basis_session=basis_session, look_for_keys=bs._look_for_keys, primitive=primitive, aspects=aspects)
        else:
            session = SshSession(self._host, session_credential, users=self._users, port=self._port,
                                 jump=self._jump, pty_params=pty_params, interactive=interactive,
                                 look_for_keys=self._look_for_keys, primitive=primitive, aspects=aspects)
        return session

    def open_tunnel(self, local_port: int = 0, remote_host: str = 'localhost', remote_port: int = 5432) -> SshTunnel:
        """
            Creates a single SSH port forwarding tunnel to a remote service. This is the ONLY way to create 
            SSH tunnels. Each tunnel represents exactly one port forward. To create multiple tunnels, 
            call this method multiple times.

            :param local_port: Local port to bind for forwarding. If 0, an available port will be chosen.
            :param remote_host: Remote host to forward to (default: localhost on remote machine).
            :param remote_port: Remote port to forward to (default: 5432 for PostgreSQL).

            :returns: A new :class:`SshTunnel` instance representing a single port forward with an established SSH connection.
            
            :raises: RuntimeError if tunnel creation fails.
            :raises: ConnectionError if SSH connection cannot be established.
        """
        # Create and establish the SSH connection
        ssh_client = self._create_client()
        
        try:
            # Create the tunnel using the internal creation method
            tunnel = SshTunnel._create_internal(ssh_client, local_port, remote_host, remote_port)
            return tunnel
        except Exception as e:
            # If tunnel creation fails, clean up the SSH client
            try:
                ssh_client.close()
            except Exception:
                # Ignore errors when closing the client
                pass
            
            # Re-raise the original exception with additional context
            raise RuntimeError(f"Failed to create SSH tunnel to {remote_host}:{remote_port}: {e}") from e

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
            # Log unexpected exceptions but continue with reboot verification
            logger.warning(f"Unexpected exception during reboot command: {e}")

        # Since we are NOT a session, we need to verify the remote machine is back up by attempting to
        # connect to the machine and run a command. We raise a TimeoutError if we cannot connect and
        # run a command before the reboot_timeout runs out.
        
        reboot_timeout = 300  # 5 minutes default timeout
        if aspects and hasattr(aspects, 'completion_timeout'):
            reboot_timeout = aspects.completion_timeout
        
        start_time = time.time()
        end_time = start_time + reboot_timeout
        retry_interval = 10  # Wait 10 seconds between attempts
        
        # Wait a bit for the reboot to start
        time.sleep(30)
        
        while time.time() < end_time:
            try:
                # Try to connect and run a simple command
                if self.verify_connectivity():
                    logger.info(f"Host {self._host} is back online after reboot")
                    return
            except Exception:
                # Connection failed, continue waiting
                pass
            
            time.sleep(retry_interval)
        
        # If we get here, the timeout was reached
        raise TimeoutError(f"Host {self._host} did not come back online within {reboot_timeout} seconds after reboot")

    def run_cmd(self, command: str, exp_status: Union[int, Sequence]=0, user: str = None, pty_params: dict = None, aspects: Optional[AspectsCmd] = None, ssh_client: Optional[SshClient]=None) -> Tuple[int, str, str]: # pylint: disable=arguments-differ
        """
            Runs a command on the designated host using the specified parameters.

            :param command: The command to run.
            :param exp_status: An integer or sequence of integers that specify the set of expected status codes from the command.
            :param user: The registered name of the user role to use to lookup the credentials for running the command.
            :param pty_params: The pty parameters to use to request a PTY when running the command.
            :param aspects: The run aspects to use when running the command.
            :param ssh_client: An optional connected SSHClient that should be for the operation.

            :returns: The status, stderr and stdout from the command that was run.
        """
        cleanup_client = False

        status, stdout, stderr = None, None, None

        try:
            if ssh_client is None:
                # If we are not passed in a client to use, we create one
                # and then clean it up before returning
                ssh_client = self._create_client(user)
                cleanup_client = True

            status, stdout, stderr = self._run_cmd(ssh_client, command, exp_status=exp_status, user=user, pty_params=pty_params, aspects=aspects)

        finally:
            # If we created a client, clean it up
            if cleanup_client:
                ssh_client.close()
                del ssh_client

        return status, stdout, stderr

    def directory_tree(self, root_dir: str, depth: int = 1, ssh_client: Optional[SshClient] = None) -> dict:
        """
            Method that creates a directory tree for the folder.

            :param root_dir: The root directory to scan when creating the tree.
            :param depth: The depth to scan to
            :param ssh_client: An optional connected SSHClient that should be for the operation.

            :returns: A dictionary with a tree of information about the directory tree found on the remote system.
        """
        dir_info = {}

        cleanup_client = False
        try:
            if ssh_client is None:
                ssh_client = self._create_client()
                cleanup_client = True

            dir_info = self._directory_tree(ssh_client, root_dir, depth=depth)

        finally:
            if cleanup_client:
                ssh_client.close()
                del ssh_client

        return dir_info

    def directory(self, root_dir: str, ssh_client: Optional[SshClient] = None) -> dict:
        """
            Method that creates a directory listing for the folder.

            :param root_dir: The directory to scan when creating the tree.
            :param ssh_client: An optional connected SSHClient that should be for the operation.

            :returns: A dictionary that contains information about the items in the target directory.
        """
        dir_info = {}

        cleanup_client = False
        try:
            if ssh_client is None:
                ssh_client = self._create_client()
                cleanup_client = True

            dir_info = self._directory(ssh_client, root_dir)

        finally:
            if cleanup_client:
                ssh_client.close()
                del ssh_client

        return dir_info

    def directory_exists(self, remotedir: str, ssh_client: Optional[SshClient] = None) -> bool:
        """
            Method used to check if a remote directory exists.

            :param remotedir: The remote remotedir path to check for existence.
            :param ssh_client: An optional connected SSHClient that should be for the operation.

            :returns: ``True`` if the directory exists, otherwise ``False``.
        """
        exists = False
        cleanup_client = False

        try:
            if ssh_client is None:
                ssh_client = self._create_client()
                cleanup_client = True

            exists = self._directory_exists(ssh_client, remotedir)

        finally:
            if cleanup_client:
                ssh_client.close()
                del ssh_client

        return exists

    def file_exists(self, remotepath: str, ssh_client: Optional[SshClient] = None) -> bool:
        """
            Method used to check if a remote file exists.

            :param remotepath: The remote file path to check for existence.
            :param ssh_client: An optional connected SSHClient that should be for the operation.

            :returns: ``True`` if the file exists, otherwise ``False``.
        """
        exists = False
        cleanup_client = False

        try:
            if ssh_client is None:
                ssh_client = self._create_client()
                cleanup_client = True

            exists = self._file_exists(ssh_client, remotepath)

        finally:
            if cleanup_client:
                ssh_client.close()
                del ssh_client

        return exists

    def file_pull(self, remotepath: str, localpath: str, ssh_client: Optional[SshClient] = None):
        """
            Method used to pull a remote file to a local file path.

            :param remotepath: The remote file path to pull to the local file.
            :param localpath: The local file path to pull the content to.
            :param ssh_client: An optional connected SSHClient that should be for the operation.
        """
        cleanup_client = False
        try:
            if ssh_client is None:
                ssh_client = self._create_client()
                cleanup_client = True

            self._file_pull(ssh_client, remotepath, localpath)

        finally:
            if cleanup_client:
                ssh_client.close()
                del ssh_client

        return

    def file_push(self, localpath: str, remotepath: str, ssh_client: Optional[SshClient] = None):
        """
            Method used to push a local file to a remote file path.

            :param localpath: The local file path to push the content of to the remote file.
            :param remotepath: The remote file path to push content to.
            :param ssh_client: An optional connected SSHClient that should be for the operation.
        """
        cleanup_client = False
        try:
            if ssh_client is None:
                ssh_client = self._create_client()
                cleanup_client = True

            self._file_push(ssh_client, localpath, remotepath)

        finally:
            if cleanup_client:
                ssh_client.close()
                del ssh_client

        return

    def get_home_directory(self, aspects: Optional[AspectsCmd] = None) -> str:
        """
            Method used to get the home directory of the credentialed user from a remote machine.
        """
        home_dir = self._get_home_directory(aspects=aspects)
        return home_dir
