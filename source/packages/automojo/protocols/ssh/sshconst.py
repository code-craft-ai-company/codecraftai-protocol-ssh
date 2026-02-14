"""
    .. module:: sshconst
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Module containing ssh constants
    
    .. moduleauthor:: Myron Walker <myron.walker@gmail.com>
    
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2025, Automation Mojo LLC"
__credits__ = []


import dataclasses
import os
import re

from automojo.credentials.sshcredential import SshCredential

DEFAULT_SSH_TIMEOUT = 300
DEFAULT_SSH_RETRY_INTERVAL = .5

DEFAULT_FAILURE_LABEL = "Failure"
DEFAULT_SUCCESS_LABEL = "Success"

INTERACTIVE_PROMPT="PROMPT%:%:%"
INTERACTIVE_PROMPT_BYTES = INTERACTIVE_PROMPT.encode('utf-8')

TEMPLATE_COMMAND_FAILURE = "RUNCMD%s: " + DEFAULT_FAILURE_LABEL + " running CMD=%s" + os.linesep + "STDOUT:" + os.linesep + "%s" + os.linesep + "STDERR:" + os.linesep + "%s"
TEMPLATE_COMMAND_SUCCESS = "RUNCMD%s: " + DEFAULT_SUCCESS_LABEL + " running CMD=%s" + os.linesep + "STDOUT:" + os.linesep + "%s" + os.linesep + "STDERR:" + os.linesep + "%s"

#                    PERMS          LINKS   OWNER       GROUPS    SIZE   MONTH  DAY  TIME    NAME
#                  rwxrwxrwx         24      myron      myron     4096   Jul    4   00:37  PCBs
REGEX_DIRECTORY_ENTRY = re.compile(r"([\S]+)\s+([0-9]+)\s+([\S]+)\s+([\S]+)\s+([0-9]+)\s+([A-Za-z]+\s+[0-9]+\s+(?:[0-9:]+|[0-9]+))\s+(.+)")


@dataclasses.dataclass
class SshJumpParams:
    """
        Parameters describing an SSH jump host used for tunneling.

        :param host: Hostname or IP address of the jump server.
        :param credential: Credential used when connecting to the jump host.
        :param port: Port number of the SSH service.
    """
    host: str
    credential: SshCredential
    port: int = 22
