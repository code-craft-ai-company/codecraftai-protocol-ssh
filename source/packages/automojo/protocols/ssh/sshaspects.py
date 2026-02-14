
"""
    .. module:: sshaspects
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: sshaspects module.
    
    .. moduleauthor:: Myron Walker <myron.walker@gmail.com>
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2025, Automation Mojo LLC"
__credits__ = []

from typing import Tuple, Optional, Union

from enum import IntEnum

class Freezable:

    def __init__(self):
        object.__setattr__(self, "__frozen__", False)
        return
    
    def freeze(self):
        object.__setattr__(self, "__frozen__", True)
        return
    
    def __setattr__(self, name, value):
        # If the '__frozen__' flag exists and is True, block all changes
        if getattr(self, "__frozen__", False):
            raise AttributeError(f"Freezable objects cannot be modified after they have been initialized and frozen. name={name}")
        
        # Otherwise, allow the assignment
        object.__setattr__(self, name, value)
        return


class ActionPattern(IntEnum):
    """
        An action pattern to use when using aspects to change the behavior of an API.
    """
    SINGLE_CALL = 0
    SINGLE_CONNECTED_CALL = 1
    DO_UNTIL_SUCCESS = 2
    DO_WHILE_SUCCESS = 3
    DO_UNTIL_CONNECTION_FAILURE = 4

class LoggingPattern:
    """
        A logging pattern to use when logging commands.
    """
    ALL_RESULTS = 0
    FAILURE_ONLY = 1
    SUCCESS_ONLY = 2


DEFAULT_COMPLETION_TIMEOUT = 600
DEFAULT_COMPLETION_INTERVAL = 10

DEFAULT_CONNECTION_TIMEOUT = 16
DEFAULT_CONNECTION_INTERVAL = 2
DEFAULT_ALLOWED_CONNECTION_EXCEPTIONS: Tuple[BaseException] = []

DEFAULT_INACTIVITY_TIMEOUT = 600
DEFAULT_INACTIVITY_INTERVAL = .5

DEFAULT_MONITOR_DELAY = 30

DEFAULT_RETRY_LOGGING_INTERVAL = 5

DEFAULT_LOGGING_PATTERN = LoggingPattern.ALL_RESULTS

DEFAULT_MUST_CONNECT = False

DEFAULT_ALLOWED_ERROR_CODES: Tuple[int] = []

class Aspects(Freezable):
    """
        Aspects are utilized with the interop APIs and agents such as the :class:`SSHAgent` class in order
        to modify the behavior of APIs with respect to retry parameter such as timeout, interval, looping patterns
        logging, etc.  The aspects object provides a way to package this common criteria into a single parameter
        or constant you can  pass to multiple APIs
    """

    def __init__(self, action_pattern: ActionPattern = ActionPattern.SINGLE_CALL,
                       completion_timeout: float = DEFAULT_COMPLETION_TIMEOUT,
                       completion_interval: float = DEFAULT_COMPLETION_INTERVAL,
                       connection_timeout: float = DEFAULT_CONNECTION_TIMEOUT,
                       connection_interval: float = DEFAULT_CONNECTION_INTERVAL,
                       inactivity_timeout: float = DEFAULT_INACTIVITY_TIMEOUT,
                       inactivity_interval: float = DEFAULT_INACTIVITY_INTERVAL,
                       monitor_delay: float = DEFAULT_MONITOR_DELAY,
                       logging_pattern: LoggingPattern = DEFAULT_LOGGING_PATTERN,
                       retry_logging_interval: int = DEFAULT_RETRY_LOGGING_INTERVAL,
                       allowed_error_codes: Tuple[int] = DEFAULT_ALLOWED_ERROR_CODES,
                       allowed_connection_exceptions: Tuple[BaseException] = DEFAULT_ALLOWED_CONNECTION_EXCEPTIONS,
                       must_connect: bool = DEFAULT_MUST_CONNECT,
                       logger: Optional[logging.Logger]=None):
        """
            Creates an :class:`Aspects` instance package.

            :param action_pattern: The :class:`ActionPattern` that the API should exhibit such as
                                   SINGULAR, DO_UNTIL_SUCCESS, DO_WHILE_SUCCESS
            :param completion_timeout: The time in seconds as a float that is the max time before
                                       timeout for the activity to complete.
            :param completion_interval: The time in seconds as a float that is waited before reattempting
                                        an activity.
            :param connection_timeout: The time in seconds as a float that is the timeout for making a connection.
            :param connection_interval: The time in seconds as a float that is waited before reattempting
                                        to connect.
            :param inactivity_timeout: The time in seconds as a float that is the max time before timeout
                                       that is waited before a :class:`TimeoutError` is raised due to inactivity.
            :param inactivity_interval: The time in seconds as a float that is waited before reattempting an activity.
            :param monitor_delay: Delay in seconds before monitoring activity after startup.
            :param logging_pattern: Pattern controlling how command results are logged.
            :param retry_logging_interval: The logging interval for retry loops.
            :param allowed_error_codes: A list of error codes that allow retry
            :param allowed_connection_exceptions: List of exceptions that do not count as connection failures.
            :param must_connect: Used to indicate that connection failures should be raised.
            :param logger: Optional logger for output.
        """
        super(Aspects).__init__()

        self.action_pattern = action_pattern
        self.completion_timeout = completion_timeout
        self.completion_interval = completion_interval
        self.connection_timeout = connection_timeout
        self.connection_interval = connection_interval
        self.inactivity_timeout = inactivity_timeout
        self.inactivity_interval = inactivity_interval
        self.monitor_delay = monitor_delay
        self.logging_pattern = logging_pattern
        self.retry_logging_interval = retry_logging_interval
        self.allowed_error_codes = tuple(allowed_error_codes)
        self.allowed_connection_exceptions = tuple(allowed_connection_exceptions)
        self.must_connect=must_connect

        if logger is None:
            self.logger = getEnhancedLogger()
        else:
            self.logger = logger

        self.freeze()
        return


class AspectsCmd(Freezable):
    """
        Extends :class:`Aspects` with command-specific parameters.
    """
    def __init__(self, expected_status: Union[int, Tuple[int]]=0,
                       user: Optional[str]=None,
                       pty_params: Optional[dict]=None,
                       action_pattern: ActionPattern = ActionPattern.SINGLE_CALL,
                       completion_timeout: float = DEFAULT_COMPLETION_TIMEOUT,
                       completion_interval: float = DEFAULT_COMPLETION_INTERVAL,
                       connection_timeout: float = DEFAULT_CONNECTION_TIMEOUT,
                       connection_interval: float = DEFAULT_CONNECTION_INTERVAL,
                       inactivity_timeout: float = DEFAULT_INACTIVITY_TIMEOUT,
                       inactivity_interval: float = DEFAULT_INACTIVITY_INTERVAL,
                       monitor_delay: float = DEFAULT_MONITOR_DELAY,
                       logging_pattern: LoggingPattern = DEFAULT_LOGGING_PATTERN,
                       retry_logging_interval: int = DEFAULT_RETRY_LOGGING_INTERVAL,
                       allowed_error_codes: Tuple[int] = DEFAULT_ALLOWED_ERROR_CODES,
                       allowed_connection_exceptions: Tuple[BaseException] = DEFAULT_ALLOWED_CONNECTION_EXCEPTIONS,
                       logger: Optional[logging.Logger]=None):
        """
            Creates an :class:`AspectsCmd` instance.

            :param expected_status: Status code or list of acceptable status codes.
            :param user: Optional user name to use for command execution.
            :param pty_params: Dictionary of pseudo-terminal parameters.
            :param action_pattern: The :class:`ActionPattern` that the API should exhibit such as
                                   SINGULAR, DO_UNTIL_SUCCESS, DO_WHILE_SUCCESS
            :param completion_timeout: The time in seconds as a float that is the max time before
                                       timeout for the activity to complete.
            :param completion_interval: The time in seconds as a float that is waited before reattempting
                                        an activity.
            :param connection_timeout: The time in seconds as a float that is the timeout for making a connection.
            :param connection_interval: The time in seconds as a float that is waited before reattempting
                                        to connect.
            :param inactivity_timeout: The time in seconds as a float that is the max time before timeout
                                       that is waited before a :class:`TimeoutError` is raised due to inactivity.
            :param inactivity_interval: The time in seconds as a float that is waited before reattempting an activity.
            :param monitor_delay: Delay in seconds before monitoring activity after startup.
            :param logging_pattern: Pattern controlling how command results are logged.
            :param retry_logging_interval: The logging interval for retry loops.
            :param allowed_error_codes: A list of error codes that allow retry
            :param allowed_connection_exceptions: List of exceptions that do not count as connection failures.
        """
        super(Aspects).__init__()

        self.action_pattern = action_pattern
        self.completion_timeout = completion_timeout
        self.completion_interval = completion_interval
        self.connection_timeout = connection_timeout
        self.connection_interval = connection_interval
        self.inactivity_timeout = inactivity_timeout
        self.inactivity_interval = inactivity_interval
        self.monitor_delay = monitor_delay
        self.logging_pattern = logging_pattern
        self.retry_logging_interval = retry_logging_interval
        self.allowed_error_codes = tuple(allowed_error_codes)
        self.allowed_connection_exceptions = tuple(allowed_connection_exceptions)
        
        self.expected_status = expected_status
        self.user = user
        self.pty_params = pty_params

        self.freeze()
        return


DEFAULT_ASPECTS = Aspects()
DEFAULT_CMD_ASPECTS = AspectsCmd()


DEFAULT_SSH_ASPECTS = DEFAULT_CMD_ASPECTS

UNDER_CONSTRUCTION_SSH_ALLOWED_EXCEPTIONS = [ConnectionError, TimeoutError, Exception]
UNDER_CONSTRUCTION_SSH_CONNECTION_TIMEOUT = 60
UNDER_CONSTRUCTION_SSH_CONNECTION_INTERVAL = 5

UNDER_CONSTRUCTION_SSH_ASPECTS = AspectsCmd(
    connection_timeout=UNDER_CONSTRUCTION_SSH_CONNECTION_TIMEOUT,
    connection_interval=UNDER_CONSTRUCTION_SSH_CONNECTION_INTERVAL,
    allowed_connection_exceptions=UNDER_CONSTRUCTION_SSH_ALLOWED_EXCEPTIONS
)
