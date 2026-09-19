class KoutenError(Exception):
    """Base class for sanitized KoutenDB transport errors."""


class ConnectionException(KoutenError):
    pass


class ConnectionTimeoutException(ConnectionException):
    pass


class AuthenticationException(KoutenError):
    pass


class ProtocolException(KoutenError):
    pass


class VersionMismatchException(ProtocolException):
    pass


class ServerException(KoutenError):
    pass


class IndeterminateWriteException(KoutenError):
    """The request may have committed. Do not automatically repeat it."""
