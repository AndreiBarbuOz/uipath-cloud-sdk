import json


class UiPathException(Exception):
    """
    Error handling in UiPathCloud is done with exceptions. All errors related to making API calls extend this.

    Some other types of exceptions might be raised by underlying libraries, for example for network-related issues.
    """
    pass


class BadInputException(UiPathException):
    """
    This exception is thrown when incorrect types/values are used
    """
    pass


class ApiError(UiPathException):
    """
    Errors due to malformed API call
    """

    def __init__(self, status, data):
        super().__init__()
        self.__status = status
        self.__data = data
        self.args = (status, data)

    @property
    def status(self):
        """
        The status returned by the UiPath API
        """
        return self.__status

    @property
    def data(self):
        """
        The (decoded) data returned by the UiPath API
        """
        return self.__data

    def __repr__(self):
        return f'UiPathException({self.status!r}, {self.data!r})'

    def __str__(self):
        return f"{self.status!s} {json.dumps(self.data)}"


class AuthError(UiPathException):
    """
    Errors due to invalid authentication credentials.
    """

    def __init__(self, error, msg):
        self.error = error
        self.msg = msg

    def __repr__(self):
        return f'AuthError({self.error!r})'


class InternalServerError(UiPathException):
    """Errors due to a problem on UiPath server."""

    def __init__(self, status_code, body):
        self.status_code = status_code
        self.body = body

    def __repr__(self):
        return f'InternalServerError({self.status_code!r}, {self.body!r})'


class RateLimitError(UiPathException):
    """Error caused by rate limiting."""

    def __init__(self, error=None, back_off=None):
        super().__init__(429, None)
        self.error = error
        self.back_off = back_off

    def __repr__(self):
        return f'RateLimitError({self.error!r}, {self.back_off!r})'
