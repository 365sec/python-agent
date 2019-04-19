from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)


class ImmunioBlockedError(BaseException):
    """
    Raised by wsgi wrapper code when the request should be blocked. This is
    caught by the wsgi wrapper higher up the stack where it has more context
    to block the request properly.

    NOTE: We extend BaseException here to reduce the risk of being caught by
          a catch-all in customer code.
    """


class ImmunioOverrideResponse(BaseException):
    """
    Raised by the agent to override the normal response for this request
    replace it with a new response instead.

    NOTE: We extend BaseException here to reduce the risk of being caught by
          a catch-all in customer code.
    """


class UnknownEngineError(Exception):
    """
    The Agent configuration has requested an unknown Engine class in
    its configuration.
    """


class ConfigError(Exception):
    """
    The Agent tried to load a configuration file but found an error.
    """
