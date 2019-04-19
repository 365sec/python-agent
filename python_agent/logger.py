"""Extension to the Python logging module."""

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import time
import logging


# Custom log levels.
TRACE = logging.DEBUG - 1

py_level_to_libagent = {
    logging.CRITICAL: b'error',
    logging.ERROR: b'error',
    logging.WARNING: b'warn',
    logging.INFO: b'info',
    logging.DEBUG: b'debug',
    TRACE: b'trace',
}

class Logger(logging.Logger, object):
    """Logger that support our custom log levels, and level checks."""

    def __init__(self, name):
        super(Logger, self).__init__(name)
        self.reset()

    def isEnabledFor(self, level):
        """Override the logger checks to use the libagent check instead."""
        if not self._enabled_func:
            return True
        return self._enabled_func(py_level_to_libagent[level])

    def trace(self, msg, *args, **kwargs):
        if self.isEnabledFor(TRACE):
            self._log(TRACE, msg, args, **kwargs)

    def reset(self):
        self._enabled_func = None
        self._startup_handler = LoggerStartupHandler()
        self._libagent_setup = False

        for handler in self.handlers:
            self.removeHandler(handler)
        self.addHandler(self._startup_handler)
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        self.addHandler(console)

    def switch(self, enabled_func, log_func):
        if self._libagent_setup:
            # This could raise an exception if already setup, but the
            # tests create a lot of agents which results in this being
            # called multiple times
            return
        else:
            self._libagent_setup = True

        self._enabled_func = enabled_func

        self._libagent_handler = LoggerLibagentHandler(log_func)
        self._libagent_handler.setFormatter(LoggerFormatter())

        self.addHandler(self._libagent_handler)
        self.removeHandler(self._startup_handler)
        for record in self._startup_handler.records:
            if self.isEnabledFor(record.levelno):
                self._libagent_handler.handle(record)


class LoggerLibagentHandler(logging.Handler, object):
    """Send the log message out to libagent."""

    def __init__(self, log_func):
        super(LoggerLibagentHandler, self).__init__()
        self._log_func = log_func

    def emit(self, record):
        try:
            level = py_level_to_libagent[record.levelno]
            msg = self.format(record)
            self._log_func(level, msg)
        except Exception as e:
            try:
                self._log_func('error', "Error Logging: %s" %(e))
            except:
                # Silently drop the message, we tried:
                pass


class LoggerStartupHandler(logging.Handler, object):
    """Saves log records at startup.

    Before getting the log file and log level, we might want to log
    some messages. This handler saves those messages until we have a
    real handler.
    """

    def __init__(self):
        super(LoggerStartupHandler, self).__init__()
        self.records = []

    def emit(self, record):
        """See `Handler`."""
        self.records.append(record)


class LoggerFormatter(logging.Formatter, object):
    """Formatter encoding our preferred output format."""

    def __init__(self, fmt=None, datefmt=None):
        if fmt is None:
            fmt = ("%(asctime)s.%(msecs)03dZ "
                   "[%(process)d-%(thread)d-%(threadName)s] "
                   "%(name)s %(levelname)-7s: "
                   "%(message)s")
        if datefmt is None:
            datefmt = "%Y-%m-%dT%H:%M:%S"
        super(LoggerFormatter, self).__init__(fmt, datefmt)
        self.converter = time.gmtime  # Output should be UTC


# Logger instance to be used throughout python_agent code.
log = Logger("python_agent")
