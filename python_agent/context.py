"""
Utility functions to calculate context hashes and a stack trace.
"""

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import os
import sys
import hashlib

from python_agent.compat import to_bytes
from python_agent.logger import log
from python_agent.deps import cachetools


THIS_DIR = os.path.dirname(__file__)


def get_stack(limit=None):
    """
    Returns the current call stack.

    Based on CPython traceback.py & inspect.py but without the I/O operations
    to read the line of code.

    As each frame is made up of the filename, lineno, and name, it's possible
    that dynamically created methods will have the same stack, even if they
    are not the same instance of a method. For example:

    def a():
        def b():
            <stacktrace>
        b()

    Each `b` will be different. In typical cases they behave the same, so the
    same stack is not an issue.

    The decorator library internally keeps track of a `_compile_count` and will
    use this to generate a unique filename for each method. So for example:

    @decorator
    def call(f, *args, **kwargs):
        return f(*args, **kwargs)

    def a():
        @call
        def b():
            <stacktrace>
        b()

    Will generate a stacktrace with `<decorator-gen-##>` in it.

    Because the numbers will change with every call we filter them
    down to just `<decorator-gen>`.

    """
    f = sys._getframe(1)
    if limit is None:
        if hasattr(sys, 'tracebacklimit'):
            limit = sys.tracebacklimit
    stack = []
    n = 0

    decorator_prefix = '<decorator-gen-'
    decorator_prefix_len = len(decorator_prefix)
    while f is not None and (limit is None or n < limit):
        lineno = f.f_lineno
        co = f.f_code
        filename = co.co_filename
        # Run often, so slice instead of .startswith()
        if filename[:decorator_prefix_len] == decorator_prefix:
            filename = "<decorator-gen>"
        name = co.co_name
        stack.append((filename, lineno, name))
        f = f.f_back
        n = n + 1
    # Return as a tuple so it is hashable for caching.
    return tuple(stack)


def get_context(additional_data=None, log_context_data=False, offset=0):
    """
    Gets the stack contexts and stack strings for the current callstack.

    @param additional_data: An optional string of extra data to hash into
                            the strict context. Allows one callstack to be
                            further subdivided. Used to add additional context
                            from ORMs.
    @param log_context_data: Set to true to enable logging all the stacks.
    @param offset: Offset to apply to the first line number in the stack.
                   Primarily used in unit tests to generated expected stacks
                   for previous lines of code.
    """
    strict_context, loose_context, stack = _build_context(
        get_stack(),
        log_context_data,
        offset,
    )

    # Mix in additional context data
    if additional_data:
        additional_data = to_bytes(additional_data, "utf8")
        strict_context = to_bytes(strict_context, "utf8")
        if log_context_data:
            log.info("Additional context data:\n%s", additional_data)

        strict_context = hashlib.sha1(
            strict_context + additional_data).hexdigest()

    return strict_context, loose_context, stack


def _is_python_agent_frame(frame):
    """
    Check if this frame is from the python_agent agent. We do the quick path
    test here to exclude most customer files so they don't fill up the
    LFU cache on `_is_python_agent_agent_file()` below.
    """
    if "/python_agent/" not in frame[0]:
        return False
    return _is_python_agent_agent_file(frame[0])


@cachetools.func.lfu_cache(maxsize=100)
def _is_python_agent_agent_file(filename):
    """
    Check if the given file is part of the python_agent agent. Cache the result
    to avoid frequent filesystem operations for `os.path.exists()`.

    This function is split from `_is_python_agent_frame()` above to allow use of
    the cache decorator.
    """
    path_part = filename.split("/python_agent/")[-1]
    path = os.path.join(THIS_DIR, path_part)
    return os.path.exists(path)


@cachetools.func.lfu_cache(maxsize=500)
def _build_context(stack, log_context_data, offset):
    """
    Builds contexts and stack strings from a raw stack generated by
    `get_stack()` above.

    The LFU cache decorator caches the expensive operations below. The
    `maxsize` value is chosen to be large enough to catch the most used
    contexts, but not so large to exhaust too much memory in the server.
    """

    # Use ropes as they're faster than string concatenation
    loose_context_rope = []
    stack_rope = []
    strict_context_rope = []

    for frame in stack:
        # Stop processing once we reach the wsgi:handle_request call:
        if "/python_agent/wsgi" in frame[0] and frame[2] == "handle_request":
            break

        # Skip any python_agent frames
        if _is_python_agent_frame(frame):
            continue

        # Unpack frame
        filename, lineno, name = frame

        # Change the lineno of the first frame by offset; useful in unit tests.
        if len(stack_rope) == 0:
            lineno += offset

        # Reduce paths to just use the filename part.
        strict_path = os.path.basename(filename)

        stack_rope.append("%s:%d:%s" % (filename, lineno, name))
        strict_context_rope.append("%s:%d:%s" % (strict_path, lineno, name))

        # Remove pathname from the loose context. The goal here
        # is to prevent upgrading package versions from changing the
        # loose context key, so for instance users don't have to
        # rebuild their whitelists every time they update a package.
        loose_context_rope.append("%s:%s" % (strict_path, name))

    stack = "\n".join(stack_rope)
    strict_context_stack = "\n".join(strict_context_rope)

    if log_context_data:
        log.info("Strict context stack:\n%s", strict_context_stack)

    strict_context = hashlib.sha1(
            strict_context_stack.encode('utf8')).hexdigest()
    loose_context = hashlib.sha1(
            "\n".join(loose_context_rope).encode('utf8')).hexdigest()

    return strict_context, loose_context, stack
