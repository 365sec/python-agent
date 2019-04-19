from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import sys

is_py2 = (sys.version_info[0] == 2)
string_types = (str, u"".__class__)

if is_py2:
    to_unicode = unicode  # pylint: disable=undefined-variable
    integer_types = (int, long)  # pylint: disable=undefined-variable

    def get_func_defaults(target):
        return target.func_defaults

    def set_func_defaults(target, value):
        target.func_defaults = value

    def to_bytes(value, encoding):
        if isinstance(value, unicode):  # pylint: disable=undefined-variable
            return value.encode(encoding)
        return value

else:
    to_unicode = str
    integer_types = (int,)

    def get_func_defaults(target):
        return target.__defaults__

    def set_func_defaults(target, value):
        target.__defaults__ = value

    def to_bytes(value, encoding):
        if isinstance(value, str):
            return value.encode(encoding)
        return value


def to_native_string(value, encoding):
    """Convert bytes from Lua to "Native" strings, which wsgi likes.

    In Python 3 these are 'str' and not 'bytes'.

    In Python 2 these are 'str' and not 'unicode'"""
    assert isinstance(value, bytes), repr(value)
    return str(value.decode(encoding))


def get_iteritems(d):
    return getattr(d, 'iteritems', getattr(d, 'items'))


def get_builtins():
    try:
        import builtins
        return builtins
    except ImportError:
        import __builtin__
        return __builtin__
