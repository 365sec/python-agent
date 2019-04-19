"""Utility module."""

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import os
import errno


def mkdir_p(path):
    """
    Ensure a directory exists.
    """
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno != errno.EEXIST or not os.path.isdir(path):
            raise


class DummyContext(object):
    """
    No-op context manager.
    """
    def __call__(self, *args, **kwargs):
        return self

    def __enter__(self, *args, **kwargs):
        pass

    def __exit__(self, exc_type, exc_value, traceback):
        pass
