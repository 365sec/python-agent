from __future__ import absolute_import

from abc import abstractmethod

# Try to use the stdlib if available, use backport if not.
try:
    # `OrderedDict` is only present in python 2.7 and later. Use this
    # to detect python 2.6 and use the backported module below.
    from collections import OrderedDict
    import collections
except ImportError:
    from . import backport_collections as collections


class DefaultMapping(collections.MutableMapping):

    __slots__ = ()

    @abstractmethod
    def __contains__(self, key):  # pragma: nocover
        return False

    @abstractmethod
    def __getitem__(self, key):  # pragma: nocover
        if hasattr(self.__class__, '__missing__'):
            return self.__class__.__missing__(self, key)
        else:
            raise KeyError(key)

    def get(self, key, default=None):
        if key in self:
            return self[key]
        else:
            return default

    __marker = object()

    def pop(self, key, default=__marker):
        if key in self:
            value = self[key]
            del self[key]
        elif default is self.__marker:
            raise KeyError(key)
        else:
            value = default
        return value

    def setdefault(self, key, default=None):
        if key in self:
            value = self[key]
        else:
            self[key] = value = default
        return value

DefaultMapping.register(dict)
