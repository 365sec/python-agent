from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from immunio.logger import log


NAME = "werkzeug"
HOOKS_CALLED = [
    "framework_input_params",
]


def add_hooks(run_hook, get_agent_func=None, timer=None):
    """
    Add our hooks into the flask library functions.
    """
    meta = {}

    try:
        import werkzeug
    except ImportError:
        return None

    meta["version"] = werkzeug.__version__

    # Install a hook to capture the BaseRequest params
    hook_werkzeug_input_params(run_hook, get_agent_func, timer)

    return meta


def hook_werkzeug_input_params(run_hook, get_agent_func, timer):
    """
    Wrap the `BaseRequest` methods that access values from request
    forms and query parameters. The `values()` call will call the
    two other properties (args/form) and combine them.
    """

    from werkzeug.wrappers import BaseRequest
    from werkzeug.utils import cached_property

    if not (isinstance(BaseRequest.args, cached_property) and
            isinstance(BaseRequest.form, cached_property)):
        log.warn("Werkzeug BaseRequest values not cached_properties")
        raise Exception("BaseRequest values must be cached_properties")


    # TODO: No hook timing
    class wrapped_property(object):
        """A proxy to the werkzeug properties. This is specifically made to
        proxy a property that is wrapped with cached_property, as the
        side-effect of that wrap is used so we only call the callback during
        the first call"""
        def __init__(self, orig):
            self.orig = orig
            self.__name__ = getattr(orig, "__name__", None)
            self.__module__ = getattr(orig, "__module__", None)
            self.__doc__ = getattr(orig, "__doc__", None)

        def __get__(self, obj, objtype=None):
            if obj is None:
                return self

            # The cached_property decorator stores the value
            # in the obj.__dict__. The descriptor is still called
            # though as it has a __get__/__set__. We can use the same
            # to only run the hook on the first call:
            first_call = self.__name__ not in obj.__dict__
            value = self.orig.__get__(obj, objtype)
            if first_call:
                # Standard ImmutableMultiDict can be converted to a list-y dict:
                try:
                    params = value.to_dict(flat=False)
                except AttributeError:
                    params = dict([(x, [y]) for x, y in value.items()])
                run_hook("framework_input_params", {
                    "params": params
                })
            return value

        def __set__(self, obj, value):
            return self.orig.__set__(obj, value)

        def __delete__(self, obj):
            return self.orig.__delete(obj)

        def getter(self, fget):
            return self.orig.getter(fget)

        def setter(self, fset):
            return self.orig.setter(fset)

        def deleter(self, fdel):
            return self.orig.deleter(fdel)

    BaseRequest.args = wrapped_property(BaseRequest.args)
    BaseRequest.form = wrapped_property(BaseRequest.form)
