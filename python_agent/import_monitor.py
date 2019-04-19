from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import sys

from immunio.compat import get_builtins

class ImportMonitor(object):
    """
    Hooks the import function and collects information about
    all libraries in use.
    """
    def __init__(self, agent):
        self._agent = agent
        self._import_path = []

    def start(self):
        """
        Replace the global python __import__() function with the one in this
        class.
        """
        # Replace the global __import__ with our own version
        builtin_module = get_builtins()
        self._original_import = builtin_module.__import__
        builtin_module.__import__ = self._import_hook

    def stop(self):
        """
        Recover the original the global python __import__() function.
        """
        # Replace the global __import__ with our own version
        builtin_module = get_builtins()
        builtin_module.__import__ = self._original_import

    def _import_hook(self, name, _globals=None, _locals=None, fromlist=None,
                     level=-1):
        """
        Internal replacement for the global __import__ function. Calls the
        saved orignal __import__ function and reports the arguments and result.
        """
        if fromlist is None:
            fromlist = []

        self._import_start(name, fromlist)

        # Keep track of what is importing what
        self._import_path.append(name)

        # Pass through to the original __import__ function.
        try:
            module = self._original_import(name, _globals, _locals, fromlist,
                                           level)
        finally:
            # Remove from list even on ImportError
            self._import_path.pop()

        self._import_complete(name, module, fromlist)

        return module

    def _import_start(self, name, fromlist):
        pass

    def _import_complete(self, name, module, fromlist):
        # get filename if present
        try:
            filename = module.__file__
        except AttributeError:
            filename = None

        self._agent.run_hook("import", "import", {
            "name": name,
            "fromlist": fromlist,
            "path": self._import_path,
            "file": filename,
            "version": self._find_version(name),
        })

    def _find_version(self, name):
        """
        Try to find a version number for the given module name.
        The module must be finished loading before calling this function.
        """
        # Common attributes to hold a version number
        VERSION_ATTRS = ["__version__", "version", "VERSION"]

        # Try each module up the hierarchy
        #  - django.db.models
        #  - django.db
        #  - django
        parts = name.split(".")
        while parts:
            # Get module name at this level
            mod_name = ".".join(parts)
            parts.pop()
            # Get module
            mod = sys.modules.get(mod_name)
            if not mod:
                continue

            # Look in common places for a version
            for attr in VERSION_ATTRS:
                if hasattr(mod, attr):
                    source = "%s.%s" % (mod_name, attr)
                    return source, getattr(mod, attr)

        # No version found
        return None
