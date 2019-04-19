from __future__ import (
    print_function
)
import os
import subprocess
import sys
import pickle

try:
    import popen2

    PATCH_POPEN2 = True
except ImportError:
    PATCH_POPEN2 = False

from functools import partial
from immunio.compat import string_types
from immunio.context import get_context
from immunio.logger import log
from immunio.patcher import monkeypatch

# Set plugin name so it can be enabled and disabled.
NAME = "pickle"
HOOKS_CALLED = ["serialization"]


def add_hooks(run_hook, get_agent_func=None, timer=None):
    """
    Add hooks for shell commands.
    """
    meta = {
        "version": ".".join(map(str, sys.version_info[:3])),  # Py version
    }

    hook_pickle_load(run_hook, timer)
    hook_pickle_loads(run_hook, timer)

    return meta


def hook_pickle_load(run_hook, timer):
    """
    Add our hook into os.system
    """

    # Replace the original 'os.system'
    @monkeypatch(pickle, 'load', timer=timer,
                 report_name="plugin.python.transformer.hook_transformer_load")
    def _our_os_system(orig_os_system, *args, **kwargs):
        log.debug("os.system(%(args)s, %(kwargs)s)", {
            "args": args,
            "kwargs": kwargs,
        })
        _, loose_context, stack = get_context()
        # print(args[0].readlines())
        # temp=args[0]
        # print(type(temp))
        # pickle.load(temp)

        # print(pickle.load(temp))
        run_hook("pickle_load", {
            # "method": "pickle.load",
            "clazz": args[:1],  # just send command
            # "information": kwargs,
            # "stack": stack,
            # "context_key": loose_context,
            # "cwd": os.getcwd()
        })
        return orig_os_system(*args, **kwargs)


def hook_pickle_loads(run_hook, timer):
    """
    Add our hook into os.system
    """

    # Replace the original 'os.system'
    @monkeypatch(pickle, 'loads', timer=timer,
                 report_name="plugin.python.transformer.hook_transformer_loads")
    def _our_os_system(orig_os_system, *args, **kwargs):
        log.debug("os.system(%(args)s, %(kwargs)s)", {
            "args": args,
            "kwargs": kwargs,
        })
        _, loose_context, stack = get_context()
        run_hook("pickle_loads", {
            # "method": "pickle.loads",
            "clazz": args[:1],  # just send command
            # "information": kwargs,
            # "stack": stack,
            # "context_key": loose_context,
            # "cwd": os.getcwd()
        })
        return orig_os_system(*args, **kwargs)
