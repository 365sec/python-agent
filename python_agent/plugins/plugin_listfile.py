from __future__ import (
    print_function
)
import os
import subprocess
import sys
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
NAME = "listdir"
HOOKS_CALLED = ["file_io"]


def add_hooks(run_hook, get_agent_func=None, timer=None):
    """
    Add hooks for shell commands.
    """
    meta = {
        "version": ".".join(map(str, sys.version_info[:3])),  # Py version
    }

    hook_os_listdir(run_hook, timer)

    return meta

def hook_os_listdir(run_hook, timer):
    """
    Add our hook into os.system
    """
    # Replace the original 'os.system'
    @monkeypatch(os, 'listdir', timer=timer,
                 report_name="plugin.python.filelist.os_listdir")
    def _our_os_system(orig_os_system, *args, **kwargs):
        log.debug("os.system(%(args)s, %(kwargs)s)", {
            "args": args,
            "kwargs": kwargs,
        })
        _, loose_context, stack = get_context()
        run_hook("os_listdir", {
            # "method": "os.listdir",
            "path": args[:1], # just send command
            # "information": kwargs,
            # "stack": stack,
            "context_key": loose_context,
            "realpath": os.path.realpath(args[0])
        })
        return orig_os_system(*args, **kwargs)



