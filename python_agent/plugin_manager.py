from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from immunio.logger import log
from immunio.util import DummyContext
from immunio.plugins import FAILED, PENDING, LOADED, DISABLED
import immunio.plugins.plugin_django
import immunio.plugins.plugin_django_xss
import immunio.plugins.plugin_fileio
import immunio.plugins.plugin_flask
import immunio.plugins.plugin_jinja2
import immunio.plugins.plugin_mysqldb
import immunio.plugins.plugin_psycopg2
import immunio.plugins.plugin_pymssql
import immunio.plugins.plugin_pymysql
import immunio.plugins.plugin_pyramid
import immunio.plugins.plugin_pysqlite2
import immunio.plugins.plugin_shell
import immunio.plugins.plugin_sqlite3
import immunio.plugins.plugin_werkzeug

import immunio.plugins.plugin_listfile
import immunio.plugins.piugin_serialization



# Plugins listed here will be enabled by default. The final list can be
# adjusted by settings the `plugins_enabled` and `plugins_disabled` config
# settings.
DEFAULT_PLUGINS = [
   # Main Frameworks
    "django",
    "flask",
    "pyramid",
]

PROTECTION_PLUGINS = [
    # Core python
    "file_io",
    "shell",
    "listdir",
    "pickle",
    # Libraries
    "sqli_sqlite2",
    "sqli_sqlite3",
    "sqli_psycopg2",
    "sqli_mysqldb",
    "sqli_pymssql",
    "sqli_pymysql",
    "xss_jinja2",
    "xss_django",
    "werkzeug",
]


def build_active_plugins(config):
    """
    Build and return a `set()` of currently active plugin names based
    on the defaults above and any `plugins_enabled` or `plugins_disabled`
    values in the supplied config.
    """
    if not config.agent_enabled:
        return set()

    # start with the defaults enabled
    active = set(DEFAULT_PLUGINS)

    # Check is code protection is enabled
    if config.get("code_protection_plugins_enabled", False, datatype=bool):
        active |= set(PROTECTION_PLUGINS)

    # Add any specifically enabled
    manually_enabled = config.get("plugins_enabled", set(), datatype=set)
    active |= manually_enabled

    # And finally remove any specifically disabled. This ensures disabled
    # has priority over enabled.
    manually_disabled = config.get("plugins_disabled", set(), datatype=set)
    active -= manually_disabled

    return active


class PluginManager(object):
    """
    Manages all plugins.
    """
    def __init__(self, config, get_agent_func=None):
        self._hook_callback = None
        self._plugin_status_callback = None
        self._plugin_status_queue = []  # A queue of message to be sent.
        self.get_agent_func = get_agent_func

        # Build a set of currently enabled plugins
        # 构建一组当前启用的插件
        self.active_plugins = build_active_plugins(config)
        log.info("Active Plugins: %s", self.active_plugins)

        self.patch()

    @property
    def debug_mode(self):
        if self.get_agent_func:
            agent = self.get_agent_func(create_if_required=False)
            if agent:
                return agent.debug_mode
        return False

    def timer(self, report_name=None, exclude_from=None):
        # If there is no Agent created yet, don't run a timer
        if self.get_agent_func:
            agent = self.get_agent_func(create_if_required=False)
            if agent:
                return agent.timer(report_name, exclude_from)
        return DummyContext()

    def set_hook_callback(self, hook_callback):
        """
        Set the hook callback function to receive hook events from
        monkey-patched modules.

        It should only ever be set once so raise an Exception if it's
        already set.
        """
        if self._hook_callback:
            raise Exception("PluginManager hook_callback is already set")
        self._hook_callback = hook_callback

    def set_plugin_status_callback(self, callback):
        if self._plugin_status_callback:
            raise Exception("PluginManager plugin status hook already set")

        self._plugin_status_callback = callback

        # Send any queued messages:
        for args in self._plugin_status_queue:
            callback(*args)
        self._plugin_status_queue = []

    def set_plugin_status(self, name, status=None, meta=None):
        if self._plugin_status_callback:
            self._plugin_status_callback(name, status, meta)
        else:
            self._plugin_status_queue.append((name, status, meta))

    def patch(self):
        """
        Actually run all the plugins to monkeypatch the code.
        """
        # The order here is significant.
        # Patch low-level calls first
        self.register(immunio.plugins.plugin_fileio)
        self.register(immunio.plugins.plugin_shell)
        # Patch database drivers next since they are used by frameworks.
        self.register(immunio.plugins.plugin_sqlite3)
        self.register(immunio.plugins.plugin_pysqlite2)
        self.register(immunio.plugins.plugin_mysqldb)
        self.register(immunio.plugins.plugin_psycopg2)
        self.register(immunio.plugins.plugin_pymssql)
        self.register(immunio.plugins.plugin_pymysql)
        # Patch support libraries used by frameworks
        self.register(immunio.plugins.plugin_jinja2)
        self.register(immunio.plugins.plugin_django_xss)
        # Patch web frameworks next.
        self.register(immunio.plugins.plugin_django)
        self.register(immunio.plugins.plugin_flask)
        self.register(immunio.plugins.plugin_werkzeug)
        self.register(immunio.plugins.plugin_pyramid)
        self.register(immunio.plugins.plugin_listfile)
        self.register(immunio.plugins.piugin_serialization)

    def register(self, plugin_module):

        """
        Call the module to do the monkeypatching and give it a `run_hook`
        function to be used by the patched methods.
        """
        plugin_module_name = plugin_module.__name__

        meta = {
            "hooks": plugin_module.HOOKS_CALLED
        }

        # Only add plugins that are currently enabled.
        if plugin_module.NAME not in self.active_plugins:
            self.set_plugin_status(plugin_module.NAME, DISABLED, meta)
            return

        def run_hook(hook, meta):
            """
            Closure to add the name to the run_hook call.
            """
            return self._run_hook(plugin_module_name, hook, meta)

        # Actually do the monkeypatching
        try:
            # For hooks that don't immediately hook everything provide
            # a callback for them to update the status when they
            # consider themselves loaded.
            if getattr(plugin_module, "LATE_HOOK", False):
                self.set_plugin_status(plugin_module.NAME, PENDING, meta)
                # The plugin might set a status while running, so we set
                # pending first, then simply update the meta afterwards.
                meta.update(
                    plugin_module.add_hooks(run_hook,
                                            self.set_plugin_status,
                                            get_agent_func=self.get_agent_func,
                                            timer=self.timer)
                    or {})
                self.set_plugin_status(plugin_module.NAME, meta=meta)
            else:
                meta.update(
                    plugin_module.add_hooks(run_hook,
                                            get_agent_func=self.get_agent_func,
                                            timer=self.timer)
                    or {})
                if "version" in meta:
                    self.set_plugin_status(plugin_module.NAME, LOADED, meta)
        except:
            if self.debug_mode:
                raise
            self.set_plugin_status(plugin_module.NAME, FAILED, meta)


    def _run_hook(self, plugin_name, hook, meta):
        """
        Receives all hook calls from the monkeypatched code. If a callback
        is set, pass the data through.

        This function also enforces the guarantee that the `run_hook` function
        passed to plugins will always return a dict.
        """
        if not self._hook_callback:
            return {}

        result = self._hook_callback(plugin_name, hook, meta)
        if not isinstance(result, dict):
            log.warn("Code for hook `%(hook)s` returned non-dict result.", {
                "hook": hook,
            })
            return {}
        return result
