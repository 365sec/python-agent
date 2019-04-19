from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from collections import defaultdict
import datetime
import platform
import uuid
import socket

from immunio import wsgi
from immunio.exceptions import (
    ImmunioBlockedError,
    ImmunioOverrideResponse,
)
from immunio.logger import log
from immunio.deps.python_ifcfg import ifcfg
from immunio.util import DummyContext
from immunio.libagent import LibAgent

##############################################################################
# Import the module-level helper methods from `python_agent` to maintain the legacy
# `python_agent.agent` namespace calls.
from immunio import (  # pylint: disable=unused-import
    report_custom_threat,
    report_failed_login_attempt,
    start,
)


from threading import local


DEFAULT_ENGINE = "SimpleEngine"
DEFAULT_REQUEST_UUID_HEADER = "x-request-uuid"

# Logging defaults.
DEFAULT_LOG_FILE = "log/python_agent.log"
DEFAULT_LOG_LEVEL = "info"


def collect_environment():
    """
    Collect information about the Agent environment. This is static data that
    should not change during one run.
    """
    try:
        import pip
        installed = pip.get_installed_distributions()
        packages = dict((x.project_name, x.version) for x in installed)
    except (ImportError, AttributeError):
        packages = None

    hostname = socket.gethostname()
    try:
        # This may fail if hostname is not mapped to an IP by the system.
        hostname_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        hostname_ip = None

    try:
        ips = set()
        for _, iface in ifcfg.interfaces().items():
            if iface['inet'] not in ['127.0.0.1', None]:
                ips.add(iface['inet'])

        ips = list(ips)
    except Exception:
        ips = []

    return {
        "platform": {
            "description": platform.platform(),
        },
        "host": {
            "hostname": hostname,
            "hostname_ip": hostname_ip,
            "ips": ips,
        },
        "runtime": {
            "name": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "language": {
            "name": "python",
        },
        "dependencies": packages,
    }

class AgentRequestStoreContext():
    def __init__(self, store, key, value):
        try:
            self.original_value = store[key]
            self.existed = True
        except KeyError:
            self.existed = False
        self.store = store
        self.key = key

        store[key] = value

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.existed:
            self.store[self.key] = self.original_value
        else:
            try:
                del self.store[self.key]
            except KeyError:
                log.warn("Request Store attempted to delete missing key %s",
                         self.key)


class Agent(object):
    """
    Manages all aspects of Immunio on a target webserver. There should only
    be a single instance of this class for each webserver process.
    """

    MAX_MESSAGES_PER_WORK = 5

    def __init__(self, config, plugin_manager):
        self._config = config

        self.environment = collect_environment()

        # Flag to indicate if we have received and processed all initial rules
        # from the Immunio servers.
        self.ready = False

        # Create thread-local storage for maintaining the active request_id
        # We don't currently support fully multithreaded servers but we do need
        # this for gevent-based servers since more than one request will be
        # active at a given time.
        self._local = local()
        self._local.request = None
        self._local.request_features_enabled = None
        self._local.request_properties = {}

        # The name of the header to add to each response with the request_uuid.
        self._request_uuid_header = self._config.get(
            "request_uuid_header", DEFAULT_REQUEST_UUID_HEADER, datatype=str)

        # Track the hook timings for each request
        self._request_timings = defaultdict(dict)

        self._agent = LibAgent(self._config)

        # Switch to the real logger now that libagent is loaded.
        log.switch(self._agent.is_log_enabled, self._agent.log)

        # Set the callback functions for plugin hooks
        plugin_manager.set_hook_callback(self.run_hook)
        plugin_manager.set_plugin_status_callback(self.plugin_status)

    @property
    def enabled(self):
        """
        Check if the Agent is enabled or not.
        """
        return True
        return self._agent.enabled

    @property
    def debug_mode(self):
        return self._agent.debug_mode

    def get_request_uuid_header(self):
        return self._request_uuid_header

    def start(self):
        """
        Start the agent.
        """

    def wrap_wsgi_app(self, app):
        """
        Wrap a WSGI app with the Agent. If agent is disabled, just return
        the original app.
        """
        # Don't wrap again if we've already wrapped once.
        if isinstance(app, wsgi.WsgiWrapper):
            log.warn("The WSGI app callable has already been wrapped by "
                     "Immunio. Immunio will operate normally, but you can "
                     "remove the explict call to `agent.wrap_wsgi_app()`. "
                     "Please contact support@immun.io for more information.")
            return app

        if self.enabled:
            # wsgi isn't a true plugin, but it's status is needed for the
            # backend.
            #
            # TODO: It might make sense for wsgi to become a plugin after the
            # py3k and libagent changes. For now hard-code the hooks/status
            self.plugin_status("wsgi", "loaded", {"hooks": wsgi.HOOKS_CALLED})
            self.plugin_status("engine", "loaded",
                    {"hooks": ["http_request_finish", "should_report"]})
            return wsgi.WsgiWrapper(self, app, self._request_uuid_header)
        else:
            # If we're not enabled then there's no libagent to send
            # status updates.
            return app

    def gen_request_id(self):
        return str(uuid.uuid1())

    def timestamp(self):
        """
        Create a timestamp string. Append a 'Z' so it's clear that all
        timestamps are UTC.
        """
        return datetime.datetime.utcnow().isoformat() + "Z"

    def http_new_request(self):
        # Generate new ID
        if self.get_request() is not None:
            raise Exception(
                "New request starting before previous request (id=%s) complete."
                % self._local.request.request_id)
        request_id = self.gen_request_id()

        # Create a new property store
        try:
            if self._local.request_properties:
                log.warn("New request with existing properties, clearing")
        except AttributeError:
            pass  # No request_properties is expected
        self._local.request_properties = {}

        # Clear any existing enabled features
        self._local.request_features_enabled = None

        self._local.request = self._agent.new_request(request_id)
        return self._local.request

    def http_request_finish(self, request=None):
        # If request_id is not provided, try to find it
        if request is None:
            request = self.get_request()
        request_id = request.request_id
        log.debug("Agent.http_request_finish for request_id=%s", request_id)

        #self.run_hook("request", "http_request_finish", {}, request)
        request.finish()

        # Done with this request_id, clear it to help detect failures
        self._local.request = None
        self._local.request_features_enabled = None
        self._local.request_properties = {}

    def add_timing(self, name, duration_ms):
        """
        Add a single time duration for the current request. The name must
        have at least two parts, separated by a dot (`.`) like `request.total`
        or `plugin.xss.render_template_done` or `hook.http_request_start`.
        """
        request = self.get_request()
        if not request:
            return
        request_id = request.request_id

        # The first dotted element is the category (hook, plugin, request)
        category, name = name.split(".", 1)

        timings = (self._request_timings[request_id]
                   .setdefault(category, {})
                   .setdefault(name, {}))
        timings.setdefault("count", 0)
        timings["count"] += 1
        timings.setdefault("total_duration", 0.0)
        timings["total_duration"] += duration_ms

    def run_hook(self, plugin, hook, meta, request=None):
        """
        Send the hook data into the Engine. If the Engine is not enabled,
        do nothing.
        """
        # If the Agent is not enabled, return an empty `dict` and no-op
        # if not self.enabled:
        #     return {}

        # If request_id is not provided, try to find it
        if request is None:
            request = self.get_request()

        if request is None:
            log.warn("run_hook with no request: %s %s %s", plugin, hook, meta)
            return

        result = request.run_hook(plugin, hook, meta)
        log.debug("Result from hook: %(result)r", {
            "result": result,
            })

        # Check if request should be blocked
        if not result.get("allow", True):
            # request should be blocked
            raise ImmunioBlockedError()

        # Check if response should be overridden
        if result.get("override_status") or result.get("override_body"):
            raise ImmunioOverrideResponse(
                int(result.get("override_status", 200)),
                [list(x) for x in result.get("override_headers", [])],
                result.get("override_body", ""),
            )

        # TODO This should return `result`, but there's no way currently to
        # convert `result` directly to a python dict. For now, let's not leak
        # the libAgent table class around until we need to.
        return {}

    def plugin_status(self, name, status=None, meta=None):
        """ Add the status message to the environment."""
        if meta is None:
            meta = {}

        self._agent.report_plugin(name, meta.get("hooks", []), status)

    def timer(self, report_name=None, exclude_from=None):
        request = self.get_request()
        if request:
            if not report_name:
                raise ValueError("`report_name` can't be %r" % (report_name,))
            category, name = report_name.split(".", 1)
            return request.timer(category, name)
        return DummyContext()

    def get_request(self):

        """
        Find the current request from thread-local storage. This is
        primarily to support gevent-based servers. We don't support fully
        threaded servers yet.
        This will require some work to make it safe for use in async code
        like tornado or twisted.
        """
        # Default to None if request is not set for this thread.

        return getattr(self._local, "request", None)

    def get_request_id(self):

        request = self.get_request()

        return request.request_id if request else None

    def property_set(self, key, value):
        return AgentRequestStoreContext(self._local.request_properties, key,
                                        value)

    def property_get(self, key, default=None):
        return self._local.request_properties.get(key, default)

    def is_feature_enabled(self, feature_name):
        # If the agent is disabled, no features are enabled
        if not self.enabled:
            return False

        # If there's no active request, no features are enabled
        if self.get_request() is None:
            return False

        # If we haven't loaded features for this request, do it now
        if self._local.request_features_enabled is None:
            result = self._local.request.run_hook("agent", "features_enabled",{})
            self._local.request_features_enabled = set(
                    [feature.decode('ascii') for feature in
                        result.get("enabled", [])])

        # Check if feature is enabled
        enabled = feature_name in self._local.request_features_enabled
        return enabled
