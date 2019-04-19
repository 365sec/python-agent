from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

# Import functions to be exposed at the `python_agent.*` level
from immunio.singleton import (
    do_setup,
    start,  # Deprecated, use `do_setup` and `wrap_wsgi_app` instead.
    wrap_wsgi_app,
)
import immunio.api.auth
import immunio.api.extend


# Get package version
from ._version import get_versions
__version__ = get_versions()['version']
del get_versions


# Get location of CA Cert file
from pkg_resources import resource_filename
__ca_file__ = resource_filename(__name__, "immunio_ca.crt")
del resource_filename


__agent_name__ = "agent-python"
__vm_version__ = "2.2.0"


def report_failed_login_attempt(user_id=None, username=None, email=None,
                                reason=None):
    """
    DEPRECATED: Use `python_agent.api.auth.login_failure()` instead.
    Remove in 2.0.0
    """
    return immunio.api.auth.login_failure(user_id=user_id, username=username,
                                          email=email, reason=reason)


def report_custom_threat(threat_name, message, metadata=None):
    """
    DEPRECATED: Use `python_agent.api.extend.custom_threat()` instead.
    Remove in 2.0.0
    """
    return immunio.api.extend.custom_threat(threat_name, message, metadata)
