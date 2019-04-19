from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from immunio.plugins.dbapi2_helper import wrap_connect


# Name plugin so it can be enabled and disabled.
NAME = "sqli_mysqldb"
HOOKS_CALLED = ["sql_connect", "sql_cursor", "sql_execute"]


def add_hooks(run_hook, get_agent_func=None, timer=None):
    """
    Add hooks to the MySQLdb.
    """
    try:
        import MySQLdb
    except ImportError:
        return None

    # The `pymysql` driver can emulate MySQLdb. If we detect it, don't patch
    # it again here
    if hasattr(MySQLdb, "install_as_MySQLdb"):
        return None

    meta = {
        "version": MySQLdb.__version__,
        "version_info": ".".join(map(str, MySQLdb.version_info)),
        "client_version": MySQLdb.get_client_info(),
    }

    # Wrap original connect function.
    wrapped_connect = wrap_connect(run_hook, get_agent_func, MySQLdb.connect,
                                   "mysql")

    # replace all references to connect
    MySQLdb.connect = wrapped_connect
    MySQLdb.Connect = wrapped_connect
    MySQLdb.Connection = wrapped_connect

    return meta
