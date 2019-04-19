from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from immunio.plugins.dbapi2_helper import wrap_connect


# Name plugin so it can be enabled and disabled.
NAME = "sqli_pymysql"
HOOKS_CALLED = ["sql_connect", "sql_cursor", "sql_execute"]


def add_hooks(run_hook, get_agent_func=None, timer=None):
    """
    Add hooks to the PyMySQL driver.
    """
    try:
        import pymysql
    except ImportError:
        return None

    meta = {
        "version": pymysql.__version__,
    }

    # Wrap original connect function.
    wrapped_connect = wrap_connect(run_hook, get_agent_func, pymysql.connect,
                                   "mysql")

    # replace all references to connect
    pymysql.connect = wrapped_connect
    pymysql.Connect = wrapped_connect
    pymysql.Connection = wrapped_connect

    return meta
