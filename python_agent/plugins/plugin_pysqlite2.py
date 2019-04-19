from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from immunio.plugins.dbapi2_helper import wrap_connect


# Name plugin so it can be enabled and disabled.
NAME = "sqli_sqlite2"
HOOKS_CALLED = ["sql_connect", "sql_cursor", "sql_execute"]


def add_hooks(run_hook, get_agent_func=None, timer=None):
    """
    Add hooks to the pysqlite2 library.
    """
    try:
        import pysqlite2.dbapi2
    except ImportError:
        return None

    meta = {
        "version": pysqlite2.dbapi2.version,
        "sqlite_version": pysqlite2.dbapi2.sqlite_version,
    }

    # wrap 'pysqlite2.dbapi2.connect' function
    wrapped_connect = wrap_connect(run_hook, get_agent_func,
                                   pysqlite2.dbapi2.connect,
                                   "sqlite3")

    # replace dbapi2 reference to connect
    pysqlite2.dbapi2.connect = wrapped_connect

    return meta
