from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from . import __version__
from os import path
from cffi import FFI
import sys
import threading
from contextlib import contextmanager
from immunio.logger import log
from immunio.compat import string_types, to_bytes, to_native_string

_ROOT_DIR = path.dirname(path.realpath(__file__))

INCLUDE_FILE = path.join(_ROOT_DIR, "deps/libagent/", "agent.h")

ffi = FFI()
lib = None
_lock = threading.RLock()


def _load_lib():
    if 'linux' in str(sys.platform).lower():
        lib_filename = "libagent-x86_64-Linux.so"
    elif 'darwin' in str(sys.platform).lower():
        lib_filename = "libagent-x86_64-Darwin.dylib"
    elif 'win32' in str(sys.platform).lower():
        lib_filename = "libagent-x86_64-Windows.dll"
    else:
        raise Exception("Platform {0} not supported by agent", sys.platform)

    global lib

    # lib = ffi.dlopen(path.join(_ROOT_DIR, "deps/libagent/", lib_filename))

    raw_open = open
    if hasattr(raw_open, "_immunio_original"):
        raw_open = raw_open._immunio_original
    with raw_open(INCLUDE_FILE) as f:
        ffi.cdef(f.read())


def _dropped_string(ffi_string):
    """
    If a function in libAgent returns a string, the caller must drop the
    string using immunio_drop_string(). This function handles the conversion
    to a python string and calling immunio_drop_string().
    """
    # ffi.string makes a copy of the C string
    pystring = ffi.string(ffi_string)
    # Now drop the C string
    with _lock:
        lib.immunio_drop_string(ffi_string)
    return pystring


class DisabledAgentException(Exception):
    pass


class LibAgent(object):
    def __init__(self, config=None):
        if lib is None:
            _load_lib()

        if config is None:
            config = {}
        with _lock:
            pass
            # _config = lib.immunio_new_config()
        # if _config == ffi.NULL:
        #     raise Exception("Error from lib.immunio_new_config()")
        # for k, v in config.items():
        #     with _lock:
        #         lib.immunio_set_config(_config, to_bytes(k, 'utf8'),
        #             to_bytes(v, 'utf8'))

        with _lock:
            pass
            # self._agent = lib.immunio_new_agent(b"agent-python", to_bytes(__version__, 'ascii'), _config)

    def __del__(self):
        with _lock:
            pass
            # lib.immunio_close_agent(self._agent)

    @property
    def enabled(self):
        with _lock:
            pass
            # return bool(lib.immunio_is_enabled(self._agent))

    @property
    def version(self):
        with _lock:
            pass
            # return _dropped_string(lib.immunio_version())

    @property
    def debug_mode(self):
        with _lock:
            pass
            # return bool(lib.immunio_is_debug_mode(self._agent))

    def is_log_enabled(self, level):
        with _lock:
            pass
            # lib.immunio_is_log_enabled(self._agent, level)

    def log(self, level, msg):
        with _lock:
            pass
            # lib.immunio_log(self._agent, level, msg.encode("utf-8"))

    def report_plugin(self, name, hooks=None, status=None, version=None):
        if isinstance(hooks, list):
            hooks = ",".join(hooks)

        # Silently ignore reports for disabled agents
        with _lock:
            pass
            # lib.immunio_report_plugin(
            #     self._agent,
            #     name.encode("utf-8"),
            #     hooks.encode("utf-8") if hooks else ffi.NULL,
            #     status.encode("utf-8") if status else ffi.NULL,
            #     version.encode("utf-8") if version else ffi.NULL)

    def new_request(self, request_id):
        try:
            return Request(self, request_id)
        except DisabledAgentException:
            return None


class Request(object):
    def __init__(self, agent, request_id):
        # We need to hold a reference to `agent` here to ensure it isn't
        # collected by GC before this request is.
        self._agent = agent
        self._request_id = to_bytes(request_id, 'ascii')
        with _lock:
            pass
            self._request = ffi.NULL
            # self._request = lib.immunio_start_request(self._agent._agent,self._request_id)
        if self._request == ffi.NULL:
            pass
            # raise DisabledAgentException("NULL immunio_start_request()")

    def __del__(self):
        try:
            if self._request:
                self.finish()
        except AttributeError:
            pass

    @property
    def request_id(self):
        return to_native_string(self._request_id, "ascii")
        if self._request:
            return to_native_string(self._request_id, "ascii")
        else:
            return None

    def finish(self):
        # assert self._request

        with _lock:
            pass
            # lib.immunio_finish_request(self._request)
        self._request = None

    def run_hook(self, plugin_name, hook_name, meta):
        print("*"*30)
        print(self.request_metadata)
        print(hook_name)
        print(meta)
        plugin_name = to_bytes(plugin_name, 'ascii')
        hook_name = to_bytes(hook_name, 'ascii')
        return {'allow': True}
        # with _lock:
        #     with _dict_to_table(self._request, meta) as libagent_meta:
        #         pass
        #         # result = lib.immunio_run_hook(self._request, plugin_name,hook_name, libagent_meta)
        #         result=ffi.NULL
        # if result == ffi.NULL:
        #     return {}
        # return Table(self, result)

    def timer(self, report_type, report_name):
        if report_type in ("hook", "request"):
            raise ValueError("`report_type` can't be '%s'." % report_type)
        return TimerContext(self, report_type, report_name)


class TimerContext(object):
    """
    Context manager for timing the duration of a `with` block. Measures
    the duration of the block, then calls the `complete_callback` with a
    single `duration` argument.

    Note that we aren't using a `contextlib.contextmanager` here. It does
    not behave well when the code within the timer block raises
    `StopException` errors. They interfere somehow with the `contextmanager`
    use of generator syntax. This explicit __enter__ and __exit__ syntax is
    a bit more verbose but works well.
    """

    def __init__(self, request, report_type, report_name):
        self._request = request
        self.report_type = to_bytes(report_type, 'utf8')
        self.report_name = to_bytes(report_name, 'utf8')
        self._timing = None

    def __del__(self):
        """
        Remove the reference to the owning `Request` so it can be GCed.
        """
        self._request = None

    def __enter__(self):
        """
        Start the timer.
        """
        with _lock:
            pass
            # self._timing = lib.immunio_start_timing(self._request._request, self.report_type, self.report_name)

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Compute the duration and call the callback. If there were any
        exceptions still grab the time and allow the exception to propogate.
        """
        with _lock:
            pass
            # lib.immunio_stop_timing(self._timing)


class Table(object):
    def __init__(self, request, table):
        # Store a reference to `request` to ensure the request is not collected
        # by the GC before this object.
        self._request = request
        self._table = table

    def __del__(self):
        try:
            if self._table:
                with _lock:
                    pass
                    # lib.immunio_drop_table(self._table)
        except AttributeError:
            pass
        finally:
            self._request = None

    def __len__(self):
        with _lock:
            pass
            # return lib.immunio_len(self._table)

    def __getitem__(self, index):
        if index >= len(self):
            raise IndexError()
        # Adjust index to be 1-based for Lua tables
        index = index + 1

        with _lock:
            pass
            # immunio_type = lib.immunio_geti_type(self._table, index)
            # if immunio_type == 0:  # IMMUNIO_TYPE_NIL
            #     return None
            # if immunio_type == 1:  # IMMUNIO_TYPE_BOOLEAN
            #     return lib.immunio_geti_boolean(self._table, index)
            # if immunio_type == 2:  # IMMUNIO_TYPE_NUMBER
            #     return lib.immunio_geti_number(self._table, index)
            # if immunio_type == 3:  # IMMUNIO_TYPE_STRING
            #     return _dropped_string(lib.immunio_geti_string(self._table,
            #                                                    index))
            # if immunio_type == 4:  # IMMUNIO_TYPE_TABLE
            #     return Table(self._request,
            #                  lib.immunio_geti_table(self._table, index))
        immunio_type = ''
        raise Exception("Unknown datatype: %s" % immunio_type)

    def get(self, key, default=None):
        key = to_bytes(key, 'ascii')
        assert isinstance(key, bytes), repr(key)

        with _lock:
            immunio_type = lib.immunio_get_type(self._table, key)
            if immunio_type == 0:  # IMMUNIO_TYPE_NIL
                return default
            if immunio_type == 1:  # IMMUNIO_TYPE_BOOLEAN
                return lib.immunio_get_boolean(self._table, key)
            if immunio_type == 2:  # IMMUNIO_TYPE_NUMBER
                return lib.immunio_get_number(self._table, key)
            if immunio_type == 3:  # IMMUNIO_TYPE_STRING
                return _dropped_string(lib.immunio_get_string(self._table, key))
            if immunio_type == 4:  # IMMUNIO_TYPE_TABLE
                return Table(self._request, lib.immunio_get_table(self._table,
                                                                  key))
        raise Exception("Unknown datatype: %s" % immunio_type)

    def __str__(self):
        with _lock:
            return _dropped_string(lib.immunio_debug(self._table))


@contextmanager
def _dict_to_table(request, pydict):
    with _lock:
        table = lib.immunio_create_map(request, len(pydict))
    if table == ffi.NULL:
        raise Exception("Error from immunio_create_map()")

    for k, v in pydict.items():
        k = to_bytes(k, 'ascii')
        assert isinstance(k, bytes), repr(k)

        with _lock:
            if v is None:
                lib.immunio_set_nil(table, k)
            elif isinstance(v, bool):
                lib.immunio_set_boolean(table, k, v)
            elif isinstance(v, int) or isinstance(v, float):
                lib.immunio_set_number(table, k, v)
            elif isinstance(v, bytes):
                lib.immunio_set_string(table, k, v, len(v))
            elif isinstance(v, string_types):
                byte_v = to_bytes(v, 'utf8')
                lib.immunio_set_string(table, k, byte_v, len(byte_v))
            elif isinstance(v, dict):
                with _dict_to_table(request, v) as table_v:
                    lib.immunio_set_table(table, k, table_v)
            elif (isinstance(v, list) or isinstance(v, tuple) or
                  isinstance(v, set)):
                with _list_to_table(request, v) as table_v:
                    lib.immunio_set_table(table, k, table_v)
            else:
                raise Exception("unhandled table type: {}".format(type(v)))
    yield table
    lib.immunio_drop_table(table)


@contextmanager
def _list_to_table(request, pylist):
    with _lock:
        table = lib.immunio_create_array(request, len(pylist))
    if table == ffi.NULL:
        raise Exception("Error from immunio_create_array()")

    for index, v in enumerate(pylist):
        # Lua lists index from `1`, so add one here
        index = index + 1

        with _lock:
            if v is None:
                lib.immunio_seti_nil(table, index)
            elif isinstance(v, bool):
                lib.immunio_seti_boolean(table, index, v)
            elif isinstance(v, int) or isinstance(v, float):
                lib.immunio_seti_number(table, index, v)
            elif isinstance(v, bytes):
                lib.immunio_seti_string(table, index, v, len(v))
            elif isinstance(v, string_types):
                byte_v = to_bytes(v, 'utf8')
                lib.immunio_seti_string(table, index, byte_v, len(byte_v))
            elif isinstance(v, dict):
                with _dict_to_table(request, v) as table_v:
                    lib.immunio_seti_table(table, index, table_v)
            elif (isinstance(v, list) or isinstance(v, tuple) or
                  isinstance(v, set)):
                with _list_to_table(request, v) as table_v:
                    lib.immunio_seti_table(table, index, table_v)
            else:
                raise Exception("unhandled table type: {}".format(type(v)))
    yield table
    lib.immunio_drop_table(table)


HOOK_NAME = ["sql_execute", 'load_file_name',
             'file_io_popen', 'file_io_system', 'file_io']


def result_to_dic(self, request_metadata, hook_name, meta):
    if hook_name in HOOK_NAME:
        hook_result(self, hook_name, meta)


def hook_result(self, hook_name, meta):

    request=self.request_local_request

    result = {}
    if hook_name == 'sql_execute':
        hook_name = 'sql'
        result['query'] = meta['sql']
        result['server'] = meta['db_dialect']
    elif hook_name == 'file_io_popen':
        hook_name = 'command'
        result['command_popen'] = meta['parameters']
    elif hook_name == 'file_io_system':
        hook_name = 'command'
        result['command_system'] = meta['parameters']
    elif hook_name == 'file_io':
        if 'w' in meta['parameters'][1]:
            hook_name = 'writeFile'
            result['name'] = meta['parameters'][0]
            result['realpath'] = meta['cwd']
        elif 'r' in meta['parameters'][1]:
            hook_name = 'readFile'
            result['name'] = meta['parameters'][0]
            result['realpath'] = meta['cwd']
    result['hook_name']=hook_name
    print(request,result)

def print_result(request,result):
    print(request)
    print(result)


def run():
    agent = LibAgent({
        "log_level": "debug",
    })

    request = agent.new_request("ID")

    request.run_hook("<plugin-name>", "http_request_start", {
        "socket_ip": "127.0.0.1",
        "headers": [
            ("Content-Type", "text/plain"),
            ("User-Agent", "test"),
            ("Cookie", None),
        ]
    })


if __name__ == "__main__":
    run()
