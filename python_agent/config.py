from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

try:
    from configparser import SafeConfigParser
except ImportError:
    from ConfigParser import SafeConfigParser
import errno
import io
import os

from python_agent.compat import string_types, to_bytes
from python_agent.exceptions import ConfigError
from python_agent.logger import log


CONFIG_FILENAME = "./python_agent.ini"
python_agent_SECTION_NAME = "python_agent"

class Config(object):
    def __init__(self, defaults=None, autoload=True):
        # Initialize to default configuration (if specified)
        self._config = defaults or {}
        log.debug("Default configuration: %(config)s", {
            "config": self._config,
            })

        # Load config
        if autoload:
            config_file, content = self.read_config_file()
            if config_file:
                self.load_config(config_file, content)
                log.debug("Configuration after loading from file: %(config)s", {
                    "config": self._config,
                    })
            else:
                log.warn("Can't find config file - using defaults")


    @staticmethod
    def read_config_file():
        # Try loading file from some standard locations. First match is used.

        locations = [
            # /etc/
            "/etc",

            # Current working directory
            os.getcwd(),
            os.path.dirname( os.path.abspath(__file__)),

            # CWD/etc/python_agent.ini
            os.path.join(os.getcwd(), "etc/"),

            # homedir
            os.path.expanduser("~"),
        ]

        # Also try every location from CWD up to root '/'
        path = os.getcwd()  # This was already included above
        while True:
            new_path, _ = os.path.split(path)
            if new_path == path:
                # At root, we're done
                break
            locations.append(new_path)
            path = new_path

        # Find first matching config file.
        for location in locations:
            # Search config filenames - prefer new one
            for name in [CONFIG_FILENAME]:
                filename = os.path.join(location, name)
                log.debug("Trying to find config file at %(filename)s", {
                    "filename": filename,
                    })

                # Try to open the file to see if it exists. Avoids any race
                # conditions between checking existence and opening.
                try:
                    with io.open(filename, "r", encoding='utf8') as f:
                        content = f.read()
                    log.debug("Found config file at %(filename)s", {
                        "filename": filename,
                        })
                    return filename, content
                except IOError as exc:
                    # re-raise all exceptions except file-not-found
                    if exc.errno != errno.ENOENT:
                        raise ConfigError(
                            "Error reading python_agent config file '%s': %s" % (
                            filename, exc))
        # No config file found, return None
        return None, None

    def load_config(self, filename, content):
        if filename.endswith(".ini"):
            return self.load_ini_config(filename, content)
        raise ValueError("Can't read from file with this extension: '%s'" % (
            filename,))

    def load_ini_config(self, filename, content):
        fp = io.StringIO(content)
        parser = SafeConfigParser()
        parser.readfp(fp, filename)
        if parser.has_section(python_agent_SECTION_NAME):
            self._config.update(dict(parser.items(python_agent_SECTION_NAME)))

    def get(self, name, default=None, datatype=None):
        """
        Get a config value. Precedence is first environment variable,
        then config file, then fall back to the default.
        """
        environ_name = "python_agent_%s" % name.upper()

        if environ_name in os.environ:
            str_value = os.environ[environ_name]
        else:
            str_value = self._config.get(name, default)

        return convert(str_value, datatype)

    def items(self):
        """
        Yield each configuration option available.
        """
        for key, val in self._config.items():
            yield key, val

    @property
    def agent_enabled(self):
        """
        Helper shortcut for testing if the agent is enabled.
        """
        return self.get("agent_enabled", default=True, datatype=bool)


def convert(value, datatype=None):
    """
    Convert a value to the specified datatype. If the value is already
    the correct type, just return it.
    """
    # If final value is None, return None
    if value is None:
        return None

    # Convert the data type if specified

    # Bytes is first because on Py2 and Py3 bytes==str so we
    # attempt to decode from unicode in either case.
    if datatype is bytes:
        # Convert to bytes first so the {starts,ends}with() works
        value = to_bytes(value, "utf8")
        if ((value.startswith(b"'") and value.endswith(b"'")) or
                (value.startswith(b'"') and value.endswith(b'"'))):
            value = value[1:-1]
        return value

    elif datatype is str:
        # Strip leading and trailing quotes.
        if ((value.startswith("'") and value.endswith("'")) or
                (value.startswith('"') and value.endswith('"'))):
            value = value[1:-1]
        return value

    elif datatype is int:
        return int(value)

    elif datatype is bool:
        # If value is already a bool, just return it
        if isinstance(value, bool):
            return value
        # Convert string value to bool
        if value.lower() in ["t", "true", "y", "yes", "on", "1"]:
            return True
        elif value.lower() in ["f", "false", "n", "no", "off", "0"]:
            return False
        else:
            raise ValueError("Can't interpret `%s` as bool" % value)

    elif datatype is set:
        # If value is already a set, just return it
        if isinstance(value, set):
            return value

        # If value is a list or tuple, just convert to a set
        if isinstance(value, list) or isinstance(value, tuple):
            return set(value)

        # Treat strings as comma-separated values.
        if isinstance(value, string_types):
            # Empty strings are empty sets
            if value.strip() == "":
                return set()
            parts = value.split(",")
            return set(x.strip() for x in parts)

        raise ValueError("Can't interpret `%s` as set" % value)

    # No conversion required
    return value
