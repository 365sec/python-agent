from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from numbers import Number
import re

from immunio.compat import string_types, get_iteritems
from immunio.logger import log
from immunio.singleton import run_hook


# Pattern of allowed characters in event names and metadata names.
SLUG_PATTERN = "^[a-zA-Z0-9_-]+$"


def custom_event(event_type, metadata=None):
    """
    Report a custom event to IMMUNIO. The reported event can be used to
    indicate a threat, or can be used to limit rates.
    """
    # `event_type` must be a string
    if not isinstance(event_type, string_types):
        raise ValueError(
            "`event_type` must be str or unicode, not %r" % (event_type,))
    # `event_type` can only contain letters, numbers, dashes, and underscores.
    if not re.match(SLUG_PATTERN, event_type):
        raise ValueError("`event_type` can only contain letters, numbers, "
                         "dashes, and underscores")

    # `metadata` is optional
    if metadata is None:
        metadata = {}

    # `metadata` must be a dict with string keys, only one level deep.
    if not isinstance(metadata, dict):
        raise ValueError("`metadata` must be a dict, not %r" % (metadata,))
    for key, value in get_iteritems(metadata)():
        if not isinstance(key, string_types):
            raise ValueError(
                "`metadata` keys must be str or unicode, not %r" % (key,))
        # `event_type` can only contain letters, numbers, dashes, and
        # underscores.
        if not re.match(SLUG_PATTERN, key):
            raise ValueError("`metadata` keys can only contain letters, "
                             "numbers, dashes, and underscores")
        if not (isinstance(value, string_types) or
                isinstance(value, Number) or
                isinstance(value, bool) or
                value is None):
            raise ValueError(
                "`metadata` values must be strings, numbers, or bools, "
                "not %r" % key)

    log.debug("API extend.custom_event "
              "event_type=%(event_type)s metadata=%(metadata)s" % {
        "event_type": event_type,
        "metadata": metadata,
    })
    return run_hook("custom_event", {
        "event_type": event_type,
        "metadata": metadata,
    })


def custom_threat(threat_name, message, metadata=None):
    """
    Inform Immunio of custom threat for your app.
    """
    if not isinstance(threat_name, string_types):
        raise ValueError(
            "`threat_name` must be str or unicode, not %r" % threat_name)

    if not isinstance(message, string_types):
        raise ValueError(
            "`message` must be str or unicode, not %r" % message)

    if metadata is None:
        metadata = {}

    if not isinstance(metadata, dict):
        raise ValueError("`metadata` must be a dict, not %r" % metadata)

    log.debug("API extend.custom_threat "
              "threat_name=%(threat_name)s message=%(message)s" % {
        "threat_name": threat_name,
        "message": message,
    })
    return run_hook("custom_threat", {
        "threat_name": threat_name,
        "message": message,
        "display_meta": metadata,
    })
