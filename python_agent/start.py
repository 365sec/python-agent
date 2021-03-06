"""
Shortcut module to automatically start a new python_agent Agent.

Add `import python_agent.start` to the top of your app's entrypoint and this will
automatically monkeypatch the required libraries, start the Agent when
a new WSGI app is created, and wrap the WSGI callable.
"""
from python_agent.singleton import do_setup

# Load the config and do MonkeyPatching.
do_setup()
