from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from immunio.logger import log
from immunio.patcher import monkeypatch
from immunio.context import get_context


# Set name so plugin can be enabled and disabled.
NAME = "flask"
HOOKS_CALLED = [
    "framework_login",
    "framework_redirect",
    "framework_route",
    "framework_user",
]


def add_hooks(run_hook, get_agent_func=None, timer=None):
    """
    Add our hooks into the flask library functions.
    """
    meta = {}

    try:
        import flask
    except ImportError:
        return None

    meta["version"] = flask.__version__

    # Install a hook to capture newly created wsgi apps and wrap them.
    hook_flask_app(run_hook, get_agent_func, timer)

    # Install a hook to capture the route name (use the url pattern)
    hook_flask_request_context(run_hook, timer)

    # Install a hook around the redirect method
    hook_flask_redirect(run_hook, timer)

    # Hook Flask-Login. This must be done before loading anything from
    # Flask-Security, as it will pull in methods like `login_user`.

    try:
        import flask.ext.login
    except ImportError:
        pass
    else:
        try:
            meta["flask_login_version"] = flask.ext.login.__version__
        except AttributeError:
            # Version 0.4.0 only has this attribute on __about__
            # although it's copied back for future versions:
            import flask.ext.login.__about__
            meta["flask_login_version"] = flask.ext.login.__about__.__version__
        hook_flask_login_user_logged_in(run_hook, timer)
        hook_flask_login_reload_user(run_hook, timer)

    try:
        import flask.ext.security
    except ImportError:
        pass
    else:
        meta["flask_security_version"] = flask.ext.security.__version__
        hook_flask_security_login_form(run_hook, timer)

    return meta


def hook_flask_app(run_hook, get_agent_func, timer):
    """
    Wrap the `Flask()` __init__ function so we can wrap each WSGI
    app as it is produced. This also creates the Agent if it hasn't been
    created yet.
    """
    import flask

    # If we don't have a `get_agent_func()` defined the app will be
    # wrapped elsewhere.
    if not get_agent_func:
        return

    # For new-style classes, special methods like __call__ are looked up
    # on the class directly, not the instance. This means it can't be
    # overridden normally. Instead, we have to override it on the class
    # to get it to check an instance method to allow us to override it
    # from the __init__ monkeypatch below.
    def immunio_call(self, *args, **kwargs):
        """
        Simply duplicate the behaviour of the original __call__ and proxy
        everything to the internal `wsgi_app` method. This stub will be
        wrapped by the Agent during the `__init__` monkeypatch below.
        """
        return self.wsgi_app(*args, **kwargs)
    flask.Flask._immunio_call = immunio_call

    @monkeypatch(flask.Flask, "__call__", timer=timer,
                 report_name="plugin.flask.app.__call__")
    def _call(orig, flask_self, *args, **kwargs):
        """
        We patch __call__ here because it is impossible to patch it on a
        per-instance basis. This mokeypatch on the class simply proxies
        through the stub `_immunio_call` defined above. Since the
        `_immunio_call` method is "normal", it can be overridden on the
        Flask instance during the __init__ monkeypatch below.
        """
        log.debug("Call to patched __call__(%(args)s, %(kwargs)s)", {
            "args": args,
            "kwargs": kwargs,
        })
        # Always call the immunio_call stub defined above. Since the stub
        # is not a special method, it can be overridden on the instance below.
        return flask_self._immunio_call(*args, **kwargs)


    @monkeypatch(flask.Flask, "__init__", timer=timer,
                 report_name="plugin.flask.app.__init__")
    def _flask_init(orig, flask_self, *args, **kwargs):
        """
        Here we patch the `__call__` method (via the _immunio_call stub) of
        every new Flask app. This ensures that when the app object is used
        as a WSGI callable, we already have it wrapped.
        """
        log.debug("Call to patched __init__(%(args)s, %(kwargs)s)", {
            "args": args,
            "kwargs": kwargs,
        })
        # Get the WSGI app (__init__ always returns None)
        orig(flask_self, *args, **kwargs)

        # Get or create the Immunio Agent singleton
        agent = get_agent_func()

        # Wrap the Flask app __call__ method (via _immunio_call) with Immunio.
        flask_self._immunio_call = agent.wrap_wsgi_app(flask_self._immunio_call)


def hook_flask_request_context(run_hook, timer=None):
    import flask

    @monkeypatch(flask.Flask, "request_context", timer=timer,
                 report_name="plugin.flask.app.request_context")
    def _flask_request_context(orig, flask_self, *args, **kwargs):
        log.debug("Call to patched request_context"
                  "(%(args)s, %(kwargs)s)", {
            "args": args,
            "kwargs": kwargs,
        })

        request_context = orig(flask_self, *args, **kwargs)
        if request_context.request.routing_exception is None:
            # Rule a string URL path with placeholders in
            # the format ``<converter(arguments):name>`
            rule = request_context.request.url_rule.rule
            run_hook("framework_route", {
                "route_name": rule
            })
        return request_context


def hook_flask_redirect(run_hook, timer):
    """Listen for the redirect() to be called and all framework_redirect"""
    import flask
    import werkzeug.utils

    # Flask imports the redirect method directly in to it's namespace, so
    # it's possible for it to be called from two locations
    for klass in (flask, werkzeug.utils):
        @monkeypatch(klass, "redirect", timer=timer,
                     report_name="plugin.flask.redirect")
        def _redirect(orig, location, *args, **kwargs):
            _strict_context, loose_context, stack = get_context()
            run_hook("framework_redirect", {
                "context_key": loose_context,
                "stack": stack,
                "destination_url": location,
            })

            return orig(location, *args, **kwargs)


def hook_flask_login_user_logged_in(run_hook, timer):
    """
    Listen for the user_logged_in signal.

    Attempt to get the username and email from the default
    Flask-Security attributes on a user.
    """
    from flask.ext.login import (
        user_logged_in,
        user_loaded_from_cookie,
        user_loaded_from_header,
        user_loaded_from_request,
    )

    @monkeypatch(user_logged_in, "send", timer=timer,
                 report_name="plugin.flask.user_logged_in")
    def _user_logged_in(orig, *args, **kwargs):
        user = kwargs.get('user')
        if not user:
            user = args[-1]

        user_id = user.get_id()
        log.debug("Flask-login user_logged_in (%(user)s)", {
            "user": user_id,
        })
        run_hook("framework_login", {
            "user_id": user_id,
            "username": getattr(user, 'username', None),
            "email": getattr(user, 'email', None),
        })
        return orig(*args, **kwargs)

    for signal in [user_loaded_from_cookie,
                   user_loaded_from_header,
                   user_loaded_from_request]:
        @monkeypatch(signal, "send", timer=timer,
                     report_name="plugin.flask.{0}".format(signal.name))
        def _user_loaded_signal(orig, *args, **kwargs):
            user = kwargs.get('user')
            if not user:
                user = args[-1]

            user_id = user.get_id()
            log.debug("Flask-login %(signal)s (%(user)s)", {
                "signal": signal.name,
                "user": user_id,
            })
            run_hook("framework_user", {
                "user_id": user_id,
                "username": getattr(user, 'username', None),
                "email": getattr(user, 'email', None),
            })
            return orig(*args, **kwargs)


def hook_flask_login_reload_user(run_hook, timer):
    """
    Replace the reload_user to set the framework_user.
    """
    import flask.ext.login
    from flask import _request_ctx_stack

    @monkeypatch(flask.ext.login.LoginManager, "reload_user", timer=timer,
            report_name="plugin.flask.reload_user")
    def _reload_user(orig, *args, **kwargs):
        log.debug("Flask-login reload_user called")
        result = orig(*args, **kwargs)
        user = _request_ctx_stack.top.user
        log.debug("Flask-login user is {0}".format(user))

        anonymous = user.is_anonymous
        if callable(anonymous):  # In older Flask-Login this is a method
            anonymous = anonymous()

        if not anonymous:
            user_id = user.get_id()
            run_hook("framework_user", {
                "user_id": user_id,
                "username": getattr(user, 'username', None),
                "email": getattr(user, 'email', None),
            })
        else:
            log.debug("Flask-login user is anonymous, no framework_user")
        return result


def hook_flask_security_login_form(run_hook, timer):
    """
    Hook the `validate` on the standard LoginForm to watch for authentication
    events.
    """
    from flask.ext.security import LoginForm
    from flask.ext.security.utils import get_message

    @monkeypatch(LoginForm, "validate", timer=timer,
                 report_name="plugin.flask.security_login_validate")
    def _validate(orig, self, *args, **kwargs):
        interesting_email_errors = [
            get_message('USER_DOES_NOT_EXIST')[0],
        ]
        interesting_password_errors = [
            get_message('INVALID_PASSWORD')[0],
            get_message('DISABLED_ACCOUNT')[0],
        ]

        result = orig(self, *args, **kwargs)
        reason = None

        # We only want to report on interesting errors. Others like when the
        # user didn't supply a username are not of any use.
        if not result:
            for error in self.email.errors:
                if error in interesting_email_errors:
                    reason = error
            for error in self.password.errors:
                if error in interesting_password_errors:
                    reason = error

            if not reason:
                return result

        auth_data = {
            "username": self.email.data,
            "is_valid": result,
            "reason": reason,
        }

        run_hook("authenticate", auth_data)

        return result
