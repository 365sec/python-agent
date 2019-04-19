from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import hashlib
import pkg_resources

from immunio.compat import get_func_defaults, set_func_defaults, to_bytes
from immunio.logger import log
from immunio.patcher import monkeypatch


# Set name so plugin can be enabled and disabled.
NAME = "pyramid"
HOOKS_CALLED = [
    "authenticate",
    "bad_cookie",
    "framework_csrf_check",
    "framework_login",
    "framework_logout",
    "framework_session",
    "framework_user",
]

def add_hooks(run_hook, get_agent_func=None, timer=None):
    """
    Add hooks to pyramid.
    """
    try:
        import pyramid  # pylint: disable=unused-variable
    except ImportError:
        return None

    try:
        version = pkg_resources.get_distribution("pyramid").version
    except pkg_resources.DistributionNotFound:
        version = None

    meta = {
        "version": version

    }

    # Add the individual hooks
    add_remember_hook(run_hook, timer)
    add_forget_hook(run_hook, timer)

    # parse_ticket needs pyramid.authentication, which imports pyramid.security
    # used by `remember` and `forget` above. Make sure parse_ticket comes after.
    add_parse_ticket_hook(run_hook, timer)

    add_signed_deserialize_hook(run_hook, timer)
    add_webob_signed_serializer_hook(run_hook, timer, version)
    add_check_csrf_hook(run_hook, timer)

    # The handle_request hooks imports pyramid.config which imports a ton of
    # other modules. Patch it last so none of the above patches miss something
    # that gets copied by pyramid.config.
    add_handle_request_hook(run_hook, get_agent_func, timer)

    return meta


def unauthenticated_userid(request):
    """
    Helper method for getting the `unauthenticated_userid` value from a
    request. For pyramid >= 1.5 `unauthenticated_userid` is an attribute
    on the request object. For older pyramid versions, before 1.5,
    `unauthenticated_userid` is a helper method in `pyramid.security`.
    """
    try:
        return request.unauthenticated_userid
    except AttributeError:
        try:
            from pyramid.security import unauthenticated_userid
            return unauthenticated_userid(request)
        except ImportError:
            return None


def add_handle_request_hook(run_hook, get_agent_func, timer):
    """
    Add a hook as early as possible in the Pyramid request flow to extract
    the user_id making the request. This is required because normally the
    user is not loaded unless the app-code actually requests it.
    """
    import pyramid.config

    # Wrap `pyramid.config.Configurator.make_wsgi_app` to get access to
    # the wsgi `app` object.
    @monkeypatch(pyramid.config.Configurator, "make_wsgi_app", timer=timer,
                 report_name="plugin.pyramid.app.make_wsgi_app")
    def _make_wsgi_app(orig, *args, **kwargs):
        app = orig(*args, **kwargs)

        # Wrap anything on the app router while we have it.
        wrap_pyramid_router(run_hook, app)

        # Wrap the WSGI app object with Immunio.
        # If we don't have a `get_agent_func()` defined the app will be
        # wrapped elsewhere.
        if get_agent_func:
            # Get or create the Immunio Agent singleton
            agent = get_agent_func()
            # Do the wrapping
            app = agent.wrap_wsgi_app(app)
        return app


def wrap_pyramid_router(run_hook, app):
    """
    Wrap a new Pyramid WSGI app object (called from wrap_wsgi_app() above).

    The `app` argument is a new Pyramid Router object.
    """
    # Now that we have the app, wrap the `handle_request` function to get
    # access to the request object as early as possible.
    orig_handle_request = app.handle_request
    def wrapped_handle_request(request, *args, **kwargs):
        # Extract the framework session_id if present.
        session_id = get_session_id_from_request(request)
        if session_id is not None:
            run_hook("framework_session", {
                "session_id": session_id,
            })

        # While we have the request, ask for the current user
        # Use the `unauthenticated_userid` property to avoid making any
        # costly access to persistant storage.
        user_id = unauthenticated_userid(request)
        if user_id is not None:
            run_hook("framework_user", {
                "user_id": user_id,
                "username": user_id,
            })

        return orig_handle_request(request, *args, **kwargs)
    app.handle_request = wrapped_handle_request


def get_session_id_from_request(request):
    """
    Safely get a `session_id` from the provided request. If sessions are
    not enabled in the app, this will return None.
    """
    # If no SessionFactory is defined for the app, `request.session` will
    # raise an exception.
    try:
        session = request.session
    except AttributeError:
        # No session available
        return None

    # Not all Pyramid sessions have a built-in `id` field. We try a few
    # common cases here and if nothing is found we use a hash of the CSRF token
    if hasattr(session, "id"):
        return session.id
    if hasattr(session, "session_id"):
        return session.session_id
    if hasattr(session, "__getitem__"):
        if "id" in session:
            return session["id"]
        if "session_id" in session:
            return session["session_id"]

    csrf_token = session.get_csrf_token()
    return hashlib.sha1(to_bytes(csrf_token, 'utf8')).hexdigest()


def add_signed_deserialize_hook(run_hook, timer):
    """
    Wrap the `pyramid.session.signed_deserialize` function to capture
    invalid session cookies. This isn't necessarily used by all session
    frameworks but should be reasonably common.
    """
    import pyramid.session

    # wrap 'signed_deserialize' function
    orig_signed_deserialize = pyramid.session.signed_deserialize

    def wrapped_signed_deserialize(token, *args, **kwargs):
        log.debug(
            "pyramid.session.signed_deserialize"
            "(%(token)s, %(args)s, %(kwargs)s)", {
                "token": token,
                "args": args,
                "kwargs": kwargs,
                })
        try:
            result = orig_signed_deserialize(token, *args, **kwargs)
        except ValueError as exc:
            run_hook("bad_cookie", {
                # We can't currently access the name of the cookie being
                # checked.
                "key": "<unknown>",
                "value": token,
                "reason": str(exc),
            })
            raise

        return result

    pyramid.session.signed_deserialize = wrapped_signed_deserialize
    # `pyramid.session.UnencryptedCookieSessionFactoryConfig` grabs a copy of
    # signed_deserialize as soon as `pyramid.session` is imported as a
    # default function argument. We need to replace the default with our
    # wrapped version by directly accessing the default arguments of the
    # function.
    from pyramid.session import UnencryptedCookieSessionFactoryConfig
    defaults = list(get_func_defaults(UnencryptedCookieSessionFactoryConfig))
    for i, default in enumerate(defaults):
        # Find which default arg is the `signed_deserialize` function
        if default == orig_signed_deserialize:
            # And replace it with our wrapped version
            defaults[i] = wrapped_signed_deserialize
    # Now replace the defaults with our modified copy
    set_func_defaults(UnencryptedCookieSessionFactoryConfig, tuple(defaults))


def add_webob_signed_serializer_hook(run_hook, timer, version):
    """
    Hook the `webog.cookies.SignedSerializer` class to catch cookie
    tamering of sessions. The SignedSerializer is used by the newer
    SignedCookieSessionFactory introduced in pyramid 1.5
    """

    if version:
        version_elements = version.split('.', 2)
        if len(version_elements) >= 2:
            if version_elements[0] == '1' and int(version_elements[1]) <= 4:
                log.info(("Pyramid versions before 1.5 do not support cookie "
                           "tampering."))
                return

    from pyramid.session import SignedSerializer

    @monkeypatch(SignedSerializer, "loads", timer=timer,
                 report_name="plugin.pyramid.cookie.signed_serializer_loads")
    def _loads(orig, self, token, *args, **kwargs):
        log.debug(
            "pyramid.session.SignedSerializer.loads"
            "(%(token)s, %(args)s, %(kwargs)s)", {
                "token": token,
                "args": args,
                "kwargs": kwargs,
                })
        try:
            result = orig(self, token, *args, **kwargs)
        except ValueError as exc:
            run_hook("bad_cookie", {
                # We currently don't support changing the default cookie name.
                "key": "session",
                "value": token,
                "reason": str(exc),
            })
            raise

        return result


def add_check_csrf_hook(run_hook, timer):
    """
    Wrap the `pyramid.session.check_csrf_token` function to catch invalid
    CSRF tokens.
    """

    import pyramid.session
    try:
        from pyramid.exceptions import BadCSRFToken as BadCsrfError
    except ImportError:
        from pyramid.httpexceptions import HTTPBadRequest as BadCsrfError
    import pyramid.config.predicates

    # wrap 'check_csrf_token' function
    orig_check_csrf_token = pyramid.session.check_csrf_token

    def wrapped_check_csrf_token(*args, **kwargs):
        log.debug(
            "pyramid.session.check_csrf_token"
            "(%(args)s, %(kwargs)s)", {
                "args": args,
                "kwargs": kwargs,
                })
        try:
            result = orig_check_csrf_token(*args, **kwargs)
        except BadCsrfError:
            result = False
            raise
        finally:
            meta = {"valid": result}
            if not result:
                meta["reason"] = "Invalid or missing CSRF token"
            run_hook("framework_csrf_check", meta)
        return result

    pyramid.session.check_csrf_token = wrapped_check_csrf_token
    pyramid.config.predicates.CheckCSRFTokenPredicate.check_csrf_token = (
        staticmethod(wrapped_check_csrf_token))


def add_parse_ticket_hook(run_hook, timer):
    """
    Wrap the parse_ticket function of AuthTktCookieHelper to capture
    invalid auth cookies. This isn't necessarily used by all auth
    frameworks but should be reasonably common.
    """
    import pyramid.authentication

    @monkeypatch("pyramid.authentication.AuthTktCookieHelper.parse_ticket",
                 timer=timer, report_name="plugin.pyramid.cookie.parse_ticket")
    def _parse_ticket(orig, _secret, token, *args, **kwargs):
        log.debug(
            "pyramid.authentication.AuthTktCookieHelper.parse_ticket"
            "(%(args)s, %(kwargs)s)", {
                "args": args,
                "kwargs": kwargs,
                })
        try:
            result = orig(_secret, token, *args, **kwargs)
        except pyramid.authentication.BadTicket as e:
            run_hook("bad_cookie", {
                # We currently don't support changing the default cookie name.
                "key": "auth_tkt",
                "value": token,
                "reason": str(e),
            })
            raise

        return result


def add_remember_hook(run_hook, timer):
    """
    The `pyramid.security.remember` function is called after any successful
    login. We use it to capture the newly logged-in user.
    """
    import pyramid.security

    @monkeypatch(pyramid.security, "remember", timer=timer,
                 report_name="plugin.pyramid.auth.remember")
    def _remember(orig, request, principal, **kwargs):
        log.debug(
            "pyramid.security.remember"
            "(%(request)s, %(principal)s, %(kwargs)s)", {
                "request": request,
                "principal": principal,
                "kwargs": kwargs,
                })

        try:
            result = orig(request, principal, **kwargs)
        except Exception as e:
            run_hook("authenticate", {
                "reason": str(e),
                "is_valid": False
            })
            raise

        # Pyramid doesn't expose a username - only the user_id so just use
        # the same value for both fields.
        run_hook("authenticate", {
            "is_valid": True,
            "username": principal,
            "user_id": principal,
        })
        run_hook("framework_login", {
            "username": principal,
            "user_id": principal,
        })
        run_hook("framework_user", {
            "user_id": principal,
            "username": principal,
        })
        return result


def add_forget_hook(run_hook, timer):
    """
    The `pyramid.security.forget` function is called after any successful
    logout. We use it to capture the logout event.
    """
    import pyramid.security

    @monkeypatch(pyramid.security, "forget", timer=timer,
                 report_name="plugin.pyramid.auth.forget")
    def _forget(orig, request):
        log.debug("pyramid.security.forget(%(request)s)", {
            "request": request,
            })

        user_id = unauthenticated_userid(request)

        result = orig(request)
        run_hook("framework_logout", {
            # Pyramid doesn't expose a username - only the user_id
            "user_id":  user_id,
            "username":  user_id,
        })
        return result
