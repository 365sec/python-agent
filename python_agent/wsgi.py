from __future__ import (
    absolute_import,
    division,
    print_function,
)

# No unicode_literals because wsgi expects ascii strings

from io import BytesIO
import logging
import sys
from threading import local

from immunio.compat import to_bytes, to_native_string
from immunio.context import get_stack
from immunio.exceptions import ImmunioBlockedError, ImmunioOverrideResponse
from immunio.logger import log

HOOKS_CALLED = ["http_request_start", "exception", "http_response_start",
        "http_response_body_chunk", "http_request_body_chunk"]


HTTP_STATUS_CODES = {
    200: "200 OK",
    201: "201 Created",
    202: "202 Accepted",
    204: "204 No Content",

    301: "301 Moved Permanently",
    302: "302 Found",
    303: "303 See Other",
    304: "304 Not Modified",
    307: "307 Temporary Redirect",

    400: "400 Bad Request",
    401: "401 Unauthorized",
    403: "403 Forbidden",
    404: "404 Not Found",
    405: "405 Method Not Allowed",

    500: "500 Internal Server Error",
}


class WsgiWrapper(object):
    """
    Accepts new requests and hands off to a new WsgiRequest object to handle.

    The WsgiRequest object takes care of calling Agent.http_request_finish() on
    completion.
    """
    def __init__(self, agent, app, request_uuid_header):
        self._agent = agent
        self._app = app
        self._request_uuid_header = request_uuid_header
        self._local = local()
        self._local.wsgi_request = None
        self._warned_about_unclosed_iter = False

    def __call__(self, environ, start_response):

        """
        Register new request with Agent then create a WsgiRequest object to
        handle it.
        """
        # If we're in debug logging, grab some extra data about the call stack
        # here to help identify what web server we're running under
        if log.isEnabledFor(logging.DEBUG):
            stack = "\n".join(["    %s:%d:%s" % frame for frame in get_stack()])
            log.debug("WsgiWrapper.__call__ stack:\n%s", stack)

        # Ensure the `wsgi_response` thread local is present
        if not hasattr(self._local, "wsgi_request"):
            self._local.wsgi_request = None

        # If the previous WsgiRequest is safe to close, but hasn't been closed,
        # close it here. This should not happen for well-behaved WSGI servers,
        # but we handle the case here in case we're running under a server
        # that doesn't comply to the spec.
        if self._local.wsgi_request and not self._local.wsgi_request.closed:
            if self._local.wsgi_request.safe_to_close:
                if not self._warned_about_unclosed_iter:
                    log.warning("WsgiResponse iterator was not closed by "
                                "server for request '%s'. Forcing close now.",
                                self._local.wsgi_request._request.request_id)
                    self._warned_about_unclosed_iter = True
                self._local.wsgi_request.close()
            else:
                # If the iterator was not fully consumed, and was not closed
                # always log a warning.
                log.warning("WsgiResponse iterator was not fully consumed and "
                            "was not closed for request '%s'.",
                            self._local.wsgi_request._request.request_id)

        # If a request is already in progress for this thread, don't start a
        # new one.

        if self._agent.get_request_id() is not None:
            print("Request '%s' already in progress, calling sub-app",
                  self._agent.get_request_id())
            # Just call original app directly.
            log.debug("Request '%s' already in progress, calling sub-app",
                      self._agent.get_request_id())
            return self._app(environ, start_response)

        #request type=Request
        request = self._agent.http_new_request()

        self._local.wsgi_request = WsgiRequest(self._agent,
            self._app, request, self._request_uuid_header)

        return self._local.wsgi_request.handle_request(environ, start_response)


class WsgiRequest(object):
    def __init__(self, agent, app, request, request_uuid_header):
        self._agent = agent
        self._app = app
        self._request = request
        self._request_uuid_header = request_uuid_header

        self._orig_start_response = None
        self._start_response_called = False
        self._wrapped_input = None
        self._output_gen = None
        self._inspect_response = False
        self._buffer_response = False
        # This is set to True when the response iteration is complete
        self.safe_to_close = False
        self.closed = False

    def handle_request(self, environ, start_response):
        # Keep a reference to the original start_response
        self._orig_start_response = start_response

        # Extract request meta
        request_metadata = self._extract_request_meta(environ)
        self._request.request_metadata = request_metadata
        # Guard call to original app
        try:
            # Report to engine
            ''''
            hook_result = self._agent.run_hook(
                "wsgi",
                "http_request_start",
                request_metadata,
                request=self._request)
            '''
            hook_result = self._agent.run_hook(
                "wsgi",
                "request",
                {},
                request=self._request)

            hook_result = {}
            inspect_body = hook_result.get("inspect_body", False)
            buffer_body = inspect_body and hook_result.get("buffer_body", False)

            # If the agent wants to see the request body, add our wrapper.
            if inspect_body:
                # Wrap the wsgi input object
                self.wrapped_input = WsgiInputWrapper(
                    self._request, self._agent, environ["wsgi.input"])
                environ["wsgi.input"] = self.wrapped_input

            if buffer_body:
                # Engine wants request body in single call, instead of
                # chunk by chunk
                data_len = int(environ.get("CONTENT_LENGTH", "0"))
                self.wrapped_input.immunio_readall(data_len)

            # Call into original app
            self._output_gen = self._app(environ, self._wrapped_start_response)

            # If we're in debug logging, grab some extra data about the result
            # type here to help identify what how it should be handled.
            if log.isEnabledFor(logging.DEBUG):
                import inspect
                output_file = None
                debug_error = None
                try:
                    target = self._output_gen
                    if hasattr(target, "__class__"):
                        target = target.__class__
                    output_file = inspect.getfile(target)
                except Exception as exc:
                    debug_error = str(exc)

                log.debug(
                    "WsgiWrapper.handle_request output_gen: "
                    "type:'%s' has-close:'%s' file:'%s' error:'%s'",
                    type(self._output_gen), hasattr(self._output_gen, "close"),
                    output_file, debug_error)

        except ImmunioBlockedError:
            # Block this request
            self._block_request()

        except ImmunioOverrideResponse as exc:
            # Block this request
            status, headers, body = exc.args

            # Headers from Lua can come back as:
            # [["header", "value"], ]
            headers = [(to_native_string(h, 'ascii'),
                to_native_string(v, 'ISO-8859-1')) for (h, v) in headers]
            self._block_request(status, headers, body)

        except Exception as exc:
            # Report error to engine
            self._agent.run_hook(
                "wsgi", "exception", {
                    "source": "WsgiWrapper.__call__",
                    "exception": str(exc),
                }, request=self._request)
            # This request is over
            self.close()
            # Re-raise to framework so it can clean up
            raise

        # This object also implements the iterator protocol
        return self

    def _wrapped_start_response(self, status, headers, exc_info=None):
        if self._request_uuid_header:
            headers.append(
                (str(self._request_uuid_header), self._request.request_id))

        # `status` is a string like "404 NOT FOUND" but Lua expects a number.
        status_code = int(status[:3])

        # We can't pass actual exceptions into Lua, so stringify if present
        if exc_info:
            exc_info_str = "%s %s" % (exc_info[0].__name__, exc_info[1])
        else:
            exc_info_str = None
        '''
        hook_response = self._agent.run_hook(
            "wsgi", "http_response_start", {
                "status": status_code,
                "status_string": status,
                "headers": headers,
                "exc_info": exc_info_str,
            }, request=self._request)
        '''
        hook_response = {}
        # Check if response body should be inspected
        self._inspect_response = hook_response.get("inspect_body", False)
        # Default to no buffering
        self._buffer_response = (self._inspect_response and
                                 hook_response.get("buffer_body", False))

        # If new headers are provided, use those instead
        if "headers" in hook_response:
            headers = hook_response["headers"]

        # Guard call to original start_response
        try:
            result = self._orig_start_response(status, headers, exc_info)
            self._start_response_called = True
        except Exception as exc:
            # Report error to engine
            self._agent.run_hook(
                "wsgi", "exception", {
                    "source": "start_response",
                    "exception": str(exc),
                }, request=self._request)
            # Re-raise to framework so it can clean up
            raise

        return result

    def _extract_request_meta(self, environ):
        request_metadata = {}
        request_metadata["protocol"] = environ.get("SERVER_PROTOCOL")
        request_metadata["scheme"] = environ.get("wsgi.url_scheme")
        #request_metadata["uri"] = environ.get("REQUEST_URI")
        request_metadata["uri"] = environ.get("wsgi.url_scheme")+'://'+environ.get('HTTP_HOST')+ environ.get("PATH_INFO")+'?'+environ.get("QUERY_STRING")
        request_metadata["querystring"] = environ.get("QUERY_STRING")
        request_metadata["method"] = environ.get("REQUEST_METHOD")
        request_metadata["path"] = environ.get("PATH_INFO")
        request_metadata["socket_ip"] = environ.get("REMOTE_ADDR")
        request_metadata["socket_port"] = environ.get("REMOTE_PORT",0)

        # Extract HTTP Headers
        request_metadata["headers"] = {}
        for k, v in environ.items():
            # All headers start with HTTP_
            if k.startswith("HTTP_"):
                # Reformat as lowercase, dash separated
                header = k[5:].lower().replace('_', '-')
                request_metadata["headers"][header] = v

        return request_metadata

    def _block_request(self, status=None, headers=None,
                       body=b"Request blocked"):
        """
        Block an http request by returning a Forbidden response.

        status = str
        headers = [(str, str),]
        body = bytes
        """
        # TODO Make this look pretty
        if status is None:
            status = "403 Forbidden"

        # status may be provided as an integer. If so, convert to the
        # equivalent string status.
        if isinstance(status, int):
            status = HTTP_STATUS_CODES.get(status, str(status))

        if headers is None:
            headers = [("Content-Type", "text/plain")]

        body = to_bytes(body, encoding="utf8")

        if self._request_uuid_header:
            headers.append(
                (str(self._request_uuid_header), self._request.request_id))

        if self._start_response_called:
            # start_response has already been called. In order to cancel the
            # response now we need to call start_response with exc_info set.
            exc_info = sys.exc_info()
        else:
            self._start_response_called = True
            exc_info = None

        # `status` is a string like "404 NOT FOUND" but Lua expects a number.
        status_code = int(status[:3])

        # We can't pass actual exceptions into Lua, so stringify if present
        if exc_info:
            exc_info_str = "%s %s" % (exc_info[0].__name__, exc_info[1])
        else:
            exc_info_str = None

        # Manually send the response start hook
        '''
        self._agent.run_hook(
            "wsgi", "http_response_start", {
                "status": status_code,
                "status_string": status,
                "headers": headers,
                "exc_info": exc_info_str,
            }, request=self._request)
        '''
        self._orig_start_response(status, headers, exc_info)
        self._output_gen = iter([body])

    def __iter__(self):
        log.debug("WSGI starting response iterator")
        # Guard call to original output iterator
        try:
            buff = []
            # We have to start iterating before testing self._inspect_response
            # because start_response() might not be called until iteration
            # begins.
            for chunk in self._output_gen:
                if not self._inspect_response:
                    yield chunk
                elif self._buffer_response:
                    buff.append(chunk)
                    yield b""
                else:
                    # Report the outgoing chunk to the engine
                    self._agent.run_hook(
                        "wsgi", "http_response_body_chunk", {
                            "chunk": chunk,
                            "buffered": False,
                        }, request=self._request)

                    yield chunk
            if self._inspect_response and self._buffer_response:
                body = b""
                if buff:
                    body = type(buff[0])().join(buff)

                # Report the buffered body to the engine
                self._agent.run_hook(
                    "wsgi", "http_response_body_chunk", {
                        "chunk": body,
                        "buffered": True,
                    }, request=self._request)
                yield body

        except ImmunioBlockedError:
            # Kill current iterator
            # TODO Should we finish iterating through it first?
            self._output_gen.close()
            # Block request (this call will replace the closed self._output_gen)
            self._block_request()
            for chunk in self._output_gen:
                yield chunk

        except ImmunioOverrideResponse as exc:
            # Kill current iterator
            # TODO Should we finish iterating through it first?
            self._output_gen.close()

            # Block request (this call will replace the closed self._output_gen)
            status, headers, body = exc.args
            self._block_request(status, headers, body)
            for chunk in self._output_gen:
                yield chunk

        except Exception as exc:
            # Report error to engine
            self._agent.run_hook(
                "wsgi", "exception", {
                    "source": "WsgiWrapper.__next__",
                    "exception": str(exc),
                }, request=self._request)
            # Re-raise to framework so it can clean up
            raise
        finally:
            self.safe_to_close = True
            log.debug("WSGI response iterator complete")

    def close(self):
        log.debug("WSGI response close() called")
        if not self.safe_to_close:
            log.warning("Server is calling close() on request '%s' "
                        "before iteration complete.", self._request.request_id)

        # Guard call to original iterator close
        try:
            # If original generator has 'close' method, we need to call it
            if hasattr(self._output_gen, "close"):
                self._output_gen.close()
        except Exception as exc:
            # Report error to engine
            self._agent.run_hook(
                "wsgi", "exception", {
                    "source": "WsgiWrapper.close",
                    "exception": str(exc),
                }, request=self._request)
            # Re-raise to framework so it can clean up
            raise
        finally:
            # Report end to engine
            self._agent.http_request_finish(request=self._request)
            # Reset for next request
            self._request = None
            self._output_gen = None
            self._orig_start_response = None
            self._start_response_called = False
            self.closed = True

class WsgiInputWrapper(object):
    """
    Wraps a WSGI input stream. Reports chunks of the request body to
    the engine as they are read by the wrapped application.
    """
    def __init__(self, request, agent, original_input):
        self._request = request
        self._agent = agent
        self._input = original_input

    def report_chunk(self, chunk, buffered=False):
        self._agent.run_hook(
            "wsgi", "http_request_body_chunk", {
                "chunk": chunk,
                "buffered": buffered,
            }, request=self._request)

    def immunio_readall(self, size):
        """
        Special method used by the agent to read the entire input body
        for inspection. After reading, the original wsgi.input is replaced
        by a BytesIO version to maintain the file-like semantics for the
        protected application. No further request_body chunks will be
        reported to the engine for this request.
        """
        # Read entire input
        buff = self._input.read(size)

        self.report_chunk(buff, buffered=True)

        # Replace input with a BytesIO object
        self._input = BytesIO(buff)
        # Clear the _agent variable so no more chunks are reported
        self._agent = None
        return buff

    def read(self, size=-1):
        """
        Reads a specified number of bytes from input. size defaults to -1
        which reads the entire input.
        """
        chunk = self._input.read(size)
        if self._agent:
            self.report_chunk(chunk)
        return chunk

    def readline(self):
        chunk = self._input.readline()
        # Don't report empty last chunk to the Agent. It just indicates EOF.
        if not chunk:
            return chunk
        if self._agent:
            self.report_chunk(chunk)
        return chunk

    def readlines(self, hint=None):
        lines = self._input.readlines(hint)
        if self._agent:
            chunk = b""
            if lines:
                chunk = type(lines[0])().join(lines)
            self.report_chunk(chunk)
        return lines

    def __iter__(self):
        for chunk in self._input:
            if self._agent:
                self.report_chunk(chunk)
            yield chunk
