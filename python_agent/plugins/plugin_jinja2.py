from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from binascii import hexlify
from hashlib import sha1
from threading import local

from contextlib import contextmanager

import os
import pkg_resources
import re

from python_agent import __version__
from python_agent.compat import to_bytes
from python_agent.logger import log
from python_agent.patcher import monkeypatch
from python_agent.util import DummyContext


# Match python_agent placeholders like {python_agent-var:0:1234}
PLACEHOLDER_REGEX = re.compile(r"\{\/?python_agent-var:[0-9]+:[0-9a-fA-F]{4}\}")


# Give a name to this plugin so it can be enabled and disabled.
NAME = "xss_jinja2"
HOOKS_CALLED = ["template_render_done"]


def add_hooks(run_hook, get_agent_func=None, timer=None):
    """
    Add hooks to Jinja2
    """
    try:
        import jinja2  # pylint: disable=unused-variable
    except ImportError:
        return None

    try:
        version = pkg_resources.get_distribution("Jinja2").version
    except pkg_resources.DistributionNotFound:
        version = None

    meta = {
        "version": version
    }

    def xss_disabled():
        if not get_agent_func:
            return False
        return not get_agent_func().is_feature_enabled("XSS")


    # Add our custom parser node
    add_python_agent_var_node(timer)
    # Hook the template parse and compile stages
    add_compiler_hooks(timer, xss_disabled)
    # Hook the actual rendering
    add_template_render_hook(run_hook, timer, xss_disabled)

    return meta


def add_python_agent_var_node(timer):
    """
    Adds a new Node type to Jinja2's parser.

    Jinja2 tries to prevent people from defining new node types by removing
    the __new__ method at the end of the nodes.py file. Unfortunately, we do
    need our own node type, so we have to work around the restriction by
    temporarily replacing the __new__ function, adding our node type, then
    putting everything back the way it was.
    """
    import jinja2.nodes

    @monkeypatch("jinja2.nodes.NodeType.__new__", timer=timer,
                 report_name="plugin.jinja2.setup.new_python_agent_node")
    def _copy_of_real_new(orig, cls, name, bases, d):
        """
        This is an exact copy of the `__new__()` method of
        jinja2.nodes.NodeType.
        """
        for attr in 'fields', 'attributes':
            storage = []
            storage.extend(getattr(bases[0], attr, ()))
            storage.extend(d.get(attr, ()))
            assert len(bases) == 1, 'multiple inheritance not allowed'
            assert len(storage) == len(set(storage)), 'layout conflict'
            d[attr] = tuple(storage)
        d.setdefault('abstract', False)
        return type.__new__(cls, name, bases, d)

    # Define our new Node type
    class python_agentVarNode(jinja2.nodes.Expr):
        fields = ('node', 'var_definition_index', 'var_code')

    # And save our new node type into the module
    jinja2.nodes.python_agentVarNode = python_agentVarNode

    # Now unwrap __new__ to replace the previous 'disabled' version
    jinja2.nodes.NodeType.__new__.python_agent_unwrap()


def add_compiler_hooks(timer, xss_disabled):
    """
    MonkeyPatch the template parser and the code generator to inject
    python_agentVarNode wrappers around template variable expressions
    (anything wrapped in `{{ }}`) to collect data every time the
    template is rendered..

    This function handles everything from the template source up to the
    compiled template. The compiled code is handled by the
    `add_template_render_hook()` function.
    """
    import jinja2.lexer
    import jinja2.parser
    import jinja2.nodes
    try:
        from jinja2._compat import NativeStringIO as StringIO
    except ImportError:
        from cStringIO import StringIO

    @monkeypatch("jinja2.parser.Parser.__init__", timer=timer,
                 report_name="plugin.jinja2.compile.parser_init")
    def _init(orig, parser_self, environment, source, name=None, filename=None,
              *args, **kwargs):
        """
        The goal here is to hash the template source and grab the
        filename. Stick the values on the instance so we can get them
        again when we parse the template.
        """
        # Calculate the SHA1 of the template source code
        source_bytes = to_bytes(source, "utf8")
        parser_self._python_agent_template_sha = sha1(source_bytes).hexdigest()

        # Prefer the `name`, but fall back to <template> if nothings better
        # is available.
        parser_self._python_agent_template_name = name or filename or "<template>"

        return orig(parser_self, environment, source, name, filename,
                    *args, **kwargs)


    # Add extra fields to the template node
    jinja2.nodes.Template.fields = ('body', '_python_agent_template_sha',
                                    '_python_agent_template_name')


    @monkeypatch("jinja2.parser.Parser.parse", timer=timer,
                 report_name="plugin.jinja2.compile.parser_parse")
    def _parse(orig, parser_self, *args, **kwargs):
        """
        Here we just copied the existing implementation here instead of
        calling the original. This gives us access to the `Template`
        instantiation.

        The goal here is to add our two extra parameters (source sha and
        name) to the Template node. We modified the Template node just
        above to accept the additional fields. When we compile the template
        we will inject these two extra variables into the generated source
        code.

        We also reset the `_python_agent_var_counter` so we can give each
        template expression a unique id that stays constant between renders
        and doesn't change due to conditionals or loops.
        """
        # Initialize the variable definition counter to 0 for this template
        parser_self._python_agent_var_counter = 0

        template_sha = parser_self._python_agent_template_sha
        template_name = parser_self._python_agent_template_name

        # Everything below is a copy of the original, except `nodes.Template`
        # has two extra python_agent-specific arguments
        result = jinja2.nodes.Template(
            parser_self.subparse(),
            template_sha,
            template_name,
            lineno=1)
        result.set_environment(parser_self.environment)
        return result


    @monkeypatch(jinja2.lexer.Lexer, "tokenize", timer=timer,
                 report_name="plugin.jinja2.compile.lexer_tokenize")
    def _tokenize(orig, tokenize_self, source, name=None, filename=None,
                  state=None):
        """
        Replaces `jinja2.lexer.Lexer.tokenize()` and does NOT call the original.

        The goal here is to observe the raw token stream from the lexer and
        grab the code for each variable definition. We use the
        `variable_begin` and `variable_end` tokens (`{{` and `}}` by default)
        to grab all the code for a variable (including the begin and end tags
        themselves in case the defaults have been changed.

        Each variable we see is appended to the `_python_agent_variables` attribute
        on the `TokenStream` instance created in this wrapper. This allows
        the variables to be accessed from the `_subparse` hook below.
        """
        # There is a circular dependency here because `_python_agent_token_iter`
        # is required to create our `TokenStream` below, but it also needs
        # to access the `TokenStream` as a holder for the extracted variables.
        # This single-element list allows `_python_agent_token_iter` to access the
        # `TokenStream` instance, even though it is defined AFTER.
        token_stream_mutable = [None]

        def _python_agent_token_iter(orig_iter):
            """
            Observes each token as it is yielded and passes it through
            unchanged. Variable blocks `{{ }}` are captured and appened to
            `TokenStream._python_agent_variables` so that they can be accessed
            from the `_subparse` hook below.
            """
            current_var = None

            for lineno, token, value in orig_iter:
                # If the `_python_agent_inside_trans_block` flag is set, we're
                # inside a `trans` template block. For those, we capture
                # the full code of the translate block and treat it as a
                # single variable.
                if (token_stream_mutable[0] and
                        token_stream_mutable[0]._python_agent_inside_trans_block):
                    token_stream_mutable[0]._python_agent_variables[-1] += value
                else:
                    # When not in a `trans` block, just capture variables
                    if token == "variable_begin":
                        current_var = [value]

                    elif token == "variable_end":
                        current_var.append(value)
                        # Grab the code and reset `current_var` for the next one
                        code = "".join(current_var)
                        token_stream_mutable[0]._python_agent_variables.append(code)
                        current_var = None

                    elif current_var is not None:
                        # Capture every token between begin and end
                        current_var.append(value)

                # Yield the original values unchanged
                yield lineno, token, value

        # Create a new token iterator for the source code
        stream = tokenize_self.tokeniter(source, name, filename, state)
        # Wrap the original iterator so we can observe the tokens flow by
        wrapped_stream = _python_agent_token_iter(stream)

        # Create a `TokenStream` using our wrapped stream.
        token_stream_mutable[0] = jinja2.lexer.TokenStream(
            tokenize_self.wrap(wrapped_stream, name, filename), name, filename)

        # Initialize the flag for handling `trans` blocks
        if not hasattr(token_stream_mutable[0], "_python_agent_inside_trans_block"):
            token_stream_mutable[0]._python_agent_inside_trans_block = False

        # This `TokenStream` is accessed by the `_python_agent_token_iter` above.
        return token_stream_mutable[0]


    import jinja2.ext
    @monkeypatch("jinja2.ext.InternationalizationExtension.parse")
    def _i18n_parse(orig, ext_self, parser):
        """
        Here we are looking for the start and end of a `{% trans %}` block.
        The `trans` block is treated as a single variable node during
        rendering but it can internally have variable nodes. During the
        `trans` block, we set the `_python_agent_inside_trans_block` flag so
        the tokenizer hook above will capture the entire text of the block,
        to use as the `code` of the resulting variable.

        We also need to initialize the code string with `{% trans` which
        are the tokens that have already been seen by the tokenizer before
        this parse function is called.
        """
        # Initialize the `_python_agent_variables` code block with the tokens
        # already seen by this point.
        block_start_string = parser.environment.block_start_string
        parser.stream._python_agent_variables.append(block_start_string + " trans")

        # Now set the `_python_agent_inside_trans_block` flag until the `trans`
        # block is finished.
        parser.stream._python_agent_inside_trans_block = True
        try:
            return orig(ext_self, parser)
        finally:
            parser.stream._python_agent_inside_trans_block = False


    @monkeypatch("jinja2.parser.Parser.subparse", timer=timer,
                 report_name="plugin.jinja2.compile.parser_subparse")
    def _subparse(orig, parser_self, *args, **kwargs):
        """
        Here we loop through all the nodes in the subparse result and wrap
        all expressions (except constants) with an python_agentVarNode.

        The python_agentVarNode doesn't render anything, but it allows us to
        pass through additional metadata during the rendering process.
        It also provides and overall group for more complex expressions
        that are inside a single {{ }}.
        """
        # During the call to subparse, the Lexer stream hook above will
        # be called. Ensure there is a place to store the data:
        if not hasattr(parser_self.stream, "_python_agent_variables"):
            parser_self.stream._python_agent_variables = []

        # This may be a nested call to `_subparse` so ignore any variables that
        # have already been captured.
        var_base_index = len(parser_self.stream._python_agent_variables)

        # Call original function
        nodes = orig(parser_self, *args, **kwargs)

        # Loop through each node looking for expressions
        for node in nodes:
            if isinstance(node, jinja2.nodes.Output):
                for i, subnode in enumerate(node.nodes):
                    # Find all the expression nodes (except literal constants)
                    if (isinstance(subnode, jinja2.nodes.Expr) and
                            not isinstance(subnode, jinja2.nodes.Literal)):
                        # Get the code for this variable. Use the
                        # `var_base_index` so we only get variables from THIS
                        # nested _subparse.
                        code = parser_self.stream._python_agent_variables.pop(
                            var_base_index)
                        # Wrap the expression node with our python_agentVarNode
                        # Include the var counter and code as well.
                        node.nodes[i] = jinja2.nodes.python_agentVarNode(
                            subnode, parser_self._python_agent_var_counter, code)
                        # Copy the internal lineno to the python_agentVarNode.
                        # Required to preserve debug_info for line numbers.
                        node.nodes[i].lineno = subnode.lineno
                        parser_self._python_agent_var_counter += 1
        return nodes


    @monkeypatch("jinja2.compiler.CodeGenerator.visit_Template", timer=timer,
                 report_name="plugin.jinja2.compile.visit_template")
    def _visit_template(orig, codegen_self, node, *args, **kwargs):
        """
        Wraps the original `visit_Template` to give us a chance to write
        two values into the global scope of the generated source code.

        This makes the template sha and the template name available
        anywhere within the generated source code.
        """
        result = orig(codegen_self, node, *args, **kwargs)
        # Add some special python_agent variables at the end
        codegen_self.writeline("# Additional metadata added by python_agent")
        codegen_self.writeline(
            "_python_agent_template_sha = '%s'" % node._python_agent_template_sha)
        codegen_self.writeline(
            "_python_agent_template_name = '%s'" % node._python_agent_template_name)
        return result

    @monkeypatch("jinja2.compiler.CodeGenerator.visit_Macro", timer=timer,
                 report_name="plugin.jinja2.compile.visit_macro")
    def _visit_macro(orig, self, node, frame):
        """
        Wrap the `visit_Macro` function in the code generator to add some
        attributes to the resulting function. These are needed for when
        macros are called directly instead of through the original template.
        """
        orig_stream = self.stream
        self.stream = StringIO()
        try:
            result = orig(self, node, frame)
            macro_sum = sha1(
                    to_bytes(self.stream.getvalue(), "utf8")).hexdigest()
            orig_stream.write(self.stream.getvalue())
        finally:
            self.stream = orig_stream

        # Jinja 2.9 adds an idtracking module and changes the format of these
        # local variable references of the format:
        # "l_%d_%s" % (frame.symbols.level, node.name)
        #
        # Although there is a frame.symbols.find_ref(), this method also checks
        # parent frames, which may not be what we want, so instead `refs` is
        # checked directly.
        try:
            # Jinja2 >= 2.9
            name = frame.symbols.refs[node.name]
        except AttributeError:
            # Jinja2 < 2.9
            name = "l_" + node.name

        # Add additional metadata as attributes of the macro function.
        self.writeline("# Additional macro metadata added by python_agent")
        self.writeline("%s._python_agent_name = \"%%s:MACRO:%s\""
                       "%%(_python_agent_template_name)" %
                       (name, node.name))
        self.writeline("%s._python_agent_sha = \"%s\"" %
                       (name, macro_sum))
        self.writeline("%s._python_agent_filename = \"%s\"" %
                       (name, self.filename or "<template>"))
        return result

    def visit_python_agentVarNode(self, node, frame):
        """
        Handle our completely custom node type when generating compiled code.

        The main idea is to "bake in" all the metadata about the template
        before it gets compiled to bytecode. This allows byte-code caching,
        provided by Jinja2 to work as expected - all the required info
        is part of the compiled source.

        The `_python_agent_var` method is defined below.
        """
        # Use `context.environment` instead of just `environment` to ensure
        # we get the _python_agent_var set by the `new_context` wrapper above.
        self.write("context.environment._python_agent_var(context.environment, ")
        # Get the original code for our sub-node
        self.visit(node.node, frame)
        # Add the template sha and name from the global scope (added by
        # our custom Template node and patched visit_Template function).
        self.write(", ")
        self.write("_python_agent_template_sha, ")
        self.write("_python_agent_template_name, ")
        # Bake in the variable index within the template, and the line number.
        self.write("%d, " % node.var_definition_index)
        self.write("%s, " % node.node.lineno)
        self.write("%r, " % node.var_code)
        self.write(')')
    # Add it to the CodeGenerator.
    jinja2.compiler.CodeGenerator.visit_python_agentVarNode = visit_python_agentVarNode


    @monkeypatch(jinja2.bccache.BytecodeCache, "get_source_checksum",
                 timer=timer,
                 report_name="plugin.jinja2.compile.get_source_checksum")
    def _get_source_checksum(orig, *args, **kwargs):
        """
        The goal here is to change the source checksum of everything in the
        BytecodeCache while python_agent is running. Cached bytecode that was
        generated without python_agent will not have the additional metadata that
        we add using the patching above.

        By changing the checksum calculation, we ensure that existing cached
        bytecode will be invalidated, and the bytecode will be regenerated
        with python_agent's additions. If python_agent is removed, the python_agent bytecode
        will become invalid, and things will go back the way they were.
        """
        original_checksum = orig(*args, **kwargs)

        # We want our modified checksum to be the same size as the original.
        # Since the original is a SHA-1, we just generate a new hash based
        # on the original. We include the agent version number here to ensure
        # bytecode generated by earlier agents is invalidated, in case the
        # format has changed in the newer agent.
        new_checksum = sha1(
            to_bytes(original_checksum, "utf8") +
            to_bytes("python_agent_" + __version__, "utf8")).hexdigest()

        return new_checksum


def add_template_render_hook(run_hook, timer, xss_disabled):
    """
    Hook the template render functions to gather per-render metadata.
    """
    import jinja2
    import jinja2.environment
    import jinja2.nodes
    import jinja2.parser
    import jinja2.runtime

    local_storage = local()


    @monkeypatch(jinja2.environment.Template, "_from_namespace", timer=timer,
                 report_name="plugin.jinja2.render.template_from_namespace")
    def _from_namespace(orig, template_cls, environment, namespace,
                        *args, **kwargs):
        """
        Here we just need to grab a copy of the template name and sha, so
        we can use them for the top-level render metadata.
        """
        template = orig(template_cls, environment, namespace, *args, **kwargs)
        # Grab our special python_agent data.
        template_name = namespace["_python_agent_template_name"]
        template_sha = namespace["_python_agent_template_sha"]


        @monkeypatch(template, "root_render_func", timer=timer,
                     report_name="plugin.jinja2.render.root_render_func",
                     skip_if=xss_disabled)
        def _root_render_func(orig, *args, **kwargs):
            # The original `root_render_func` is a generator that renders the
            # template chunk by chunk. Our processing needs the rendered output
            # as a single string, so collect up the chunks and concatenate them.
            with rendering():
                result = u"".join(orig(*args, **kwargs))

            yield post_render_result(result, template_sha, template_name,
                                     template.filename)

        return template


    @monkeypatch("jinja2.environment.Template.new_context", timer=timer,
                 report_name="plugin.jinja2.render.template_new_context")
    def _init(orig, *args, **kwargs):
        """
        Ensure that the `_python_agent_var()` method (defined below) is
        accessible from within our template code.

        We run this function whether XSS is enabled or not, to ensure that
        `context.environment._python_agent_var` is always accessible to templates.
        """
        context = orig(*args, **kwargs)
        context.environment._python_agent_var = python_agent_var
        return context


    @monkeypatch(jinja2.runtime.Macro, "__call__", timer=timer,
                 report_name="plugin.jinja2.render.macro",
                 skip_if=xss_disabled)
    def _macro_call(orig, macro_self, *args, **kwargs):
        """
        Wrap the call on a Macro so that we can handle the case where
        it's called directly instead of from a template.

        When called from a template the template render will handle the
        post_rendering, but when called directly it needs to be done
        here.
        """
        name = getattr(macro_self, "_python_agent_name", macro_self.name)
        sha = getattr(macro_self, "_python_agent_sha", None)
        filename = getattr(macro_self, "_python_agent_filename", None)

        # Anonymous `Macro` blocks are generated by the compiler for `call()`
        # blocks. Since `call()` blocks are anonymous, they can't be called
        # directly from outside the root rendering. If this is an anonymous
        # `Macro` block, just return the default output.
        #
        # We also just call the original if our metadata is missing. This
        # can happen when a macro is defined in an external pre-compiled
        # module.
        if (macro_self.name is None or
                name is None or sha is None or filename is None):
            return orig(macro_self, *args, **kwargs)

        # If the `Macro` block is named, wrap it in our rendering machinery.
        with rendering():
            result = orig(macro_self, *args, **kwargs)

        result = post_render_result(result, sha, name, filename)
        return result


    def python_agent_var(environment, val, template_sha, filename,
                    var_definition_index, lineno, code):
        """
        This helper method is called once for every variable injected
        into a page. The data is recorded and used to add our
        `python_agent-var` tags to the output.
        """
        # The `timer` param is allowed to be None. If it is None, use a
        # DummyContext() here instead to maintain the code structure.
        python_agent_var_timer = timer or DummyContext()

        with python_agent_var_timer("plugin.jinja2.render.python_agent_var"):
            # If XSS is disabled, short circuit this function and return the
            # original value unaltered.
            if xss_disabled():
                return val

            # Get a unique id for this variable replacement.
            var_instance_index = local_storage.var_instance_index
            local_storage.var_instance_index += 1

            # Grab the rendering nonce - this changes for every render.
            nonce = local_storage.render_nonce

            # Check if the value has been marked as "safe" for Jinja2
            marked_safe = hasattr(val, "__html__")

            # If a finalizer is defined on the environment, use it.
            if environment.finalize is not None:
                val = environment.finalize(val)

            # Force the value to a plain string
            val = jinja2.runtime.to_string(val)

            # If this variable contains any nested vars, remove those and
            # the associated value from `meta.vars`. There are a few cases
            # in Jinja where it would be common to have nested tags
            # (super(), macro, call, and block assignments with set).
            # Removing nested tags here covers all those cases.
            #
            # At some point we may want to revist the Lua side to handle nested
            # tags to keep some of the context we're discarding here.
            pattern = r"\{\/?python_agent-var:([0-9]+):%s}" % nonce
            tags = set(re.findall(pattern, val))
            # Remove all the nested tags from val
            val = re.sub(pattern, "", val)
            # Remove entries from `meta.vars`
            for tag in tags:
                del local_storage.var_meta[tag]

            # Record metadata about the particular variable.
            var = {
                "template_sha": template_sha,
                "template_id": str(var_definition_index),
                "nonce": nonce,
                "code": code,
                "file": filename,
                "line": lineno,
                "marked_safe": marked_safe,
            }
            local_storage.var_meta[str(var_instance_index)] = var

            # Wrap the value in our tags. Mark our tags as binary strings. This
            # ensures that if `val` is `str` coming in, we won't coerce it to
            # unicode. If `val` is already `unicode`, these binary strings will
            # be automatically converted to `unicode`.
            if isinstance(val, bytes):
                tag_body = b"python_agent-var:%d:%s" % (var_instance_index, nonce)
                result = b"{%(tag_body)s}%(val)s{/%(tag_body)s}" % {
                    "val": val,
                    "tag_body": tag_body,
                }

            else:
                tag_body = "python_agent-var:%d:%s" % (var_instance_index, nonce)
                result = "{%(tag_body)s}%(val)s{/%(tag_body)s}" % {
                    "val": val,
                    "tag_body": tag_body,
                }


            # Ensure that any data that was originally marked safe is still
            # marked safe with our tags added.
            if marked_safe:
                result = jinja2.Markup(result)

            return result

    def post_render_result(result, sha, name, origin):
        """
        Elements like Macros can be rendered both in a template, and outside of
        a template. The render_depth is used to distinguish between the two
        cases.

        This method can be called after each element is rendered, and will only
        call our hook when the full rendering is complete.
        """
        if local_storage.render_depth == 0:
            log.debug(
                "python_agent.plugin.jinja2.post_render_result"
                "name=%(name)s  result=%(result)s", {
                    "name": name,
                    "result": result,
                })
            hook_result = run_hook("template_render_done", {
                "rendered": result,
                "template_sha": sha,
                "name": name,
                "origin": origin,
                "nonce": local_storage.render_nonce,
                "vars": local_storage.var_meta,
            })

            result = hook_result.get("rendered", result)

            # If something goes wrong, the final_result may contain some python_agent
            # placeholders. As a double check, ensure they are all removed.
            result = PLACEHOLDER_REGEX.sub("", result)
        return result

    @contextmanager
    def rendering():
        # If the first time through, make sure our local storage
        # variables are present.
        if not hasattr(local_storage, "render_depth"):
            local_storage.render_depth = 0

        # If this is our main rendering starting, reset a few variables
        if local_storage.render_depth == 0:
            local_storage.var_instance_index = 0
            local_storage.var_meta = {}
            # Generate a new nonce for this rendering
            local_storage.render_nonce = hexlify(os.urandom(2)).decode('ascii')

        local_storage.render_depth += 1

        try:
            yield
        finally:
            local_storage.render_depth -= 1
