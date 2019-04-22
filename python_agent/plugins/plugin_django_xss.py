from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from hashlib import sha1
from binascii import hexlify
from os import urandom
from threading import local
import re


from python_agent.compat import to_bytes, string_types
from python_agent.logger import log
from python_agent.patcher import monkeypatch


# Set name so plugin can be enabled and disabled.
NAME = "xss_django"
HOOKS_CALLED = ["template_render_done"]


# Match python_agent placeholders like {python_agent-var:0:1234}
PLACEHOLDER_INSIDE = r"python_agent-var:[0-9]+:[0-9a-fA-F]{4}"
PLACEHOLDER_REGEX = re.compile(r"\{\/?" + PLACEHOLDER_INSIDE + "\}")


# Constants for versions of Django. We only care about the major and minor.
V1_4 = (1, 4)
V1_5 = (1, 5)
V1_6 = (1, 6)
V1_7 = (1, 7)
V1_8 = (1, 8)
V1_9 = (1, 9)
V1_10 = (1, 10)
V1_11 = (1, 11)


class RenderContext(object):
    """
    Holds the state of the current in-progress rendering.
    """
    def __init__(self):
        self.template_vars = {}
        self.template_render_index = 0
        self.nonce = hexlify(urandom(2)).decode('ascii')
        self.template_stack = []


def add_hooks(run_hook, get_agent_func=None, timer=None):
    """
    Add our hooks into the django library functions.
    """
    try:
        import django
        import django.conf
    except ImportError:
        return None

    hook_templates(run_hook, timer)

    meta = {
        "version": django.get_version(),
    }

    return meta


def hook_templates(run_hook, timer):
    """
    Hook the Django template system to monitor output for XSS exploits.
    """
    import django


    # Many of the hooked functions have changed over time, so only hook if
    # the version matches one we test with.
    VERSION = django.VERSION[0:2]

    if VERSION < V1_4 or VERSION > V1_11:
        log.warn("Django version %(version)s not supported by python_agent", {
            "version": ".".join([str(v) for v in VERSION]),
        })
        return

    # Patch the template loading/parsing
    patch_template_parsing(timer, VERSION)

    # Patch some specific node types that need tweaks to work with python_agent's
    # tagged variable format.
    patch_filter_node(timer)
    patch_ifchanged_node(timer, VERSION)

    # Patch the actual template rendering process.
    patch_template_rendering(run_hook, timer, VERSION)


def patch_template_rendering(run_hook, timer, VERSION):
    """
    Hook the functions involved in actually rendering a template.
    """
    local_storage = local()

    import django.template.loader_tags  # pylint: disable=unused-variable

    # When a sub-template is rendered using the Include node, we need to
    # prevent starting another render context. Here we set the `is_include_node`
    # flag, so we know not to start a new context in the `Template.render`
    # monkeypatch below.
    if V1_4 <= VERSION <= V1_6:
        target = "django.template.loader_tags.BaseIncludeNode.render_template"
    else:
        target = "django.template.loader_tags.IncludeNode.render"

    @monkeypatch(target, timer=timer,
                 report_name="plugin.django.xss.IncludeNode_render")
    def _render_template(orig, *args, **kwargs):
        try:
            local_storage.is_include_node = True
            return orig(*args, **kwargs)
        finally:
            local_storage.is_include_node = False


    from django.utils.safestring import SafeText

    # Capture the beginning and end of a template being rendered. This hook
    # sets up the render context. Within the rendering, the current context
    # will be populated with variable information to be sent to Lua.
    @monkeypatch("django.template.base.Template.render", timer=timer,
                 report_name="plugin.django.xss.Template_render")
    def _render(orig, template_self, *args, **kwargs):
        # Don't start a new RenderContext for include nodes.
        if getattr(local_storage, "is_include_node", False):
            return orig(template_self, *args, **kwargs)

        # Ensure `render_context_stack` is initialized for this thread
        if getattr(local_storage, "render_context_stack", None) is None:
            local_storage.render_context_stack = []

        render_context = RenderContext()

        local_storage.render_context_stack.append(render_context)

        try:
            # Run original render
            rendered = orig(template_self, *args, **kwargs)

            result = run_hook("template_render_done", {
                "template_sha": template_self._python_agent_template_sha,
                "name": template_self._python_agent_name,
                "origin": template_self._python_agent_origin,
                "nonce": render_context.nonce,
                "vars": render_context.template_vars,
                "rendered": rendered,
            })
            # If a new render was provided in the hook response, use it instead
            rendered = result.get("rendered", rendered)

            # If something goes wrong, the final_result may contain some python_agent
            # placeholders. As a double check, ensure they are all removed.
            rendered = PLACEHOLDER_REGEX.sub("", rendered)

            # Ensure the final result is still marked as `SafeText`.
            return SafeText(rendered)
        finally:
            if not getattr(local_storage, "is_include_node", False):
                local_storage.render_context_stack.pop()


    # When templates extend other templates, we capture the transistion here,
    # by appending the current template object to the stack.
    @monkeypatch("django.template.base.Template._render", timer=timer,
                 report_name="plugin.django.xss.Template_render2")
    def _render(orig, template_self, context):
        log.debug("Template._render(%(context)s)", {
            "context": context,
            })

        render_context = local_storage.render_context_stack[-1]

        render_context.template_stack.append(template_self)
        try:
            return orig(template_self, context)
        finally:
            render_context.template_stack.pop()


    if VERSION < V1_5:
        from django.utils.timezone import localtime
        from django.utils.encoding import force_unicode
    else:
        from django.utils.timezone import template_localtime
        from django.utils.encoding import force_text
    from django.utils.formats import localize
    from django.utils.html import escape
    from django.utils.safestring import (
        SafeData,
        SafeText,
        EscapeData,
    )

    def python_agent_render_value_in_context(value, context):
        """
        Custom version of `django.template.base.render_value_in_context` that
        behaves exactly like the original, except it adds an attribute to
        the result indicating if the value was automatically escaped by Django
        or returned as-is.
        """
        # Handle minor differences in 1.4
        if VERSION < V1_5:
            value = localtime(value, use_tz=context.use_tz)
            value = localize(value, use_l10n=context.use_l10n)
            value = force_unicode(value)
        else:
            value = template_localtime(value, use_tz=context.use_tz)
            value = localize(value, use_l10n=context.use_l10n)
            value = force_text(value)

        if ((context.autoescape and not isinstance(value, SafeData)) or
                isinstance(value, EscapeData)):
            if VERSION < V1_7:
                escaped = escape(value)
                escaped._python_agent_marked_safe = False
            else:
                # v1.7 and newer consider objects with `__html__` as safe.
                if hasattr(value, '__html__'):
                    escaped = SafeText(value.__html__())
                    escaped._python_agent_marked_safe = True
                else:
                    escaped = escape(value)
                    escaped._python_agent_marked_safe = False
            return escaped
        else:
            escaped = SafeText(value)
            escaped._python_agent_marked_safe = True
            return escaped


    if VERSION < V1_9:
        # In Django 1.8 and earlier we also need to patch the DebugVariableNode.
        import django.template.base  # pylint: disable=unused-variable
        import django.template.debug
        targets = [
            "django.template.base.VariableNode.render",
            "django.template.debug.DebugVariableNode.render",
        ]
    else:
        # Django 1.9 just has the one VariableNode.
        import django.template.base
        targets = ["django.template.base.VariableNode.render"]

    for target in targets:
        @monkeypatch(target, timer=timer,
                     report_name="plugin.django.xss.VariableNode_render")
        def _render(orig, node_self, context):
            """
            Render a variable into the template output.

            NOTE: We don't call the original here - we duplicate it below to
                  get access to the intermediate `output` value before it is
                  rendered into the context.
            """
            ## START Duplicated `render()` code.
            try:
                output = node_self.filter_expression.resolve(context)
                rendered = python_agent_render_value_in_context(output, context)
            except UnicodeDecodeError:
                # Unicode conversion can fail sometimes for reasons out of our
                # control (e.g. exception rendering). In that case, we fail
                # quietly.
                rendered = SafeText('')
                rendered._python_agent_marked_safe = True
            ## FINISH Duplicated `render()` code.

            # Get attribute added by `python_agent_render_value_in_context()`
            marked_safe = rendered._python_agent_marked_safe
            delattr(rendered, "_python_agent_marked_safe")

            # Get current render context
            render_context = local_storage.render_context_stack[-1]

            # If this variable contains nested tags, don't tag this variable
            # substitution.
            # XXX In the future, we should be able to modify the Lua side to
            # handle nested tags correctly.
            if PLACEHOLDER_REGEX.search(rendered):
                # Contains nested tags, don't wrap
                return rendered

            # Assign an index to this render
            var_index = str(render_context.template_render_index)
            render_context.template_render_index += 1

            # Record the var data
            render_context.template_vars[var_index] = {
                "template_sha": node_self._python_agent_template_sha,
                "file": node_self._python_agent_file_name,
                "template_id": node_self._python_agent_template_var_id,
                "marked_safe": marked_safe,
                "nonce": render_context.nonce,
                "line": node_self._python_agent_lineno,
                "code": node_self._python_agent_code,
            }

            # Tag the rendered value
            tag = "python_agent-var:%s:%s" % (var_index, render_context.nonce)

            rendered = SafeText("{%s}%s{/%s}" % (tag, rendered, tag))
            return rendered

        # By tagging the rendered value, this changes the behavior of the
        # {% spaceless %} builtin tag so this preserves the expected behavior.
        @monkeypatch("django.utils.html.strip_spaces_between_tags", timer=timer,
                     report_name="plugin.django.xss.strip_spaces_between_tags")
        def _strip_spaces_between_tags(orig, value):
            value = orig(value)  # This already calls force_unicode
            value = re.sub(r'>\s+({python_agent-var:\d+:\w+})<', r'>\1<', value)
            value = re.sub(r'>({/python_agent-var:\d+:\w+})\s+<', r'>\1<', value)
            return value


def patch_template_parsing(timer, VERSION):
    """
    Hook the functions involved in loading and parsing a template, to ensure
    we collect all the required information.
    """
    parsing_local_storage = local()

    import django.template.base  # pylint: disable=unused-variable

    # Getting the filename reliably varies between Django versions.
    # Only required for Django < 1.9
    if V1_4 <= VERSION <= V1_7:
        import django.template.loader
        @monkeypatch("django.template.loader.make_origin", timer=timer,
                     report_name="plugin.django.xss.loader_make_origin")
        def _make_origin(orig, name, *args, **kwargs):
            parsing_local_storage.last_captured_origin = name
            return orig(name, *args, **kwargs)
    elif VERSION == V1_8:
        import django.template.engine
        @monkeypatch("django.template.engine.Engine.make_origin", timer=timer,
                     report_name="plugin.django.xss.Engine_make_origin")
        def _make_origin(orig, engine_self, name, *args, **kwargs):
            parsing_local_storage.last_captured_origin = name
            return orig(engine_self, name, *args, **kwargs)


    # Collect information about the template file itself.
    @monkeypatch("django.template.base.Template.__init__", timer=timer,
                 report_name="plugin.django.xss.Template_init")
    def _template_init(orig, template_self, template_string, *args, **kwargs):
        # Create a placeholder for the template definition id
        template_self._python_agent_template_var_index = 0

        # Compute SHA of template string
        template_self._python_agent_template_sha = sha1(
                to_bytes(template_string, "utf8")).hexdigest()

        # Initialize the template var definition index for this template
        template_self._python_agent_template_var_index = 0

        # Extract name if present
        name = None
        if len(args) > 1:
            name = args[1]
        if "name" in kwargs:
            name = kwargs["name"]
        # If no name is available, default to `<template>`
        template_self._python_agent_name = name or "<template>"

        # Extract origin if present
        origin = None
        if len(args) > 0:
            origin = args[0]
        if "origin" in kwargs:
            origin = kwargs["origin"]
        # `origin`, if specified, is an object with a `name` attribute.
        origin = getattr(origin, "name", None)

        # Django version < 1.9 only provide an Origin in debug mode, so we
        # need to use the name we captured in the `make_origin` hooks above.
        if VERSION < V1_9:
            if getattr(parsing_local_storage, "last_captured_origin", None):
                origin = parsing_local_storage.last_captured_origin
                parsing_local_storage.last_captured_origin = None
        # If no origin is available, default to `<template>`
        template_self._python_agent_origin = origin or "<template>"

        if not hasattr(parsing_local_storage, "template_init_stack"):
            parsing_local_storage.template_init_stack = []
        parsing_local_storage.template_init_stack.append(template_self)
        try:
            return orig(template_self, template_string, *args, **kwargs)
        finally:
            parsing_local_storage.template_init_stack.pop()



    # Capture information about each variable node within the template.
    from django.template.base import (
        VariableNode,
        VARIABLE_TAG_START,
        VARIABLE_TAG_END,
    )
    @monkeypatch("django.template.base.Parser.extend_nodelist", timer=timer,
                 report_name="plugin.django.xss.Parser_extend_nodelist")
    def _extend_node_list(orig, parser_self, nodelist, node, token):
        if isinstance(node, VariableNode):
            # Get current template
            template = parsing_local_storage.template_init_stack[-1]

            # Assign a unique index for this variable node
            node._python_agent_template_var_id = str(
                template._python_agent_template_var_index)
            template._python_agent_template_var_index += 1

            # Save details about this variable on the node itself.
            node._python_agent_lineno = token.lineno
            node._python_agent_file_name = template._python_agent_name
            node._python_agent_template_sha = template._python_agent_template_sha

            node._python_agent_code = "%s %s %s" % (
                VARIABLE_TAG_START, token.contents, VARIABLE_TAG_END)
        return orig(parser_self, nodelist, node, token)


def patch_filter_node(timer):
    """
    The FilterNode allows template authors to apply a filter to an
    entire block of template output. This causes some trouble because the
    block will likely contain some intermediate rendered output which may
    contain some python_agent markup tags like `{python_agent-var:1:1234}`.

    These tags interfere with filters like "FirstUpper" that capatilize the
    first letter in the block. The built-in cases operate on the first or
    last letters, so here we strip off the python_agent tags, run the filter,
    then put them back on.
    """
    import django.template.defaulttags  # pylint: disable=unused-variable

    @monkeypatch("django.template.defaulttags.FilterNode.render", timer=timer,
                 report_name="plugin.django.xss.FilterNode_render")
    def _render(orig, node_self, context, *args, **kwargs):
        # Get contents of the FilterNode
        output = node_self.nodelist.render(context)

        # Check for the common case of the filter node surrounding a variable
        enclosing_filter = re.compile(r"^{(%s)}(.*){\/(%s)}$" % (
            PLACEHOLDER_INSIDE, PLACEHOLDER_INSIDE))

        # If it matches, separate out the python_agent tags, filter the contents
        # then put the tags back on.
        pre = ""
        post = ""
        matches = enclosing_filter.findall(output)
        if matches:
            match = matches[0]
            pre, output, post = match
            pre = "{%s}" % pre
            post = "{/%s}" % post

        # Run the filter, and add back the python_agent tags if present. Note that
        # push only returns a context manager after Django 1.4.
        context_dir = context.push()
        try:
            context_dir["var"] = output
            return pre + node_self.filter_expr.resolve(context) + post
        finally:
            context.pop()


def patch_ifchanged_node(timer, VERSION):
    """
    The IfChanged block only outputs its contents if the contents are
    different then the last time through the loop. When we add our python_agent
    tags we break this behaviour because we always increment the var index
    on every insertion, so the content will ALWAYS be different.

    To fix this, we remove all the python_agent tags from the values being
    compared, but still include them in the actual output.
    """
    from django.template.base import VariableDoesNotExist
    if V1_4 <= VERSION <= V1_5:
        @monkeypatch(
            "django.template.defaulttags.IfChangedNode.render", timer=timer,
            report_name="plugin.django.xss.IfChangedNode_render")
        def _if_changed_node_render(orig, node_self, context):
            if 'forloop' in context and node_self._id not in context['forloop']:
                node_self._last_seen = None
                context['forloop'][node_self._id] = 1
            try:
                if node_self._varlist:
                    # Consider multiple parameters.  This automatically behaves
                    # like an OR evaluation of the multiple variables.
                    compare_to = [
                        var.resolve(context, True)
                        for var in node_self._varlist]
                    # REMOVE THE python_agent TAGS FROM compare_to VALUES
                    compare_to = [
                        PLACEHOLDER_REGEX.sub("", x)
                        if isinstance(x, string_types)
                        else x for x in compare_to]
                else:
                    compare_to = node_self.nodelist_true.render(context)
                    # REMOVE THE python_agent TAGS FROM compare_to VALUE
                    compare_to = (
                        PLACEHOLDER_REGEX.sub("", compare_to)
                        if isinstance(compare_to, string_types) else compare_to)
            except VariableDoesNotExist:
                compare_to = None

            if compare_to != node_self._last_seen:
                node_self._last_seen = compare_to
                content = node_self.nodelist_true.render(context)
                return content
            elif node_self.nodelist_false:
                return node_self.nodelist_false.render(context)
            return ''
    else:
        @monkeypatch(
            "django.template.defaulttags.IfChangedNode.render", timer=timer,
            report_name="plugin.django.xss.IfChangedNode_render")
        def _if_changed_node_render(orig, node_self, context):
            # Init state storage
            state_frame = node_self._get_context_stack_frame(context)
            if node_self not in state_frame:
                state_frame[node_self] = None

            nodelist_true_output = None
            try:
                if node_self._varlist:
                    # Consider multiple parameters.  This automatically behaves
                    # like an OR evaluation of the multiple variables.
                    compare_to = [
                        var.resolve(context, True)
                        for var in node_self._varlist]
                    # REMOVE THE python_agent TAGS FROM compare_to VALUES
                    compare_to = [
                        PLACEHOLDER_REGEX.sub("", x)
                        if isinstance(x, string_types)
                        else x for x in compare_to]
                else:
                    # The "{% ifchanged %}" syntax (without any variables)
                    # compares the rendered output.
                    compare_to = nodelist_true_output = (
                        node_self.nodelist_true.render(context))
                    # REMOVE THE python_agent TAGS FROM compare_to VALUE
                    compare_to = (
                        PLACEHOLDER_REGEX.sub("", compare_to)
                        if isinstance(compare_to, string_types) else compare_to)
            except VariableDoesNotExist:
                compare_to = None

            if compare_to != state_frame[node_self]:
                state_frame[node_self] = compare_to
                # render true block if not already rendered
                return (nodelist_true_output or
                        node_self.nodelist_true.render(context))
            elif node_self.nodelist_false:
                return node_self.nodelist_false.render(context)
            return ''
