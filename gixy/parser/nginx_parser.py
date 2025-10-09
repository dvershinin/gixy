import os
import glob
import logging
import fnmatch

from gixy.core.exceptions import InvalidConfiguration
from gixy.parser import raw_parser
from gixy.parser.raw_parser import ParseException
from gixy.directives import block, directive
from gixy.utils.text import to_native

LOG = logging.getLogger(__name__)


class NginxParser(object):
    def __init__(self, cwd="", allow_includes=True):
        self.cwd = cwd
        self.configs = {}
        self.is_dump = False
        self.allow_includes = allow_includes
        self.directives = {}
        self.parser = raw_parser.RawParser()
        self._init_directives()
        self._path_stack = None

    def parse_file(self, path, root=None):
        LOG.debug("Parse file: {0}".format(path))
        content = open(path).read()
        return self.parse(content=content, root=root, path_info=path)

    def parse(self, content, root=None, path_info=None):
        if path_info is not None:
            self._path_stack = path_info

        if not root:
            root = block.Root()
        try:
            parsed = self.parser.parse(content)
        except ParseException as e:
            error_msg = "char {char} (line:{line}, col:{col})".format(
                char=e.loc, line=e.lineno, col=e.col
            )
            if path_info:
                LOG.error(
                    'Failed to parse config "{file}": {error}'.format(
                        file=path_info, error=error_msg
                    )
                )
            else:
                LOG.error("Failed to parse config: {error}".format(error=error_msg))
            raise InvalidConfiguration(error_msg)

        if len(parsed) and parsed[0].getName() == "file_delimiter":
            #  Were parse nginx dump
            LOG.info("Switched to parse nginx configuration dump.")
            root_filename = self._prepare_dump(parsed)
            if self.path_info:
                self._path_stack = path_info # XXX: hack because parse() is called in tests without setting _path_stack
            self.is_dump = True
            self.cwd = os.path.dirname(root_filename)
            parsed = self.configs[root_filename]

        self.parse_block(parsed, root)
        self._path_stack = path_info
        return root

    def parse_block(self, parsed_block, parent):
        for parsed in parsed_block:
            # Skip invalid entries (strings, None, etc.)
            if not parsed or isinstance(parsed, str):
                LOG.debug("Skipping invalid parsed entry: {0}".format(repr(parsed)))
                continue

            # Check if parsed has getName method (ParseResults object)
            if not hasattr(parsed, 'getName'):
                LOG.warning("Skipping entry without getName method: {0}".format(type(parsed)))
                continue

            parsed_type = parsed.getName()
            parsed_name = parsed[0]
            parsed_args = parsed[1:]
            if parent.name in ['map', 'geo'] and parsed_type == 'directive': # Hack because included maps are treated as directives (bleh)
                if len(parsed_args) > 1:
                    error_msg = "Invalid map with {} parameters: map {} {} {{ {} {}; }};".format(len(parsed_args), parent.args[0], parent.args[1], parsed_name, ' '.join(parsed_args))
                    LOG.warn('Failed to parse "{path_info}": {error}'.format(path_info=self.path_info, error=error_msg))
                    continue

                parsed_type = 'hash_value'
            if parsed_type == "include":
                # TODO: WTF?!
                path_info = self.path_info
                self._resolve_include(parsed_args, parent)
                self._path_stack = path_info
            else:
                directive_inst = self.directive_factory(
                    parsed_type, parsed_name, parsed_args
                )
                if directive_inst:
                    parent.append(directive_inst)

    def directive_factory(self, parsed_type, parsed_name, parsed_args):
        klass = self._get_directive_class(parsed_type, parsed_name)
        if not klass:
            return None

        if klass.is_block:
            args = [to_native(v).strip() for v in parsed_args[0]]
            children = parsed_args[1]

            inst = klass(parsed_name, args)
            self.parse_block(children, inst)
            return inst
        else:
            args = [to_native(v).strip() for v in parsed_args]
            return klass(parsed_name, args)

    def _get_directive_class(self, parsed_type, parsed_name):
        if (
            parsed_type in self.directives
            and parsed_name in self.directives[parsed_type]
        ):
            return self.directives[parsed_type][parsed_name]
        elif parsed_type == "block":
            return block.Block
        elif parsed_type == "directive":
            return directive.Directive
        elif parsed_type == "hash_value":
            return directive.MapDirective
        elif parsed_type == "unparsed_block":
            LOG.warning('Skip unparseable block: "%s"', parsed_name)
            return None
        else:
            return None

    def _init_directives(self):
        self.directives["block"] = block.get_overrides()
        self.directives["directive"] = directive.get_overrides()

    def _resolve_include(self, args, parent):
        pattern = args[0]
        #  TODO(buglloc): maybe file providers?
        if self.is_dump:
            return self._resolve_dump_include(pattern=pattern, parent=parent)
        if not self.allow_includes:
            LOG.debug("Includes are disallowed, skip: {0}".format(pattern))
            return

        return self._resolve_file_include(pattern=pattern, parent=parent)

    def _resolve_file_include(self, pattern, parent):
        path = os.path.join(self.cwd, pattern)
        exists = False
        for file_path in glob.iglob(path):
            if not os.path.exists(file_path):
                continue
            exists = True
            # parse the include into current context
            self.parse_file(file_path, parent)

        if not exists:
            # Align behavior with nginx: unmatched glob patterns are not warnings
            if glob.has_magic(path):
                LOG.debug("Include pattern matched no files: {0}".format(path))
            else:
                LOG.warning("File not found: {0}".format(path))

    def _resolve_dump_include(self, pattern, parent):
        path = os.path.join(self.cwd, pattern)
        found = False
        for file_path, parsed in self.configs.items():
            if not fnmatch.fnmatch(file_path, path):
                continue
            found = True

            # Flatten includes by parsing into the current parent context.
            # We only switch the path stack for correct file attribution but keep
            # cwd unchanged (prefix-based) so relative includes inside dumps
            # resolve as they commonly do in nginx deployments.
            # This intentionally diverges from commit 0ef30ce (which switches cwd
            # to the included file directory) to avoid mis-resolving patterns like
            # sites/default.conf including conf.d/listen → /etc/nginx/conf.d/listen.
            old_stack = self._path_stack
            self._path_stack = file_path

            self.parse_block(parsed, parent)

            self._path_stack = old_stack

        if not found:
            # Align behavior with nginx: unmatched glob patterns are not warnings
            if glob.has_magic(path):
                LOG.debug("Include pattern matched no files: {0}".format(path))
            else:
                LOG.warning("File not found: {0}".format(path))

    def _prepare_dump(self, parsed_block):
        filename = ""
        root_filename = ""
        for parsed in parsed_block:
            if parsed.getName() == "file_delimiter":
                if not filename:
                    root_filename = parsed[0]
                filename = parsed[0]
                self.configs[filename] = []
                continue
            self.configs[filename].append(parsed)
        return root_filename

    @property
    def path_info(self):
        """Current file being parsed, or None."""
        return self._path_stack if self._path_stack else None
