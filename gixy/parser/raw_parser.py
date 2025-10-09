import logging
import crossplane
from crossplane.errors import NgxParserBaseException

LOG = logging.getLogger(__name__)


def _process_nginx_string(value):
    """
    Process nginx string escape sequences to match the old parser behavior.
    Specifically handles \" -> " conversion.
    """
    if not isinstance(value, str):
        return value
        
    # Handle escape sequences similar to the old NginxQuotedString parser
    # The old parser had: self.escCharReplacePattern = '\\\\(\'|")'
    # This means it would convert \' -> ' and \" -> "
    result = value.replace('\\"', '"').replace("\\'", "'")
    return result


def _tokenize_lua_content(content):
    """
    Treat Lua content as opaque for security analysis.
    Gixy's security plugins don't analyze Lua syntax, so we just preserve the content as-is.
    """
    if not content or not isinstance(content, str):
        return []
    
    # Return the content as a single opaque token
    # This preserves the Lua code but doesn't try to parse its internal structure
    return [content.strip()]


class ParseException(Exception):
    """Exception for parsing errors that mimics pyparsing.ParseException interface"""
    def __init__(self, msg, loc=0, lineno=1, col=1):
        super(ParseException, self).__init__(msg)
        self.msg = msg
        self.loc = loc
        self.lineno = lineno
        self.col = col


class ParseResults(list):
    """A list subclass that mimics pyparsing.ParseResults behavior"""
    def __init__(self, data=None, name=None):
        super(ParseResults, self).__init__(data or [])
        self._name = name

    def getName(self):
        return self._name

    def setName(self, name):
        self._name = name
        return self
    
    def asList(self):
        """Convert to a regular list, recursively converting nested ParseResults"""
        result = []
        for item in self:
            if isinstance(item, ParseResults):
                result.append(item.asList())
            else:
                result.append(item)
        return result


class RawParser(object):
    """
    A class that parses nginx configuration with crossplane
    """

    def parse(self, data):
        """
        Returns the parsed tree in a format compatible with the old pyparsing implementation.
        """
        if isinstance(data, bytes):
            content = data.decode('utf-8', errors='replace')
        else:
            content = data
            
        # Remove UTF-8 BOM if present (works for both bytes->string and string input)
        if content.startswith('\ufeff'):
            content = content[1:]
            
        content = content.strip()

        if not content:
            return ParseResults()

        try:
            # Since crossplane expects a filename, we need to create a temporary file
            import tempfile
            import os
            
            # Create a temporary file with the content
            with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp_file:
                temp_file.write(content)
                temp_filename = temp_file.name
            
            try:
                # Parse using crossplane with relaxed context checking for standalone configs
                parsed = crossplane.parse(
                    temp_filename, 
                    single=True, 
                    strict=False,  # Allow directives outside their normal context
                    check_ctx=False,  # Skip context validation
                    check_args=False,  # Skip argument validation
                    comments=True  # Include comments in the output
                )
                
                # Convert crossplane format to the expected format
                return self._convert_crossplane_to_parseresults(parsed)
            finally:
                # Clean up temporary file
                os.unlink(temp_filename)
            
        except NgxParserBaseException as e:
            # Convert crossplane error to ParseException format
            raise ParseException(str(e), loc=0, lineno=getattr(e, 'line', 1), col=1)
        except Exception as e:
            raise ParseException(str(e), loc=0, lineno=1, col=1)

    def _convert_crossplane_to_parseresults(self, crossplane_data):
        """
        Convert crossplane's JSON format to the ParseResults format expected by the old parser.
        """
        result = ParseResults()
        
        if not crossplane_data or 'config' not in crossplane_data:
            return result
            
        # Handle the config structure from crossplane
        config_list = crossplane_data['config']
        if not config_list:
            return result
            
        for file_data in config_list:
            if 'parsed' in file_data and file_data['parsed']:
                # Add file delimiter if this is a multi-file scenario
                if len(config_list) > 1:
                    file_delimiter = ParseResults([file_data.get('file', 'unknown')], 'file_delimiter')
                    result.append(file_delimiter)
                
                # Add parsed content
                result.extend(self._convert_blocks(file_data['parsed']))
            
        return result

    def _convert_blocks(self, blocks):
        """
        Convert crossplane blocks to ParseResults format.
        """
        result = ParseResults()

        # Validate input - blocks should be a list
        if not blocks or not isinstance(blocks, list):
            return result

        # Filter out inline comments (comments that share line numbers with directives)
        line_numbers_with_directives = set()
        for item in blocks:
            if isinstance(item, dict) and item.get('directive') != '#':
                line_numbers_with_directives.add(item.get('line'))

        filtered_blocks = []
        for item in blocks:
            # Skip non-dict items (strings, None, etc.)
            if not isinstance(item, dict):
                LOG.debug("Skipping non-dict item in blocks: {0}".format(type(item)))
                continue

            if item.get('directive') == '#':
                # Skip comments that are on the same line as directives (inline comments)
                if item.get('line') not in line_numbers_with_directives:
                    filtered_blocks.append(item)
            else:
                filtered_blocks.append(item)

        for block in filtered_blocks:
            if not isinstance(block, dict):
                continue
                
            directive_name = block.get('directive', '')
            args = [_process_nginx_string(arg) for arg in block.get('args', [])]
            
            if 'block' in block:
                # This is a block directive
                block_args = ParseResults(args)
                block_content = ParseResults(self._convert_blocks(block['block']))
                
                # Determine block type
                if directive_name == 'if':
                    # Special handling for if blocks
                    if_condition = self._parse_if_condition(args)
                    parsed_block = ParseResults([directive_name, if_condition, block_content], 'block')
                elif directive_name == 'location':
                    # Location blocks - let crossplane handle the argument parsing naturally
                    location_args = ParseResults(args)
                    parsed_block = ParseResults([directive_name, location_args, block_content], 'block')
                else:
                    # Generic block
                    parsed_block = ParseResults([directive_name, block_args, block_content], 'block')
                    
                result.append(parsed_block)
            else:
                # This is a simple directive
                if directive_name == '#':
                    # Special handling for comments
                    comment_text = block.get('comment', '').strip()
                    
                    # Check if this is a file delimiter comment
                    if comment_text.startswith('configuration file ') and comment_text.endswith(':'):
                        # Extract file path from "configuration file /path/to/file:"
                        file_path = comment_text[len('configuration file '):-1]
                        parsed_directive = ParseResults([file_path], 'file_delimiter')
                    else:
                        parsed_directive = ParseResults([comment_text], 'comment')
                elif directive_name == 'include':
                    # Special handling for include
                    parsed_directive = ParseResults([directive_name] + args, 'include')
                elif directive_name.endswith('_lua_block'):
                    # Special handling for Lua blocks - treat as block with tokenized content
                    if args and args[0]:
                        tokenized_content = _tokenize_lua_content(args[0])
                        parsed_directive = ParseResults([directive_name, [], tokenized_content], 'block')
                    else:
                        parsed_directive = ParseResults([directive_name, [], []], 'block')
                else:
                    # Regular directive
                    parsed_directive = ParseResults([directive_name] + args, 'directive')
                
                result.append(parsed_directive)
                
        return result

    def _parse_if_condition(self, args):
        """
        Parse if condition arguments to match the expected format.
        """
        if not args:
            return ParseResults()
            
        # Crossplane already parses if conditions correctly into separate arguments
        # We just need to return them as a ParseResults
        return ParseResults(args)
