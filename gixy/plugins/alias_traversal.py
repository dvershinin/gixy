import gixy
from gixy.plugins.plugin import Plugin
from gixy.core.regexp import Regexp
from gixy.core.variable import compile_script

import re

class alias_traversal(Plugin):
    """
    Insecure examples:
        location /files {
            alias /home/;
        }
        location ~ /site/(l\.)(.*) {
            alias /lol$1/$2;
        }
    """
    summary = 'Path traversal via misconfigured alias.'
    severity = gixy.severity.HIGH
    description = 'Using alias in a prefixed location that doesn\'t ends with directory separator could lead to path ' \
                  'traversal vulnerability. '
    help_url = 'https://github.com/dvershinin/gixy/blob/master/docs/en/plugins/aliastraversal.md'
    directives = ['alias']

    def audit(self, directive):
        severity = self.severity

        for location in directive.parents:
            if location.name != 'location':
                continue

            if location.modifier in ['~', '~*']:
                prev_var = None
                sets = []
                for var in compile_script(directive.path):
                    sets.append((var, prev_var, var.regexp))
                    prev_var = var

                # /images/(.*)/lol <- location_regex
                # alias /app/static/$1; < - sets[]
                # [('/app/static/', None), ('.*', '/app/static/')]
                location_regex = re.sub(r"\\(.)", r"\1", location.path)

                up_to_char = 0
                for var, prev_var, is_regex in sets:
                    if is_regex:
                        regex_to_find = '(' + str(var.value) + ')'
                        found_char = location_regex.find(regex_to_find, up_to_char)
                        if found_char < 0:
                            continue

                        up_to_char = found_char

                        pre_location_ends_with_slash = False
                        if up_to_char >= 0:
                            if location_regex[up_to_char-1] == '/' or var.must_startswith('/'):
                                pre_location_ends_with_slash = True

                        if not pre_location_ends_with_slash:
                            if str(prev_var.value)[-1] == '/':
                                if var.can_startswith('.'):
                                    if var.can_contain('/'):
                                        # location /site(.*) ~ { alias /lol/$1; }
                                        self.report_issue(directive, location, gixy.severity.HIGH)
                                    else:
                                        # location /site([^/]*) ~ { alias /lol/$1; }
                                        self.report_issue(directive, location, gixy.severity.LOW)
                            else:
                                # location /site(.*) ~ { alias /lol$1; }
                                self.report_issue(directive, location, gixy.severity.LOW)
                        else:
                            if str(prev_var.value)[-1] != '/' and not var.must_startswith('/'):
                                # location /site/(.*) ~ { alias /lol$1; }
                                self.report_issue(directive, location, gixy.severity.LOW)

            elif not location.modifier or location.modifier == '^~':
                # We need non-strict prefixed locations
                if not location.path.endswith('/'):
                    if directive.path.endswith('/'):
                        self.report_issue(directive, location, gixy.severity.HIGH)
                    else:
                        self.report_issue(directive, location, gixy.severity.LOW)
            return

    def report_issue(self, directive, location, severity):
        self.add_issue(
            severity=severity,
            directive=[directive, location]
        )
