import gixy
from gixy.core.issue import Fix, Issue

# Base URL for plugin documentation
DOCS_BASE_URL = "https://gixy.getpagespeed.com/checks/"


class Plugin:
    """
    Base class for all Gixy plugins.

    Plugins detect security issues in NGINX configurations.

    Class Attributes:
        summary: Short description of the issue this plugin detects.
        description: Detailed description of the issue.
        severity: Default severity level for issues from this plugin.
        directives: List of directive names this plugin audits.
        options: Plugin-specific configuration options.
        options_help: Help text for configuration options.
        supports_full_config: Whether plugin uses post_audit() for full config analysis.

    Properties:
        help_url: Auto-generated URL to documentation (override _help_url to customize).
    """

    summary = ""
    description = ""
    severity = gixy.severity.UNSPECIFIED
    directives = []
    options = {}
    options_help = {}

    # Override this to use a custom help URL (e.g., external documentation)
    _help_url = None

    # Flag to indicate plugin supports full config analysis
    supports_full_config = False
    full_config_subsystems = ("http",)

    def __init__(self, config):
        self._issues = []
        self.config = config
        self.audit_context = None

    @property
    def help_url(self):
        """Get the help URL for this plugin.

        Returns the custom _help_url if set, otherwise auto-generates from class name.
        URL format: https://gixy.getpagespeed.com/checks/{plugin-name}/
        where plugin-name is the class name with underscores replaced by dashes.
        """
        if self._help_url:
            return self._help_url
        slug = self.__class__.__name__.replace("_", "-")
        return f"{DOCS_BASE_URL}{slug}/"

    def add_issue(
        self,
        directive,
        summary=None,
        severity=None,
        description=None,
        reason=None,
        help_url=None,
        fixes=None,
    ):
        """
        Add an issue found by this plugin.

        Args:
            directive: The directive(s) involved in this issue.
            summary: Override the default summary.
            severity: Override the default severity.
            description: Override the default description.
            reason: Specific reason for this instance.
            help_url: Override the default help URL.
            fixes: List of Fix objects or a single Fix for suggested remediations.
        """
        self._issues.append(
            Issue(
                self,
                directives=directive,
                summary=summary,
                severity=severity,
                description=description,
                reason=reason,
                help_url=help_url,
                fixes=fixes,
            )
        )

    def audit(self, directive):
        """
        Audit a single directive for issues.

        Override this method in subclasses to implement the audit logic.

        Args:
            directive: The directive to audit.
        """
        pass

    def post_audit(self, root):
        """
        Called after all directives have been audited with the full config tree.

        Only called if supports_full_config is True and a full config is detected.
        Override this method for plugins that need to analyze the complete configuration.

        Args:
            root: The root of the parsed configuration tree.
        """
        pass

    @property
    def issues(self):
        """Get all issues found by this plugin."""
        return self._issues

    @property
    def name(self):
        """Get the plugin name (class name)."""
        return self.__class__.__name__

    @staticmethod
    def make_fix(title, search, replace, description=None):
        """
        Helper method to create a Fix object.

        Args:
            title: Human-readable title for the fix (shown in IDE menus).
            search: Text pattern to find in the problematic line.
            replace: Text to replace the search pattern with.
            description: Optional longer description of what the fix does.

        Returns:
            A Fix object.
        """
        return Fix(title, search, replace, description)
