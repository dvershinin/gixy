"""
ReDoS (Regular Expression Denial of Service) detection plugin.

This plugin analyzes regular expressions used in nginx configuration for
patterns that may cause catastrophic backtracking, leading to denial of service.

Detects:
  - Nested quantifiers: (a+)+, (a*)+, ((ab)+)+ → exponential O(2^n) backtracking
  - Overlapping alternatives: (a|ab)+, (.|x)+ → polynomial O(n^2) backtracking
  - Adjacent overlapping quantifiers: .*.*something → polynomial backtracking
  - Quantifiers in lookaheads: (?=.*a)+ → can cause issues

Example attack:
  Pattern: ^/(a+)+$
  Input: /aaaaaaaaaaaaaaaaaaaaaaaaaab
  Result: regex engine tries 2^24 paths before failing
"""

import re

try:
    from redoctor import Config as RedoctorConfig
    from redoctor import Flags as RedoctorFlags
    from redoctor import check as redoctor_check

    REDOCTOR_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised without the deep extra
    RedoctorConfig = None
    RedoctorFlags = None
    redoctor_check = None
    REDOCTOR_AVAILABLE = False

from gixy.core.sre_parse import sre_parse
from gixy.core.sre_parse.sre_parse import (
    ANY,
    ASSERT,
    ASSERT_NOT,
    AT,
    BRANCH,
    CATEGORY,
    IN,
    LITERAL,
    MAX_REPEAT,
    MIN_REPEAT,
    NEGATE,
    NOT_LITERAL,
    RANGE,
    SUBPATTERN,
)
from gixy.core.sre_parse import sre_constants

import gixy
from gixy.plugins.plugin import Plugin

# Quantifier opcodes
QUANTIFIERS = (MAX_REPEAT, MIN_REPEAT)

# Concrete character sets for the standard regex categories that we can enumerate
# safely. CATEGORY_NOT_* and locale/unicode variants stay unknown — boundary
# detection falls back to "conservative / keep flagging" for those.
_CATEGORY_CHARS = {
    sre_constants.CATEGORY_DIGIT: set("0123456789"),
    sre_constants.CATEGORY_SPACE: set(" \t\n\r\f\v"),
    sre_constants.CATEGORY_WORD: set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    ),
}


class RedosVulnerability:
    """Represents a detected ReDoS vulnerability with details."""

    EXPONENTIAL = "exponential"  # O(2^n) - very dangerous
    POLYNOMIAL = "polynomial"  # O(n^k) - dangerous

    def __init__(self, vuln_type, description, pattern_snippet=None, attack_hint=None):
        self.type = vuln_type
        self.description = description
        self.pattern_snippet = pattern_snippet
        self.attack_hint = attack_hint

    def __str__(self):
        result = self.description
        if self.attack_hint:
            result += f" (try input like: {self.attack_hint})"
        return result


class RedosAnalyzer:
    """
    Analyzes regex patterns for ReDoS vulnerabilities using sre_parse.

    This analyzer uses static analysis of the regex AST to detect patterns
    known to cause catastrophic backtracking. It requires no external
    dependencies and runs in milliseconds.

    Detection categories:

    1. NESTED QUANTIFIERS (Exponential - O(2^n))
       - (a+)+, (a*)+, (a+)*, (a*)*
       - ((ab)+)+, ((a|b)+)+
       - Any quantifier containing another quantifier

    2. OVERLAPPING ALTERNATIVES (Polynomial - O(n^k))
       - (a|ab)+ where 'a' is prefix of 'ab'
       - (.|x)+ where '.' matches 'x'
       - Regex parser optimizes (a|ab) to a(?:|b)

    3. ADJACENT OVERLAPPING QUANTIFIERS (Polynomial)
       - .*.*something - two greedy quantifiers competing
       - .+.+end - similar issue
    """

    def __init__(self, pattern, case_insensitive=False, deep=False):
        self.pattern = pattern
        self.flags = re.IGNORECASE if case_insensitive else 0
        self.case_insensitive = case_insensitive
        self.deep = deep
        self.vulnerabilities = []

    def analyze(self):
        """
        Analyze the pattern and return list of RedosVulnerability objects.
        Returns empty list if pattern is safe.
        """
        self.vulnerabilities = []

        if self.deep and REDOCTOR_AVAILABLE:
            # ReDoctor's quick profile combines automata and bounded custom-VM
            # fuzzing, but deliberately skips recall through Python's
            # backtracking regex engine. NGINX patterns can be untrusted input.
            result = redoctor_check(
                self.pattern,
                flags=RedoctorFlags(ignore_case=self.case_insensitive),
                config=RedoctorConfig.quick(),
            )
            if result.is_vulnerable:
                complexity = result.complexity
                vuln_type = RedosVulnerability.POLYNOMIAL
                if complexity.is_exponential:
                    vuln_type = RedosVulnerability.EXPONENTIAL
                return [
                    RedosVulnerability(
                        vuln_type,
                        f"ReDoctor {result.checker} analysis found "
                        f"{complexity.summary} backtracking",
                        attack_hint=str(result.attack_pattern),
                    )
                ]
            if result.is_safe:
                return []

        try:
            parsed = sre_parse.parse(self.pattern, self.flags)
        except (re.error, Exception):
            # If we can't parse it, we can't analyze it
            return []

        # Check for various vulnerability patterns
        self._check_nested_quantifiers(parsed, depth=0, in_quantifier=False)
        self._check_overlapping_alternatives(parsed)
        self._check_adjacent_quantifiers(parsed)

        return self.vulnerabilities

    def _check_nested_quantifiers(self, parsed, depth, in_quantifier, tail=None):
        """Recursively check for nested quantifiers (exponential backtracking).

        An inner unbounded quantifier inside an outer unbounded quantifier is
        safe when the chars that MUST be consumed immediately after it are
        disjoint from the inner quantifier's own char set — the boundary
        prevents ambiguous splits between iterations.

        Args:
            parsed: Parsed regex element list at the current scope.
            depth: Current recursion depth (informational).
            in_quantifier: True if we are inside the body of an unbounded
                outer quantifier and any unbounded quantifier we find is a
                potential nested-quantifier ReDoS.
            tail: Chars that must be consumed immediately after the last
                element of ``parsed``. ``None`` means unknown/unrestricted.
        """
        for i, (op, av) in enumerate(parsed):
            if op in QUANTIFIERS:
                min_repeat, max_repeat, subpattern = av
                can_repeat_multiple = (
                    max_repeat > 1 or max_repeat == sre_parse.MAXREPEAT
                )

                if can_repeat_multiple:
                    if in_quantifier:
                        boundary = self._next_or_inherited(parsed, i, tail)
                        if not self._is_safe_boundary(subpattern, boundary):
                            self.vulnerabilities.append(
                                RedosVulnerability(
                                    RedosVulnerability.EXPONENTIAL,
                                    "Nested quantifier detected - causes exponential O(2^n) backtracking",
                                    attack_hint="repeat the matching char many times + non-matching char",
                                )
                            )
                            return
                        # Safe boundary on this inner quantifier — keep recursing
                        # in case it itself contains a deeper unsafe nesting.
                        body_tail = self._body_tail(subpattern, parsed, i, tail)
                        self._check_nested_quantifiers(
                            subpattern, depth + 1, in_quantifier=True, tail=body_tail
                        )
                    else:
                        body_tail = self._body_tail(subpattern, parsed, i, tail)
                        if self._contains_quantifier(subpattern, tail=body_tail):
                            self.vulnerabilities.append(
                                RedosVulnerability(
                                    RedosVulnerability.EXPONENTIAL,
                                    "Nested quantifier in group - causes exponential O(2^n) backtracking",
                                    attack_hint="repeat the matching char many times + non-matching char",
                                )
                            )
                            return
                        self._check_nested_quantifiers(
                            subpattern, depth + 1, in_quantifier=True, tail=body_tail
                        )
                else:
                    self._check_nested_quantifiers(
                        subpattern, depth + 1, in_quantifier=in_quantifier, tail=tail
                    )

            elif op == SUBPATTERN:
                _, subpattern = av
                sub_tail = self._next_or_inherited(parsed, i, tail)
                self._check_nested_quantifiers(
                    subpattern, depth + 1, in_quantifier, tail=sub_tail
                )

            elif op == BRANCH:
                _, branches = av
                sub_tail = self._next_or_inherited(parsed, i, tail)
                for branch in branches:
                    self._check_nested_quantifiers(
                        branch, depth + 1, in_quantifier, tail=sub_tail
                    )

            elif op in (ASSERT, ASSERT_NOT):
                _, subpattern = av
                # Lookarounds do not consume input; do not propagate tail.
                self._check_nested_quantifiers(
                    subpattern, depth + 1, in_quantifier, tail=None
                )

    def _contains_quantifier(self, parsed, tail=None):
        """Check whether ``parsed`` contains an unbounded quantifier without a safe boundary.

        Args:
            parsed: Parsed regex element list to inspect.
            tail: Chars that must be consumed immediately after the last
                element of ``parsed``; used as the boundary for a quantifier
                that sits at the end of ``parsed``.

        Returns:
            True if an unsafe unbounded quantifier is found.
        """
        for i, (op, av) in enumerate(parsed):
            if op in QUANTIFIERS:
                min_repeat, max_repeat, subpattern = av
                if max_repeat > 1 or max_repeat == sre_parse.MAXREPEAT:
                    boundary = self._next_or_inherited(parsed, i, tail)
                    if not self._is_safe_boundary(subpattern, boundary):
                        return True
            elif op == SUBPATTERN:
                _, subpattern = av
                sub_tail = self._next_or_inherited(parsed, i, tail)
                if self._contains_quantifier(subpattern, tail=sub_tail):
                    return True
            elif op == BRANCH:
                _, branches = av
                sub_tail = self._next_or_inherited(parsed, i, tail)
                for branch in branches:
                    if self._contains_quantifier(branch, tail=sub_tail):
                        return True
            elif op in (ASSERT, ASSERT_NOT):
                _, subpattern = av
                if self._contains_quantifier(subpattern, tail=None):
                    return True
        return False

    def _next_or_inherited(self, parsed, i, inherited_tail):
        """Required first chars after ``parsed[i]``, falling back to ``inherited_tail``.

        Args:
            parsed: Parent element list.
            i: Index of the element whose successor boundary is needed.
            inherited_tail: Tail inherited from the enclosing scope.

        Returns:
            A set of chars, or None if undetermined.
        """
        after = self._required_first_chars(parsed[i + 1 :])
        if after:
            return after
        return inherited_tail

    def _body_tail(self, body, parent_parsed, i, inherited_tail):
        """Boundary chars for the END of an unbounded quantifier's body.

        Between iterations the engine restarts the body — so the chars that
        bound an inner quantifier at end-of-body are the union of the body's
        own first chars (next-iteration start) and whatever tail follows the
        outer quantifier in its parent scope.
        """
        outer_tail = self._next_or_inherited(parent_parsed, i, inherited_tail)
        body_first = self._required_first_chars(body)
        if body_first is None:
            return None
        if not body_first:
            return outer_tail
        if outer_tail is None:
            return body_first
        return body_first | outer_tail

    def _is_safe_boundary(self, quant_body, boundary):
        """True if the quantifier body's chars are disjoint from ``boundary``.

        Args:
            quant_body: Subpattern of the quantifier (MAX_REPEAT/MIN_REPEAT body).
            boundary: Required-first-chars set immediately following the
                quantifier in its context, or None if undetermined.

        Returns:
            True if the boundary is concrete and provably disjoint from the
            quantifier's first chars, False otherwise (conservative).
        """
        if not boundary:
            return False
        inner = self._required_first_chars(quant_body)
        if not inner:
            return False
        return boundary.isdisjoint(inner)

    def _required_first_chars(self, parsed):
        """Chars that MUST be consumed when matching ``parsed`` starts.

        Returns:
            A set of chars (possibly empty when ``parsed`` is empty), or
            ``None`` when the leading element can match a class we cannot
            enumerate (ANY, NOT_LITERAL, negated/unknown CATEGORY, etc.).
        """
        if not parsed:
            return set()
        op, av = parsed[0]
        if op == LITERAL:
            return {chr(av)}
        if op in (ANY, NOT_LITERAL):
            return None
        if op == IN:
            return self._in_chars(av)
        if op == AT:
            return self._required_first_chars(parsed[1:])
        if op == SUBPATTERN:
            _, sub = av
            sub_chars = self._required_first_chars(sub)
            if sub_chars is None:
                return None
            if not sub_chars:
                return self._required_first_chars(parsed[1:])
            return sub_chars
        if op == BRANCH:
            _, branches = av
            all_chars = set()
            for branch in branches:
                chars = self._required_first_chars(branch)
                if chars is None:
                    return None
                if not chars:
                    rest = self._required_first_chars(parsed[1:])
                    if rest is None:
                        return None
                    return (all_chars | rest) if all_chars else rest
                all_chars |= chars
            return all_chars
        if op in QUANTIFIERS:
            min_repeat, _, sub = av
            sub_chars = self._required_first_chars(sub)
            if min_repeat == 0:
                rest = self._required_first_chars(parsed[1:])
                if sub_chars is None or rest is None:
                    return None
                return sub_chars | rest
            if sub_chars is None:
                return None
            if not sub_chars:
                return self._required_first_chars(parsed[1:])
            return sub_chars
        if op in (ASSERT, ASSERT_NOT):
            return self._required_first_chars(parsed[1:])
        return None

    def _in_chars(self, members):
        """Enumerate the chars matched by a parsed IN clause.

        Args:
            members: The IN clause's child list (LITERAL/RANGE/CATEGORY/NEGATE).

        Returns:
            A set of chars, or ``None`` when negated or containing an
            un-enumerable CATEGORY (CATEGORY_NOT_*, locale/unicode variants).
        """
        chars = set()
        for inner_op, inner_av in members:
            if inner_op == NEGATE:
                return None
            if inner_op == LITERAL:
                chars.add(chr(inner_av))
            elif inner_op == RANGE:
                chars |= {chr(c) for c in range(inner_av[0], inner_av[1] + 1)}
            elif inner_op == CATEGORY:
                cat_chars = _CATEGORY_CHARS.get(inner_av)
                if cat_chars is None:
                    return None
                chars |= cat_chars
            else:
                return None
        return chars or None

    def _check_overlapping_alternatives(self, parsed, in_quantifier=False):
        """
        Check for overlapping alternatives with quantifiers - causes POLYNOMIAL backtracking.

        Examples:
        - (a|ab)+   → Python optimizes to a(?:|b)+, empty branch causes backtracking
        - (.|x)+    → '.' matches 'x', so alternatives overlap
        - (foo|foobar)+ → 'foo' is prefix of 'foobar'
        """
        for op, av in parsed:
            if op in QUANTIFIERS:
                min_repeat, max_repeat, subpattern = av
                can_repeat = (
                    max_repeat > min_repeat or max_repeat == sre_parse.MAXREPEAT
                )

                if can_repeat:
                    if self._has_overlapping_branch(subpattern):
                        self.vulnerabilities.append(
                            RedosVulnerability(
                                RedosVulnerability.POLYNOMIAL,
                                "Overlapping alternatives in quantified group - causes polynomial O(n²) backtracking",
                                attack_hint="repeat the common prefix many times",
                            )
                        )
                        return
                    self._check_overlapping_alternatives(subpattern, in_quantifier=True)
                else:
                    self._check_overlapping_alternatives(subpattern, in_quantifier)

            elif op == SUBPATTERN:
                _, subpattern = av
                self._check_overlapping_alternatives(subpattern, in_quantifier)

            elif op == BRANCH:
                _, branches = av
                if in_quantifier and self._branches_overlap(branches):
                    self.vulnerabilities.append(
                        RedosVulnerability(
                            RedosVulnerability.POLYNOMIAL,
                            "Overlapping alternatives in quantified group - causes polynomial O(n²) backtracking",
                            attack_hint="repeat the common prefix many times",
                        )
                    )
                    return
                for branch in branches:
                    self._check_overlapping_alternatives(branch, in_quantifier)

    def _check_adjacent_quantifiers(self, parsed, prev_was_greedy_quantifier=False):
        """
        Check for adjacent quantifiers that can match overlapping content.

        Examples:
        - .*.*end    → two greedy .* compete for the same characters
        - .+.+suffix → similar issue
        - [a-z]*[a-z]*done → overlapping character classes
        """
        for i, (op, av) in enumerate(parsed):
            if op in QUANTIFIERS:
                min_repeat, max_repeat, subpattern = av
                can_be_greedy = max_repeat == sre_parse.MAXREPEAT or max_repeat > 1

                # Check if this quantifier matches "anything" (. or broad class)
                matches_anything = self._matches_broad_input(subpattern)

                if prev_was_greedy_quantifier and can_be_greedy and matches_anything:
                    self.vulnerabilities.append(
                        RedosVulnerability(
                            RedosVulnerability.POLYNOMIAL,
                            "Adjacent greedy quantifiers matching overlapping content - causes polynomial backtracking",
                            attack_hint="long string of matching characters without the expected suffix",
                        )
                    )
                    return

                prev_was_greedy_quantifier = can_be_greedy and matches_anything
                self._check_adjacent_quantifiers(subpattern, False)

            elif op == SUBPATTERN:
                _, subpattern = av
                self._check_adjacent_quantifiers(subpattern, prev_was_greedy_quantifier)

            elif op == BRANCH:
                _, branches = av
                for branch in branches:
                    self._check_adjacent_quantifiers(branch, prev_was_greedy_quantifier)
            else:
                # Reset after non-quantifier
                prev_was_greedy_quantifier = False

    def _matches_broad_input(self, parsed):
        """Check if pattern matches a broad range of input (like . or [^x])."""
        if len(parsed) != 1:
            return False
        op, av = parsed[0]
        if op == ANY:
            return True
        if op == NOT_LITERAL:
            return True  # [^x] matches almost everything
        if op == IN:
            # Check if it's a negated class or very broad
            for inner_op, inner_av in av:
                if inner_op == CATEGORY:
                    return True  # \w, \d, \s are fairly broad
            # Check size of character class
            char_count = 0
            for inner_op, inner_av in av:
                if inner_op == LITERAL:
                    char_count += 1
                elif inner_op == RANGE:
                    char_count += inner_av[1] - inner_av[0] + 1
            if char_count > 10:  # Arbitrary threshold for "broad"
                return True
        return False

    def _has_overlapping_branch(self, parsed):
        """Check if pattern contains a BRANCH with overlapping or empty alternatives."""
        for op, av in parsed:
            if op == BRANCH:
                _, branches = av
                # Empty branch = Python's optimization of (a|ab) → a(?:|b)
                for branch in branches:
                    if len(branch) == 0:
                        return True
                if self._branches_overlap(branches):
                    return True
            elif op == SUBPATTERN:
                _, subpattern = av
                if self._has_overlapping_branch(subpattern):
                    return True
            elif op in QUANTIFIERS:
                _, _, subpattern = av
                if self._has_overlapping_branch(subpattern):
                    return True
        return False

    def _branches_overlap(self, branches):
        """
        Check if any branches in an alternation can match the same input.
        """
        if len(branches) < 2:
            return False

        # Check for '.' (ANY) in any branch
        for branch in branches:
            if self._contains_any(branch):
                return True

        # Check for overlapping first characters
        first_chars = []
        for branch in branches:
            chars = self._get_first_chars(branch)
            if chars is None:
                return True
            first_chars.append(chars)

        for i, chars1 in enumerate(first_chars):
            for chars2 in first_chars[i + 1 :]:
                if chars1 & chars2:
                    return True

        return False

    def _contains_any(self, parsed):
        """Check if pattern contains ANY (.) matcher."""
        for op, av in parsed:
            if op == ANY:
                return True
            elif op == SUBPATTERN:
                _, subpattern = av
                if self._contains_any(subpattern):
                    return True
            elif op == BRANCH:
                _, branches = av
                for branch in branches:
                    if self._contains_any(branch):
                        return True
            elif op in QUANTIFIERS:
                _, _, subpattern = av
                if self._contains_any(subpattern):
                    return True
        return False

    def _get_first_chars(self, parsed):
        """Get possible first characters. Returns None if could match anything."""
        if not parsed:
            return set()

        op, av = parsed[0]

        if op == LITERAL:
            return {chr(av)}
        elif op in (NOT_LITERAL, ANY):
            return None
        elif op == IN:
            chars = set()
            for inner_op, inner_av in av:
                if inner_op == LITERAL:
                    chars.add(chr(inner_av))
                elif inner_op == RANGE:
                    for c in range(inner_av[0], inner_av[1] + 1):
                        chars.add(chr(c))
                elif inner_op == CATEGORY:
                    return None
            return chars if chars else None
        elif op == SUBPATTERN:
            _, subpattern = av
            return self._get_first_chars(subpattern)
        elif op == BRANCH:
            _, branches = av
            all_chars = set()
            for branch in branches:
                chars = self._get_first_chars(branch)
                if chars is None:
                    return None
                all_chars |= chars
            return all_chars
        elif op in QUANTIFIERS:
            min_repeat, _, subpattern = av
            if min_repeat == 0 and len(parsed) > 1:
                sub_chars = self._get_first_chars(subpattern)
                next_chars = self._get_first_chars(parsed[1:])
                if sub_chars is None or next_chars is None:
                    return None
                return sub_chars | next_chars
            return self._get_first_chars(subpattern)
        elif op == AT:
            return self._get_first_chars(parsed[1:]) if len(parsed) > 1 else set()

        return None


class regex_redos(Plugin):
    r"""
    🛡️ ReDoS (Regular Expression Denial of Service) Detection

    Detects regex patterns that can cause catastrophic backtracking,
    allowing attackers to DoS your nginx server with minimal resources.

    ═══════════════════════════════════════════════════════════════════
    VULNERABILITY TYPES DETECTED
    ═══════════════════════════════════════════════════════════════════

    1. NESTED QUANTIFIERS (Exponential - O(2^n)) 🔴 CRITICAL
       location ~ ^/(a+)+$
       location ~ ^/((ab)*)+$
       → Input "/aaaaaaaaaaaaaaab" tries 2^n paths

    2. OVERLAPPING ALTERNATIVES (Polynomial - O(n²)) 🟠 HIGH
       location ~ ^/(a|ab)+$
       location ~ ^/(.|x)+$
       → Alternatives match same input, causing backtracking

    3. ADJACENT QUANTIFIERS (Polynomial) 🟠 HIGH
       location ~ ^/.*.*end$
       → Two greedy quantifiers compete for same characters

    ═══════════════════════════════════════════════════════════════════
    SAFE PATTERNS
    ═══════════════════════════════════════════════════════════════════

       location ~ ^/[a-z]+$          # Simple character class ✓
       location ~ ^/\d{1,10}$        # Bounded quantifier ✓
       location ~ ^/(foo|bar)$       # Non-overlapping alternatives ✓
       location = /exact             # Exact match (no regex) ✓

    ═══════════════════════════════════════════════════════════════════

    Analysis runs in milliseconds.
    """

    summary = "Regex vulnerable to ReDoS (Regular Expression Denial of Service)"
    severity = gixy.severity.HIGH
    description = (
        "Regular expressions with nested quantifiers or overlapping alternatives "
        "can cause catastrophic backtracking, allowing attackers to consume excessive "
        "CPU resources with specially crafted requests. A single malicious request "
        "can tie up an nginx worker for minutes or longer."
    )
    directives = ["location", "if", "rewrite", "server_name", "map"]
    options = {"deep": False}
    options_help = {
        "deep": (
            "Use ReDoctor automata and bounded custom-VM fuzzing to find "
            "exponential and higher-degree polynomial ambiguity. Requires "
            "the gixy-ng[deep] extra."
        )
    }

    def __init__(self, config):
        super(regex_redos, self).__init__(config)
        self.deep = bool(self.config.get("deep"))

    def audit(self, directive):
        """Extract regex patterns from directive and check for ReDoS vulnerabilities."""

        patterns = self._extract_patterns(directive)

        for pattern, context in patterns:
            if not pattern:
                continue

            case_insensitive = self._is_case_insensitive(directive, context)

            analyzer = RedosAnalyzer(pattern, case_insensitive, deep=self.deep)
            vulnerabilities = analyzer.analyze()

            if vulnerabilities:
                vuln = vulnerabilities[0]
                severity = gixy.severity.HIGH
                if vuln.type == RedosVulnerability.EXPONENTIAL:
                    severity = gixy.severity.HIGH  # Could make CRITICAL if we had it

                reason = f"Regex `{pattern}` is vulnerable: {vuln}"
                self.add_issue(directive=directive, reason=reason, severity=severity)

    def _extract_patterns(self, directive):
        """
        Extract regex patterns from various directive types.
        Returns list of (pattern, context) tuples.
        """
        patterns = []

        if directive.name == "location":
            if directive.modifier in ("~", "~*"):
                patterns.append((directive.path, "location"))

        elif directive.name == "if":
            if directive.operand in ("~", "~*", "!~", "!~*"):
                patterns.append((directive.value, "if"))

        elif directive.name == "rewrite":
            if hasattr(directive, "pattern") and directive.pattern:
                patterns.append((directive.pattern, "rewrite"))

        elif directive.name == "server_name":
            for arg in directive.args:
                if arg.startswith("~"):
                    pattern = arg[1:]
                    if pattern.startswith("*"):
                        pattern = pattern[1:]
                    patterns.append((pattern, "server_name"))

        elif directive.name == "map":
            # Map blocks can have regex keys
            if hasattr(directive, "children"):
                for child in directive.children:
                    if hasattr(child, "source") and child.source:
                        src = child.source
                        if src.startswith("~"):
                            pattern = src[1:]
                            if pattern.startswith("*"):
                                pattern = pattern[1:]
                            patterns.append((pattern, "map"))

        return patterns

    def _is_case_insensitive(self, directive, context):
        """Determine if the regex is case-insensitive."""
        if directive.name == "location":
            return directive.modifier == "~*"
        elif directive.name == "if":
            return directive.operand in ("~*", "!~*")
        elif directive.name == "server_name":
            for arg in directive.args:
                if arg.startswith("~*"):
                    return True
        elif context == "map":
            return True  # Map regex keys with ~* are case insensitive
        return False
