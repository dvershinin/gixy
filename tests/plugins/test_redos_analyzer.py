"""Unit tests for the ReDoS analyzer."""

from redoctor import Diagnostics

from gixy.plugins.regex_redos import RedosAnalyzer, RedosVulnerability


class TestNestedQuantifiers:
    """Test detection of nested quantifier patterns."""

    def test_plus_inside_plus(self):
        """(a+)+ is vulnerable."""
        analyzer = RedosAnalyzer("(a+)+")
        vulns = analyzer.analyze()
        assert len(vulns) > 0
        assert "Nested quantifier" in str(vulns[0])

    def test_star_inside_plus(self):
        """(a*)+ is vulnerable."""
        analyzer = RedosAnalyzer("(a*)+")
        vulns = analyzer.analyze()
        assert len(vulns) > 0
        assert "Nested quantifier" in str(vulns[0])

    def test_plus_inside_star(self):
        """(a+)* is vulnerable."""
        analyzer = RedosAnalyzer("(a+)*")
        vulns = analyzer.analyze()
        assert len(vulns) > 0
        assert "Nested quantifier" in str(vulns[0])

    def test_star_inside_star(self):
        """(a*)* is vulnerable."""
        analyzer = RedosAnalyzer("(a*)*")
        vulns = analyzer.analyze()
        assert len(vulns) > 0
        assert "Nested quantifier" in str(vulns[0])

    def test_nested_groups(self):
        """((ab)+)+ is vulnerable."""
        analyzer = RedosAnalyzer("((ab)+)+")
        vulns = analyzer.analyze()
        assert len(vulns) > 0
        assert "Nested quantifier" in str(vulns[0])

    def test_nested_with_content(self):
        """((a+).)+ has nested quantifier — `.` cannot bound `a+`."""
        analyzer = RedosAnalyzer("((a+).)+")
        vulns = analyzer.analyze()
        assert len(vulns) > 0
        assert "Nested quantifier" in str(vulns[0])

    def test_complex_nested(self):
        """^/(a+)+$ is vulnerable."""
        analyzer = RedosAnalyzer("^/(a+)+$")
        vulns = analyzer.analyze()
        assert len(vulns) > 0


class TestOverlappingAlternatives:
    """Test detection of overlapping alternatives in quantifiers."""

    def test_prefix_overlap(self):
        """(a|ab)+ has overlapping alternatives."""
        analyzer = RedosAnalyzer("(a|ab)+")
        vulns = analyzer.analyze()
        assert len(vulns) > 0
        assert "Overlapping" in str(vulns[0])

    def test_dot_overlap(self):
        """(.|a)+ - dot overlaps with everything."""
        analyzer = RedosAnalyzer("(.|a)+")
        vulns = analyzer.analyze()
        assert len(vulns) > 0

    def test_longer_prefix_overlap(self):
        """(foo|foobar)+ has overlapping alternatives."""
        analyzer = RedosAnalyzer("(foo|foobar)+")
        vulns = analyzer.analyze()
        assert len(vulns) > 0


class TestSafePatterns:
    """Test that safe patterns don't trigger false positives."""

    def test_simple_plus(self):
        """a+ is safe."""
        analyzer = RedosAnalyzer("a+")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_simple_star(self):
        """a* is safe."""
        analyzer = RedosAnalyzer("a*")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_character_class_plus(self):
        """[a-z]+ is safe."""
        analyzer = RedosAnalyzer("[a-z]+")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_bounded_quantifier(self):
        """a{1,10} is safe (bounded)."""
        analyzer = RedosAnalyzer("a{1,10}")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_non_overlapping_alternatives(self):
        """(foo|bar) without quantifier is safe."""
        analyzer = RedosAnalyzer("(foo|bar)")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_non_overlapping_alternatives_plus(self):
        """(foo|bar)+ with non-overlapping alternatives is safe."""
        analyzer = RedosAnalyzer("(foo|bar)+")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_anchored_pattern(self):
        """^[a-z]+$ is safe."""
        analyzer = RedosAnalyzer("^[a-z]+$")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_single_quantifier_group(self):
        """(abc)+ is safe - no nested quantifier."""
        analyzer = RedosAnalyzer("(abc)+")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_sequential_quantifiers(self):
        """a+b+ is safe - not nested."""
        analyzer = RedosAnalyzer("a+b+")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_real_world_safe_pattern(self):
        """^/api/v[0-9]+/users$ is safe."""
        analyzer = RedosAnalyzer("^/api/v[0-9]+/users$")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_optional_group_with_inner_quantifier(self):
        """([a-z]+/)? is safe - ? means 0 or 1 times, no exponential backtracking."""
        analyzer = RedosAnalyzer("^/([a-z]+/)?foo$")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_optional_group_real_world(self):
        """Real-world cache busting pattern should be safe."""
        analyzer = RedosAnalyzer("^/([_0-9a-zA-Z-]+/)?core/cache/busting/1/core/(.*)")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_optional_group_complex(self):
        """Complex optional group should be safe."""
        analyzer = RedosAnalyzer("^/(prefix-[a-z0-9]+)?/api/v[0-9]+$")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_bounded_outer_with_unbounded_inner(self):
        """(a+){0,1} is same as (a+)? - bounded outer, should be safe."""
        analyzer = RedosAnalyzer("(a+){0,1}")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_bounded_outer_max_2(self):
        """(a+){1,2} has bounded outer max=2, still could have some backtracking."""
        # This is a borderline case - max=2 means at most 2 repetitions
        # Not exponential but could flag as nested
        analyzer = RedosAnalyzer("(a+){1,2}")
        vulns = analyzer.analyze()
        # We allow max>1 to be flagged, so this should be flagged
        assert len(vulns) > 0

    def test_literal_boundary_inside_group(self):
        """(a+b)+ is safe — literal `b` is disjoint from the inner `a+`."""
        analyzer = RedosAnalyzer("(a+b)+")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_charclass_boundary_inside_group(self):
        """([a-z]+/)+core is safe — `/` not in [a-z]."""
        analyzer = RedosAnalyzer("([a-z]+/)+core")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_boundary_nested_subpattern(self):
        r"""((sub)+\.)+example is safe — `\.` bounds the inner (sub)+."""
        analyzer = RedosAnalyzer(r"((sub)+\.)+example")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_boundary_with_word_category(self):
        r"""(\w+/)+end is safe — `/` not in \w."""
        analyzer = RedosAnalyzer(r"(\w+/)+end")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_boundary_alternation_branches(self):
        """Every branch has a disjoint literal terminator."""
        analyzer = RedosAnalyzer("(foo[a-w]+x|bar[0-8]+9)+")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_real_world_issue99(self):
        """Issue #99: cache-busting pattern with `+` outer must clear."""
        analyzer = RedosAnalyzer("^/([_0-9a-zA-Z-]+/)+core/cache/busting/1/core/(.*)")
        vulns = analyzer.analyze()
        assert len(vulns) == 0

    def test_nested_subpattern_boundary(self):
        """((a+)b)+ is safe — `b` follows the inner SUBPATTERN containing a+."""
        analyzer = RedosAnalyzer("((a+)b)+")
        vulns = analyzer.analyze()
        assert len(vulns) == 0


class TestRealWorldVulnerablePatterns:
    """Test detection of real-world vulnerable patterns."""

    def test_email_like(self):
        """^([a-zA-Z0-9]+)+@example.com$ has nested quantifier."""
        analyzer = RedosAnalyzer("^([a-zA-Z0-9]+)+@example.com$")
        vulns = analyzer.analyze()
        assert len(vulns) > 0

    def test_classic_redos(self):
        """^(a|a)+$ is the classic ReDoS pattern."""
        analyzer = RedosAnalyzer("^(a|a)+$")
        vulns = analyzer.analyze()
        assert len(vulns) > 0

    def test_url_path_vulnerable(self):
        """^/((sub)+)+example\\.com$ - no literal boundary between iterations."""
        analyzer = RedosAnalyzer(r"^/((sub)+)+example\.com$")
        vulns = analyzer.analyze()
        assert len(vulns) > 0

    def test_outer_level_boundary_does_not_save(self):
        """`b` is outside the outer `+`; iterations of outer + are still ambiguous."""
        analyzer = RedosAnalyzer("(a+)+b")
        vulns = analyzer.analyze()
        assert len(vulns) > 0

    def test_overlapping_inner_outer(self):
        """Boundary `a` is in [a-z], so `([a-z]+a)+` is still vulnerable."""
        analyzer = RedosAnalyzer("([a-z]+a)+")
        vulns = analyzer.analyze()
        assert len(vulns) > 0

    def test_any_boundary_unsafe(self):
        """`.` matches anything (including `a`); not a safe boundary for `a+`."""
        analyzer = RedosAnalyzer("(a+.)+")
        vulns = analyzer.analyze()
        assert len(vulns) > 0

    def test_alternation_overlapping_boundary(self):
        """`x` is in `[a-z]`, so this alternation IS vulnerable."""
        analyzer = RedosAnalyzer("(foo[a-z]+x|bar[0-9]+y)+")
        vulns = analyzer.analyze()
        assert len(vulns) > 0


class TestAdjacentQuantifiers:
    """Test detection of adjacent overlapping quantifiers."""

    def test_adjacent_dot_star(self):
        """.*.*end has adjacent greedy quantifiers."""
        analyzer = RedosAnalyzer(".*.*end")
        vulns = analyzer.analyze()
        assert len(vulns) > 0
        assert "Adjacent" in str(vulns[0]) or "backtracking" in str(vulns[0])

    def test_adjacent_dot_plus(self):
        """.+.+suffix has adjacent greedy quantifiers."""
        analyzer = RedosAnalyzer(".+.+suffix")
        vulns = analyzer.analyze()
        assert len(vulns) > 0

    def test_non_adjacent_quantifiers(self):
        """.*foo.* is safe - quantifiers separated by literal."""
        analyzer = RedosAnalyzer(".*foo.*")
        vulns = analyzer.analyze()
        # This might or might not trigger depending on implementation
        # The key is it shouldn't crash
        assert isinstance(vulns, list)


class TestInvalidPatterns:
    """Test handling of invalid/unparseable patterns."""

    def test_invalid_regex(self):
        """Invalid regex should return empty list, not crash."""
        analyzer = RedosAnalyzer("(unclosed")
        vulns = analyzer.analyze()
        assert vulns == []

    def test_empty_pattern(self):
        """Empty pattern is safe."""
        analyzer = RedosAnalyzer("")
        vulns = analyzer.analyze()
        assert len(vulns) == 0


class TestVulnerabilityDetails:
    """Test that vulnerability objects have proper details."""

    def test_exponential_type(self):
        """Nested quantifiers should be marked as exponential."""
        analyzer = RedosAnalyzer("(a+)+")
        vulns = analyzer.analyze()
        assert len(vulns) > 0
        from gixy.plugins.regex_redos import RedosVulnerability

        assert vulns[0].type == RedosVulnerability.EXPONENTIAL

    def test_polynomial_type(self):
        """Overlapping alternatives should be marked as polynomial."""
        analyzer = RedosAnalyzer("(a|ab)+")
        vulns = analyzer.analyze()
        assert len(vulns) > 0
        from gixy.plugins.regex_redos import RedosVulnerability

        assert vulns[0].type == RedosVulnerability.POLYNOMIAL

    def test_attack_hint(self):
        """Vulnerabilities should have attack hints."""
        analyzer = RedosAnalyzer("(a+)+")
        vulns = analyzer.analyze()
        assert len(vulns) > 0
        assert vulns[0].attack_hint is not None


class TestDeepAnalysis:
    """Test the opt-in ReDoctor-backed analysis mode."""

    def test_deep_clears_prefix_alternative_false_positive(self):
        """(a|ab)+ has no two cycles consuming the same string."""
        analyzer = RedosAnalyzer("(a|ab)+", deep=True)
        assert analyzer.analyze() == []

    def test_deep_finds_separated_polynomial_ambiguity(self):
        """Separated stars can form an IDA chain missed by local heuristics."""
        analyzer = RedosAnalyzer(".*a.*a", deep=True)
        vulnerabilities = analyzer.analyze()
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].type == RedosVulnerability.POLYNOMIAL
        assert "ReDoctor automaton" in str(vulnerabilities[0])
        assert "O(n^4)" in str(vulnerabilities[0])
        assert "\\x00" in str(vulnerabilities[0])

    def test_deep_finds_exponential_ambiguity(self):
        analyzer = RedosAnalyzer("(a|aa)+", deep=True)
        vulnerabilities = analyzer.analyze()
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].type == RedosVulnerability.EXPONENTIAL

    def test_deep_invalid_pattern_does_not_escape(self):
        assert RedosAnalyzer("(unclosed", deep=True).analyze() == []

    def test_deep_uses_nginx_flags_and_safe_quick_profile(self, monkeypatch):
        captured = {}

        def fake_check(pattern, flags, config):
            captured.update(pattern=pattern, flags=flags, config=config)
            return Diagnostics.safe(pattern, checker="automaton")

        monkeypatch.setattr("gixy.plugins.regex_redos.redoctor_check", fake_check)
        assert RedosAnalyzer("abc", case_insensitive=True, deep=True).analyze() == []
        assert captured["pattern"] == "abc"
        assert captured["flags"].ignore_case is True
        assert captured["config"].skip_recall is True

    def test_deep_unknown_falls_back_to_nginx_heuristics(self, monkeypatch):
        monkeypatch.setattr(
            "gixy.plugins.regex_redos.redoctor_check",
            lambda pattern, flags, config: Diagnostics.unknown(pattern),
        )
        vulnerabilities = RedosAnalyzer("(a+)+", deep=True).analyze()
        assert len(vulnerabilities) == 1
        assert "Nested quantifier" in str(vulnerabilities[0])

    def test_missing_redoctor_falls_back_to_nginx_heuristics(self, monkeypatch):
        monkeypatch.setattr("gixy.plugins.regex_redos.REDOCTOR_AVAILABLE", False)
        vulnerabilities = RedosAnalyzer("(a+)+", deep=True).analyze()
        assert len(vulnerabilities) == 1
        assert "Nested quantifier" in str(vulnerabilities[0])
