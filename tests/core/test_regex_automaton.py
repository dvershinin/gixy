"""Tests for recheck-inspired automata ReDoS analysis."""

import random
import string

import pytest

from gixy.core.regex_automaton import AutomatonComplexity, AutomatonRedosAnalyzer


@pytest.mark.parametrize(
    "pattern",
    [
        "(a+)+",
        "(a|a)*",
        "(a|aa)+",
        "(a|b|ab)*",
        "(aa|b|aab)*",
    ],
)
def test_exponential_ambiguity(pattern):
    result = AutomatonRedosAnalyzer(pattern).analyze()
    assert result.kind == AutomatonComplexity.EXPONENTIAL


@pytest.mark.parametrize(
    "pattern,degree",
    [
        (".*a.*a", 2),
        ("^(.a)*a(.a)*a$", 2),
        (".*a.*a.*a", 3),
        (".*.*end", 2),
    ],
)
def test_polynomial_ambiguity_degree(pattern, degree):
    result = AutomatonRedosAnalyzer(pattern).analyze()
    assert result.kind == AutomatonComplexity.POLYNOMIAL
    assert result.degree == degree


@pytest.mark.parametrize(
    "pattern",
    [
        "(a|ab)+",
        "(a+b)+",
        "(foo|bar)+",
        "[a-z]+",
        "^(a()*a)*$",
        "^foo$",
    ],
)
def test_linear_or_constant_patterns_are_safe(pattern):
    result = AutomatonRedosAnalyzer(pattern).analyze()
    assert result.kind in (AutomatonComplexity.SAFE, AutomatonComplexity.LINEAR)


def test_unsupported_lookaround_is_unknown_without_execution():
    result = AutomatonRedosAnalyzer("(?=a)b").analyze()
    assert result.kind == AutomatonComplexity.UNKNOWN
    assert result.reason == "look-around assertion"


def test_invalid_pattern_is_unknown():
    result = AutomatonRedosAnalyzer("(unclosed").analyze()
    assert result.kind == AutomatonComplexity.UNKNOWN


def test_product_work_is_bounded():
    result = AutomatonRedosAnalyzer(".*a.*a", max_product_steps=1).analyze()
    assert result.kind == AutomatonComplexity.UNKNOWN
    assert result.reason == "automata product work limit exceeded"


def test_analyzer_can_be_reused():
    analyzer = AutomatonRedosAnalyzer(".*a.*a")
    assert analyzer.analyze().kind == AutomatonComplexity.POLYNOMIAL
    assert analyzer.analyze().kind == AutomatonComplexity.POLYNOMIAL


def test_case_insensitive_ranges_overlap():
    result = AutomatonRedosAnalyzer("([a-z]|A[a-z])*", case_insensitive=True).analyze()
    assert result.kind == AutomatonComplexity.EXPONENTIAL


def test_untrusted_pattern_fuzz_smoke_never_raises():
    """Arbitrary parser input must produce a typed result, never escape."""
    randomizer = random.Random(0)
    alphabet = string.ascii_letters + string.digits + "[](){}?+*|.^$\\-"
    valid_kinds = {
        AutomatonComplexity.SAFE,
        AutomatonComplexity.LINEAR,
        AutomatonComplexity.POLYNOMIAL,
        AutomatonComplexity.EXPONENTIAL,
        AutomatonComplexity.UNKNOWN,
    }
    for _ in range(250):
        size = randomizer.randint(0, 80)
        pattern = "".join(randomizer.choice(alphabet) for _ in range(size))
        assert AutomatonRedosAnalyzer(pattern).analyze().kind in valid_kinds
