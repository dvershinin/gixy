"""Automata-based regular-expression complexity analysis.

The implementation follows the EDA/IDA ambiguity model used by recheck:
exponential ambiguity is found with a synchronized pair product, while chains
of synchronized loops identify polynomial ambiguity.  It operates only on the
parsed expression and never executes an untrusted regular expression.
"""

from collections import defaultdict, deque
import re

from gixy.core.sre_parse import sre_constants, sre_parse
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


_MAX_CODEPOINT = 0x10FFFF
_QUANTIFIERS = (MAX_REPEAT, MIN_REPEAT)
_CATEGORY_RANGES = {
    sre_constants.CATEGORY_DIGIT: ((ord("0"), ord("9")),),
    sre_constants.CATEGORY_SPACE: tuple(
        (ord(char), ord(char)) for char in " \t\n\r\f\v"
    ),
    sre_constants.CATEGORY_WORD: (
        (ord("0"), ord("9")),
        (ord("A"), ord("Z")),
        (ord("_"), ord("_")),
        (ord("a"), ord("z")),
    ),
}
_NEGATED_CATEGORIES = {
    sre_constants.CATEGORY_NOT_DIGIT: sre_constants.CATEGORY_DIGIT,
    sre_constants.CATEGORY_NOT_SPACE: sre_constants.CATEGORY_SPACE,
    sre_constants.CATEGORY_NOT_WORD: sre_constants.CATEGORY_WORD,
}


class UnsupportedRegex(Exception):
    """Raised when safe structural analysis cannot model a regex construct."""


class AnalysisLimit(Exception):
    """Raised when a configured automata size limit is exceeded."""


class AutomatonComplexity:
    """Complexity result returned by :class:`AutomatonRedosAnalyzer`."""

    SAFE = "safe"
    LINEAR = "linear"
    POLYNOMIAL = "polynomial"
    EXPONENTIAL = "exponential"
    UNKNOWN = "unknown"

    def __init__(self, kind, degree=None, reason=None):
        self.kind = kind
        self.degree = degree
        self.reason = reason


class _Fragment:
    """Nullable/first/last properties for a position-automaton fragment."""

    def __init__(
        self,
        nullable,
        first=None,
        last=None,
        nullable_paths=None,
        first_paths=None,
        last_paths=None,
    ):
        self.nullable_paths = (
            (1 if nullable else 0) if nullable_paths is None else nullable_paths
        )
        self.nullable = self.nullable_paths > 0
        self.first = set(first or ())
        self.last = set(last or ())
        self.first_paths = first_paths or dict.fromkeys(self.first, 1)
        self.last_paths = last_paths or dict.fromkeys(self.last, 1)


def _add_path_counts(*counts):
    """Add path multiplicities, retaining only the significant 0/1/many state."""
    result = defaultdict(int)
    for mapping, multiplier in counts:
        for position, count in mapping.items():
            result[position] = min(2, result[position] + count * multiplier)
    return dict(result)


def _merge_ranges(ranges):
    """Return sorted, coalesced inclusive code-point intervals."""
    merged = []
    for start, end in sorted(ranges):
        if start > end:
            continue
        start = max(0, start)
        end = min(_MAX_CODEPOINT, end)
        if not merged or start > merged[-1][1] + 1:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return tuple((start, end) for start, end in merged)


def _complement(ranges):
    """Return the Unicode-code-point complement of ``ranges``."""
    result = []
    cursor = 0
    for start, end in _merge_ranges(ranges):
        if cursor < start:
            result.append((cursor, start - 1))
        cursor = end + 1
    if cursor <= _MAX_CODEPOINT:
        result.append((cursor, _MAX_CODEPOINT))
    return tuple(result)


def _intersects(left, right):
    """Return whether two sorted interval sets share a code point."""
    i = 0
    j = 0
    while i < len(left) and j < len(right):
        left_start, left_end = left[i]
        right_start, right_end = right[j]
        if left_end < right_start:
            i += 1
        elif right_end < left_start:
            j += 1
        else:
            return True
    return False


def _intersects_three(first, second, third):
    """Return whether three interval sets share a code point."""
    for first_start, first_end in first:
        for second_start, second_end in second:
            start = max(first_start, second_start)
            end = min(first_end, second_end)
            if start > end:
                continue
            for third_start, third_end in third:
                if max(start, third_start) <= min(end, third_end):
                    return True
    return False


class _PositionAutomatonBuilder:
    """Build an epsilon-free Glushkov position automaton from ``sre_parse``."""

    def __init__(self, case_insensitive=False, max_positions=1200):
        self.case_insensitive = case_insensitive
        self.max_positions = max_positions
        self.predicates = {}
        # Keep duplicate follow edges: two structural reasons for the same
        # transition are distinct backtracking paths (for example, the inner
        # and outer loops in ``(a+)+``).
        self.follow = defaultdict(list)
        self._next_position = 1

    def build(self, parsed):
        """Return ``(states, edges, accept_states)`` for a parsed expression."""
        fragment = self._compile_sequence(parsed)
        states = set(range(self._next_position))
        edges = []
        for position, count in fragment.first_paths.items():
            for _ in range(count):
                edges.append((0, self.predicates[position], position))
        for source, targets in self.follow.items():
            for target in targets:
                edges.append((source, self.predicates[target], target))
        accept_states = set(fragment.last)
        if fragment.nullable:
            accept_states.add(0)
        return states, edges, accept_states

    def _new_position(self, predicate):
        if self._next_position > self.max_positions:
            raise AnalysisLimit("position automaton is too large")
        position = self._next_position
        self._next_position += 1
        self.predicates[position] = predicate
        return _Fragment(False, {position}, {position})

    def _compile_sequence(self, parsed):
        result = _Fragment(True)
        for op, value in parsed:
            result = self._concatenate(result, self._compile_node(op, value))
        return result

    def _concatenate(self, left, right):
        for source, left_count in left.last_paths.items():
            for target, right_count in right.first_paths.items():
                self.follow[source].extend([target] * min(2, left_count * right_count))
        first = left.first | right.first if left.nullable else left.first
        last = right.last | left.last if right.nullable else right.last
        first_paths = _add_path_counts(
            (left.first_paths, 1),
            (right.first_paths, left.nullable_paths),
        )
        last_paths = _add_path_counts(
            (right.last_paths, 1),
            (left.last_paths, right.nullable_paths),
        )
        nullable_paths = min(2, left.nullable_paths * right.nullable_paths)
        return _Fragment(
            nullable_paths > 0,
            first,
            last,
            nullable_paths=nullable_paths,
            first_paths=first_paths,
            last_paths=last_paths,
        )

    def _alternate(self, fragments):
        nullable = any(fragment.nullable for fragment in fragments)
        first = set()
        last = set()
        nullable_paths = 0
        first_paths = {}
        last_paths = {}
        for fragment in fragments:
            first.update(fragment.first)
            last.update(fragment.last)
            nullable_paths = min(2, nullable_paths + fragment.nullable_paths)
            first_paths = _add_path_counts((first_paths, 1), (fragment.first_paths, 1))
            last_paths = _add_path_counts((last_paths, 1), (fragment.last_paths, 1))
        return _Fragment(
            nullable,
            first,
            last,
            nullable_paths=nullable_paths,
            first_paths=first_paths,
            last_paths=last_paths,
        )

    def _compile_node(self, op, value):
        if op == LITERAL:
            return self._new_position(self._literal_ranges(value))
        if op == NOT_LITERAL:
            return self._new_position(_complement(self._literal_ranges(value)))
        if op == ANY:
            return self._new_position(((0, _MAX_CODEPOINT),))
        if op == IN:
            return self._new_position(self._class_ranges(value))
        if op == CATEGORY:
            return self._new_position(self._category_ranges(value))
        if op == AT:
            return _Fragment(True)
        if op == SUBPATTERN:
            _, subpattern = value
            return self._compile_sequence(subpattern)
        if op == BRANCH:
            _, branches = value
            return self._alternate(
                [self._compile_sequence(branch) for branch in branches]
            )
        if op in _QUANTIFIERS:
            minimum, maximum, subpattern = value
            return self._compile_repeat(minimum, maximum, subpattern)
        if op in (ASSERT, ASSERT_NOT):
            raise UnsupportedRegex("look-around assertion")
        raise UnsupportedRegex(f"unsupported opcode: {op}")

    def _compile_repeat(self, minimum, maximum, subpattern):
        if maximum == sre_parse.MAXREPEAT:
            body = self._compile_sequence(subpattern)
            for source, last_count in body.last_paths.items():
                for target, first_count in body.first_paths.items():
                    count = min(2, last_count * first_count)
                    self.follow[source].extend([target] * count)
            nullable_paths = 1 if minimum == 0 else body.nullable_paths
            return _Fragment(
                minimum == 0 or body.nullable,
                body.first,
                body.last,
                nullable_paths=nullable_paths,
                first_paths=body.first_paths,
                last_paths=body.last_paths,
            )

        if maximum > 100:
            raise AnalysisLimit("bounded repeat is too large")
        result = _Fragment(True)
        for index in range(maximum):
            copy = self._compile_sequence(subpattern)
            if index >= minimum:
                copy.nullable = True
                copy.nullable_paths = max(1, copy.nullable_paths)
            result = self._concatenate(result, copy)
        return result

    def _literal_ranges(self, codepoint):
        ranges = [(codepoint, codepoint)]
        if self.case_insensitive and codepoint < 128:
            char = chr(codepoint)
            ranges.extend(
                (ord(candidate), ord(candidate))
                for candidate in {char.lower(), char.upper()}
            )
        return _merge_ranges(ranges)

    def _category_ranges(self, category):
        if category in _NEGATED_CATEGORIES:
            return _complement(_CATEGORY_RANGES[_NEGATED_CATEGORIES[category]])
        ranges = _CATEGORY_RANGES.get(category)
        if ranges is None:
            raise UnsupportedRegex("unsupported character category")
        return _merge_ranges(ranges)

    def _class_ranges(self, members):
        negate = False
        ranges = []
        for op, value in members:
            if op == NEGATE:
                negate = True
            elif op == LITERAL:
                ranges.extend(self._literal_ranges(value))
            elif op == RANGE:
                ranges.append(value)
                if self.case_insensitive and value[1] < 128:
                    for codepoint in range(value[0], value[1] + 1):
                        ranges.extend(self._literal_ranges(codepoint))
            elif op == CATEGORY:
                ranges.extend(self._category_ranges(value))
            else:
                raise UnsupportedRegex("unsupported character class member")
        ranges = _merge_ranges(ranges)
        return _complement(ranges) if negate else ranges


class AutomatonRedosAnalyzer:
    """Classify structural backtracking complexity with automata products."""

    def __init__(
        self,
        pattern,
        case_insensitive=False,
        max_positions=1200,
        max_product_states=50000,
        max_product_steps=500000,
    ):
        self.pattern = pattern
        self.case_insensitive = case_insensitive
        self.max_positions = max_positions
        self.max_product_states = max_product_states
        self.max_product_steps = max_product_steps
        self._product_steps = 0

    def analyze(self):
        """Return safe/linear, polynomial, exponential, or unknown complexity."""
        self._product_steps = 0
        try:
            flags = sre_parse.SRE_FLAG_IGNORECASE if self.case_insensitive else 0
            parsed = sre_parse.parse(self.pattern, flags)
            states, edges, accept_states = _PositionAutomatonBuilder(
                case_insensitive=self.case_insensitive,
                max_positions=self.max_positions,
            ).build(parsed)
            return self._classify(states, edges, accept_states)
        except (
            UnsupportedRegex,
            AnalysisLimit,
            re.error,
            sre_constants.error,
            ValueError,
            OverflowError,
            RecursionError,
        ) as error:
            return AutomatonComplexity(AutomatonComplexity.UNKNOWN, reason=str(error))

    def _classify(self, states, edges, accept_states):
        outgoing = defaultdict(list)
        reverse = defaultdict(set)
        for edge_id, (source, predicate, target) in enumerate(edges):
            outgoing[source].append((predicate, target, edge_id))
            reverse[target].add(source)

        reachable = self._reachable({0}, outgoing)
        productive = self._reverse_reachable(accept_states, reverse)
        active = reachable & productive
        if not active:
            return AutomatonComplexity(AutomatonComplexity.SAFE)

        components = self._strong_components(active, outgoing)
        component_for = {
            state: index
            for index, component in enumerate(components)
            for state in component
        }
        cyclic = {
            index
            for index, component in enumerate(components)
            if len(component) > 1
            or any(
                target == next(iter(component))
                for _, target, _ in outgoing[next(iter(component))]
            )
        }

        for index in cyclic:
            if self._has_exponential_ambiguity(components[index], outgoing):
                return AutomatonComplexity(AutomatonComplexity.EXPONENTIAL)

        if not cyclic:
            return AutomatonComplexity(AutomatonComplexity.SAFE)

        component_edges = defaultdict(set)
        for source in active:
            source_component = component_for[source]
            for _, target, _ in outgoing[source]:
                if target not in active:
                    continue
                target_component = component_for[target]
                if source_component != target_component:
                    component_edges[source_component].add(target_component)

        reachability = {
            index: self._component_reachable(index, component_edges)
            for index in range(len(components))
        }
        ida_edges = defaultdict(set)
        for source in cyclic:
            for target in cyclic & reachability[source]:
                if self._has_polynomial_ambiguity(
                    components[source],
                    components[target],
                    active,
                    outgoing,
                    reachability,
                    component_for,
                ):
                    ida_edges[source].add(target)

        degree = self._maximum_degree(cyclic, ida_edges)
        if degree >= 2:
            return AutomatonComplexity(AutomatonComplexity.POLYNOMIAL, degree=degree)
        return AutomatonComplexity(AutomatonComplexity.LINEAR)

    @staticmethod
    def _reachable(initial, outgoing):
        seen = set(initial)
        pending = list(initial)
        while pending:
            source = pending.pop()
            for _, target, _ in outgoing[source]:
                if target not in seen:
                    seen.add(target)
                    pending.append(target)
        return seen

    @staticmethod
    def _reverse_reachable(initial, reverse):
        seen = set(initial)
        pending = list(initial)
        while pending:
            target = pending.pop()
            for source in reverse[target]:
                if source not in seen:
                    seen.add(source)
                    pending.append(source)
        return seen

    @staticmethod
    def _strong_components(states, outgoing):
        adjacency = {
            state: {target for _, target, _ in outgoing[state] if target in states}
            for state in states
        }
        reverse = defaultdict(set)
        for source, targets in adjacency.items():
            for target in targets:
                reverse[target].add(source)

        visited = set()
        order = []
        for root in states:
            if root in visited:
                continue
            stack = [(root, False)]
            while stack:
                state, expanded = stack.pop()
                if expanded:
                    order.append(state)
                    continue
                if state in visited:
                    continue
                visited.add(state)
                stack.append((state, True))
                stack.extend(
                    (target, False)
                    for target in adjacency[state]
                    if target not in visited
                )

        components = []
        assigned = set()
        for root in reversed(order):
            if root in assigned:
                continue
            component = set()
            pending = [root]
            assigned.add(root)
            while pending:
                state = pending.pop()
                component.add(state)
                for source in reverse[state]:
                    if source not in assigned:
                        assigned.add(source)
                        pending.append(source)
            components.append(component)
        return components

    def _has_exponential_ambiguity(self, component, outgoing):
        for origin in component:
            initial = (origin, origin, False)
            pending = deque([initial])
            seen = {initial}
            while pending:
                left, right, diverged = pending.popleft()
                for left_predicate, left_target, left_id in outgoing[left]:
                    if left_target not in component:
                        continue
                    for right_predicate, right_target, right_id in outgoing[right]:
                        self._consume_product_step()
                        if right_target not in component or not _intersects(
                            left_predicate, right_predicate
                        ):
                            continue
                        next_diverged = (
                            diverged
                            or left_target != right_target
                            or left_id != right_id
                        )
                        state = (left_target, right_target, next_diverged)
                        if state == (origin, origin, True):
                            return True
                        if state not in seen:
                            seen.add(state)
                            if len(seen) > self.max_product_states:
                                raise AnalysisLimit("pair product is too large")
                            pending.append(state)
        return False

    def _has_polynomial_ambiguity(
        self,
        source_component,
        target_component,
        active,
        outgoing,
        reachability,
        component_for,
    ):
        between = {
            state
            for state in active
            if component_for[state] == component_for[next(iter(source_component))]
            or component_for[state]
            in reachability[component_for[next(iter(source_component))]]
        }
        between = {
            state
            for state in between
            if component_for[state] == component_for[next(iter(target_component))]
            or component_for[next(iter(target_component))]
            in reachability[component_for[state]]
        }

        for source in source_component:
            for target in target_component:
                initial = (source, source, target)
                goal = (source, target, target)
                pending = deque([initial])
                seen = {initial}
                while pending:
                    first, middle, third = pending.popleft()
                    for first_predicate, first_target, _ in outgoing[first]:
                        if first_target not in source_component:
                            continue
                        for middle_predicate, middle_target, _ in outgoing[middle]:
                            if middle_target not in between:
                                continue
                            for third_predicate, third_target, _ in outgoing[third]:
                                self._consume_product_step()
                                if third_target not in target_component:
                                    continue
                                if not _intersects_three(
                                    first_predicate,
                                    middle_predicate,
                                    third_predicate,
                                ):
                                    continue
                                state = (first_target, middle_target, third_target)
                                if state == goal:
                                    return True
                                if state not in seen:
                                    seen.add(state)
                                    if len(seen) > self.max_product_states:
                                        raise AnalysisLimit(
                                            "triple product is too large"
                                        )
                                    pending.append(state)
        return False

    def _consume_product_step(self):
        """Bound synchronized-product work before adversarial graphs fan out."""
        self._product_steps += 1
        if self._product_steps > self.max_product_steps:
            raise AnalysisLimit("automata product work limit exceeded")

    @staticmethod
    def _component_reachable(initial, edges):
        seen = set()
        pending = list(edges[initial])
        while pending:
            component = pending.pop()
            if component in seen:
                continue
            seen.add(component)
            pending.extend(edges[component] - seen)
        return seen

    @staticmethod
    def _maximum_degree(cyclic, ida_edges):
        cache = {}

        def degree(component):
            if component not in cache:
                cache[component] = 1 + max(
                    [degree(target) for target in ida_edges[component]] or [0]
                )
            return cache[component]

        return max(degree(component) for component in cyclic)
