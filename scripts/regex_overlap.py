"""Conservative disjointness checks, not an ICU regex execution engine.

Compile a deliberately broader language to a small NFA. A False result proves
disjointness; unsupported syntax or resource limits always return True (unknown).
No sampled URLs are used to decide whether a module can be published.
"""
from __future__ import annotations

from functools import lru_cache
import re
from re import _constants as C, _parser as P


# ASCII after case folding, plus a bucket for all remaining Unicode characters.
ALL = (1 << 129) - 1
UNICODE = 1 << 128
MAX_STATES = 2048
MAX_PAIRS = 20000


class UnknownPattern(ValueError):
    pass


def literal_mask(value: int) -> int:
    if value > 127:
        raise UnknownPattern("non-ASCII literal")
    return 1 << ord(chr(value).lower())


def class_mask(items: list) -> int:
    mask = 0
    for op, value in items:
        if op == C.LITERAL:
            mask |= literal_mask(value)
        elif op == C.RANGE:
            if value[1] > 127:
                raise UnknownPattern("non-ASCII range")
            for char in range(value[0], value[1] + 1):
                mask |= literal_mask(char)
        elif op == C.CATEGORY:
            if value == C.CATEGORY_DIGIT:
                chars = "0123456789"
            elif value == C.CATEGORY_WORD:
                chars = "abcdefghijklmnopqrstuvwxyz0123456789_"
            elif value == C.CATEGORY_SPACE:
                chars = " \t\r\n\f\v"
            else:
                return ALL
            mask |= UNICODE
            for char in chars:
                mask |= literal_mask(ord(char))
        else:
            # In particular, do not complement a folded/approximated class.
            return ALL
    # Under ICU case folding a class may match a non-ASCII equivalent, whose
    # full case fold can contain several characters (e.g. dotted I). Widen
    # positive classes to arbitrary-length sequences and retain Unicode.
    if mask & sum(1 << ord(char) for char in "abcdefghijklmnopqrstuvwxyz"):
        mask |= UNICODE
    return mask


def edge_anchored(items: list, *, start: bool) -> bool:
    if not items:
        return False
    op, value = items[0 if start else -1]
    if op == C.AT:
        allowed = {C.AT_BEGINNING, C.AT_BEGINNING_STRING} if start else {C.AT_END, C.AT_END_STRING}
        return value in allowed
    if op == C.SUBPATTERN:
        return edge_anchored(value[-1], start=start)
    if op == C.BRANCH:
        return all(edge_anchored(branch, start=start) for branch in value[1])
    return False


class NFA:
    def __init__(self) -> None:
        self.edges: list[list[tuple[int, int]]] = []
        self.epsilon: list[set[int]] = []
        self.closures: dict[int, frozenset[int]] = {}

    def state(self) -> int:
        if len(self.edges) >= MAX_STATES:
            raise UnknownPattern("state limit")
        self.edges.append([])
        self.epsilon.append(set())
        return len(self.edges) - 1

    def sequence(self, items: list, start: int, end: int) -> None:
        current = start
        for index, (op, value) in enumerate(items):
            target = end if index == len(items) - 1 else self.state()
            if op == C.LITERAL:
                self.edges[current].append((literal_mask(value), target))
            elif op in (C.IN, C.CATEGORY, C.ANY, C.NOT_LITERAL):
                mask = class_mask(value) if op == C.IN else class_mask([(op, value)]) if op == C.CATEGORY else ALL
                self.epsilon[current].add(target)
                self.edges[current].append((mask, current))
            elif op == C.SUBPATTERN:
                if (value[1] | value[2]) & ~re.IGNORECASE:
                    raise UnknownPattern("inline flags other than i")
                self.sequence(value[-1], current, target)
            elif op == C.BRANCH:
                for branch in value[1]:
                    self.sequence(branch, current, target)
            elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
                minimum, maximum, repeated = value
                if minimum > 32 or (maximum != C.MAXREPEAT and maximum > 32):
                    raise UnknownPattern("large bounded repeat")
                cursor = current
                for _ in range(minimum):
                    next_state = self.state()
                    self.sequence(repeated, cursor, next_state)
                    cursor = next_state
                self.epsilon[cursor].add(target)
                if maximum == C.MAXREPEAT:
                    loop = self.state()
                    self.sequence(repeated, cursor, loop)
                    self.epsilon[loop].add(cursor)
                else:
                    for _ in range(maximum - minimum):
                        next_state = self.state()
                        self.sequence(repeated, cursor, next_state)
                        cursor = next_state
                        self.epsilon[cursor].add(target)
            elif op == C.AT:
                # Only outer start/end anchors are used. Ignoring other
                # assertions broadens the language and cannot prove safety.
                self.epsilon[current].add(target)
            else:
                raise UnknownPattern(f"unsupported regex operation: {op}")
            current = target
        if not items:
            self.epsilon[start].add(end)

    def closure(self, state: int) -> frozenset[int]:
        if state in self.closures:
            return self.closures[state]
        seen = {state}
        todo = [state]
        while todo:
            for target in self.epsilon[todo.pop()]:
                if target not in seen:
                    seen.add(target)
                    todo.append(target)
        result = frozenset(seen)
        self.closures[state] = result
        return result


@lru_cache(maxsize=512)
def compile_pattern(pattern: str) -> NFA:
    # ICU and Python differ for several escapes, extended-mode parsing, and
    # Unicode classes. Analyze only their shared syntax; leave the rest unknown.
    if "{{{" in pattern or any(
        escape not in "dDwWsSbBAZfnrt" for escape in re.findall(r"\\([A-Za-z0-9])", pattern)
    ):
        raise UnknownPattern("unsupported escape or module parameter")
    in_class = False
    escaped = False
    for char in pattern:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "[":
            if in_class:
                raise UnknownPattern("nested ICU character class")
            in_class = True
        elif char == "]":
            in_class = False
    if any(operator in pattern for operator in ("&&", "--", "~~")):
        raise UnknownPattern("ICU set operation")
    if "(?P" in pattern or re.search(r"\(\?[^:<=!P#)]*[amsuxL]", pattern):
        raise UnknownPattern("unsupported flags")
    parsed = P.parse(pattern)
    if parsed.state.flags & ~(re.UNICODE | re.IGNORECASE):
        raise UnknownPattern("unsupported global flags")
    nfa = NFA()
    start, end = nfa.state(), nfa.state()
    nfa.sequence(parsed, start, end)
    if not edge_anchored(parsed, start=True):
        nfa.edges[start].append((ALL, start))
    # ICU $ / \Z may also match before a final line terminator.
    tail = class_mask([(C.CATEGORY, C.CATEGORY_SPACE)]) if edge_anchored(parsed, start=False) else ALL
    nfa.edges[end].append((tail, end))
    return nfa


def patterns_may_overlap(first: str, second: str) -> bool:
    """False only when the over-approximated languages have empty intersection."""
    try:
        left, right = compile_pattern(first), compile_pattern(second)
        pending = [(0, 0)]
        seen = set(pending)
        while pending:
            a, b = pending.pop()
            ac, bc = left.closure(a), right.closure(b)
            if 1 in ac and 1 in bc:
                return True
            for x in ac:
                for y in bc:
                    for amask, adest in left.edges[x]:
                        for bmask, bdest in right.edges[y]:
                            pair = (adest, bdest)
                            if amask & bmask and pair not in seen:
                                if len(seen) >= MAX_PAIRS:
                                    return True
                                seen.add(pair)
                                pending.append(pair)
        return False
    except (UnknownPattern, re.error, RecursionError, OverflowError):
        return True
