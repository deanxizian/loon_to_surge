"""Serialize remote JQ programs onto one Surge profile line."""
from __future__ import annotations

import json


def compact_jq_program(program: str) -> str:
    """Remove comments without changing strings or interpolation expressions.

    Backslash-continued comments differ between JQ 1.7 and 1.8, so reject that
    ambiguous form. Interpolations re-enter code, including nested strings
    and delimiters. Actual line breaks in string text become JSON escapes.
    Grammar and function validation remain the real jq compiler's job.
    """
    output: list[str] = []
    states = ["code"]
    closing = {"(": ")", "[": "]", "{": "}"}
    comment = False
    index = 0
    while index < len(program):
        char = program[index]
        if comment:
            if char == "\\":
                if program.startswith("\\\r\n", index):
                    raise ValueError("Remote JQ uses version-dependent backslash-continued comments")
                if program.startswith("\\\n", index):
                    raise ValueError("Remote JQ uses version-dependent backslash-continued comments")
                if program.startswith("\\\\", index):
                    index += 2
                    continue
            if char == "\n":
                comment = False
                output.append("\n")
            index += 1
            continue

        if states[-1] == '"':
            if char == "\\":
                if index + 1 == len(program):
                    raise ValueError("Unterminated escape in remote JQ string")
                following = program[index + 1]
                if following in "\r\n":
                    raise ValueError("Invalid escaped line break in remote JQ string")
                output.append(program[index:index + 2])
                if following == "(":
                    states.append(")")
                index += 2
                continue
            if char == '"':
                states.pop()
            # str.splitlines() in the profile reader also recognizes these
            # Unicode separators. Keep them inside the JQ string as escapes.
            if char in "\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029":
                output.append(json.dumps(char)[1:-1])
            else:
                output.append(char)
            index += 1
            continue

        if char == "#":
            comment = True
            index += 1
            continue
        if char == '"':
            states.append('"')
        elif char in closing:
            states.append(closing[char])
        elif char in ")]}":
            if states[-1] != char:
                raise ValueError("Mismatched delimiter in remote JQ program")
            states.pop()
        elif char in "\v\f\x1c\x1d\x1e\x85\u2028\u2029":
            raise ValueError("Invalid whitespace outside a remote JQ string")
        output.append("\n" if char == "\r" else char)
        index += 1

    if states != ["code"]:
        raise ValueError("Unterminated string or delimiter in remote JQ program")
    # Match the existing output layout for programs without inline comments.
    lines = (line.strip(" \t\r") for line in "".join(output).split("\n"))
    return " ".join(line for line in lines if line)
