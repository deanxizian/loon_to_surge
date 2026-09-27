"""Tokenization shared by conversion preflight and output validation."""


def tokenize_surge_line(line: str) -> list[str]:
    tokens: list[str] = []
    token: list[str] = []
    quote = ""
    escaped = False
    token_started = False

    for char in line:
        if escaped:
            token.append(char)
            escaped = False
            token_started = True
            continue
        if quote and char == "\\":
            token.append(char)
            escaped = True
            token_started = True
            continue
        if char in ("'", '"'):
            if quote == char:
                quote = ""
            elif not quote:
                quote = char
                token_started = True
            else:
                token.append(char)
            continue
        if char.isspace() and not quote:
            if token_started:
                tokens.append("".join(token))
                token = []
                token_started = False
            continue
        token.append(char)
        token_started = True

    if quote:
        raise ValueError("unclosed quote")
    if escaped:
        raise ValueError("trailing escape")
    if token_started:
        tokens.append("".join(token))
    return tokens
