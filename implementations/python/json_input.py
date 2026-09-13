"""§6 raw JSON input: UTF-8, I-JSON, no duplicates, no -0, binary64 numbers.

The parser is iterative (explicit stack, no Python recursion). Nesting depth is
therefore bounded only by memory, as §5 requires: parser nesting limits are
local transport/resource policy and MUST NOT be used to declare an assertion
protocol-invalid.
"""

from __future__ import annotations

import math
import re
from typing import Any

NONCHARACTER = re.compile(
    r"[\ufdd0-\ufdef\ufffe\uffff]"
    r"|[\U0001fffe\U0001ffff\U0002fffe\U0002ffff"
    r"\U0003fffe\U0003ffff\U0004fffe\U0004ffff"
    r"\U0005fffe\U0005ffff\U0006fffe\U0006ffff"
    r"\U0007fffe\U0007ffff\U0008fffe\U0008ffff"
    r"\U0009fffe\U0009ffff\U000afffe\U000affff"
    r"\U000bfffe\U000bffff\U000cfffe\U000cffff"
    r"\U000dfffe\U000dffff\U000efffe\U000effff"
    r"\U000ffffe\U000fffff\U0010fffe\U0010ffff]"
)

_WS = " \t\n\r"
_DIGITS = "0123456789"
_HEX = "0123456789abcdefABCDEF"

# Stack-frame kinds for the iterative parser.
_OBJ = 0
_ARR = 1

# Parser phases.
_VALUE = 0
_KEY = 1
_COLON = 2
_OBJ_NEXT = 3
_ARR_NEXT = 4


class JsonInputError(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(reason if not detail else f"{reason}: {detail}")


class _Parser:
    """Iterative JSON parser over a decoded str.

    States: expect a value / expect an object key / expect a colon / expect
    ',' or '}' / expect ',' or ']'. An explicit stack of open containers
    replaces the call stack, so nesting depth is limited only by memory.
    """

    def __init__(self, text: str) -> None:
        self.s = text
        self.n = len(text)

    def _ws(self, i: int) -> int:
        s, n = self.s, self.n
        while i < n and s[i] in _WS:
            i += 1
        return i

    def parse_document(self) -> Any:
        s, n = self.s, self.n
        i = self._ws(0)
        if i >= n:
            raise JsonInputError("invalid-json", "empty")
        stack: list[list[Any]] = []  # frames: [_OBJ, dict, key] / [_ARR, list]
        phase = _VALUE
        value: Any = None
        have_value = False

        while True:
            if phase == _VALUE:
                i = self._ws(i)
                if i >= n:
                    raise JsonInputError("invalid-json", "unexpected end of input")
                c = s[i]
                if c == "{":
                    i += 1
                    j = self._ws(i)
                    if j < n and s[j] == "}":
                        i = j + 1
                        value = {}
                        have_value = True
                    else:
                        if j >= n or s[j] != '"':
                            raise JsonInputError("invalid-json", "object key")
                        stack.append([_OBJ, {}, None])
                        phase = _KEY
                        i = j
                        continue
                elif c == "[":
                    i += 1
                    j = self._ws(i)
                    if j < n and s[j] == "]":
                        i = j + 1
                        value = []
                        have_value = True
                    else:
                        stack.append([_ARR, []])
                        phase = _VALUE
                        i = j
                        continue
                elif c == '"':
                    value, i = self._string(i)
                    have_value = True
                elif c == "t":
                    if s[i : i + 4] != "true":
                        raise JsonInputError("invalid-json", "true")
                    i += 4
                    value = True
                    have_value = True
                elif c == "f":
                    if s[i : i + 5] != "false":
                        raise JsonInputError("invalid-json", "false")
                    i += 5
                    value = False
                    have_value = True
                elif c == "n":
                    if s[i : i + 4] != "null":
                        raise JsonInputError("invalid-json", "null")
                    i += 4
                    value = None
                    have_value = True
                elif c == "-" or "0" <= c <= "9":
                    value, i = self._number(i)
                    have_value = True
                else:
                    raise JsonInputError("invalid-json", f"byte at {i}")

                if not have_value:
                    continue
                have_value = False
                # Deliver the completed value.
                if not stack:
                    j = self._ws(i)
                    if j != n:
                        raise JsonInputError("invalid-json", "trailing data")
                    return value
                frame = stack[-1]
                if frame[0] == _OBJ:
                    key = frame[2]
                    assert key is not None
                    if key in frame[1]:
                        raise JsonInputError("duplicate-member-name", key)
                    frame[1][key] = value
                    phase = _OBJ_NEXT
                else:
                    frame[1].append(value)
                    phase = _ARR_NEXT
                continue

            if phase == _KEY:
                # At entry i points at the opening quote (checked before push,
                # or after a comma below).
                key, i = self._string(i)
                stack[-1][2] = key
                phase = _COLON
                continue

            if phase == _COLON:
                i = self._ws(i)
                if i >= n or s[i] != ":":
                    raise JsonInputError("invalid-json", "colon")
                i += 1
                phase = _VALUE
                continue

            if phase == _OBJ_NEXT:
                i = self._ws(i)
                if i >= n:
                    raise JsonInputError("invalid-json", "unterminated object")
                c = s[i]
                if c == ",":
                    i = self._ws(i + 1)
                    if i >= n or s[i] != '"':
                        raise JsonInputError("invalid-json", "object key")
                    phase = _KEY
                    continue
                if c == "}":
                    i += 1
                    frame = stack.pop()
                    value = frame[1]
                    have_value = True
                    phase = _VALUE
                    # Re-run the delivery path for the popped container.
                    if not stack:
                        j = self._ws(i)
                        if j != n:
                            raise JsonInputError("invalid-json", "trailing data")
                        return value
                    parent = stack[-1]
                    if parent[0] == _OBJ:
                        key = parent[2]
                        assert key is not None
                        if key in parent[1]:
                            raise JsonInputError("duplicate-member-name", key)
                        parent[1][key] = value
                        phase = _OBJ_NEXT
                    else:
                        parent[1].append(value)
                        phase = _ARR_NEXT
                    have_value = False
                    continue
                raise JsonInputError("invalid-json", f"object at {i}")

            if phase == _ARR_NEXT:
                i = self._ws(i)
                if i >= n:
                    raise JsonInputError("invalid-json", "unterminated array")
                c = s[i]
                if c == ",":
                    i += 1
                    phase = _VALUE
                    continue
                if c == "]":
                    i += 1
                    frame = stack.pop()
                    value = frame[1]
                    if not stack:
                        j = self._ws(i)
                        if j != n:
                            raise JsonInputError("invalid-json", "trailing data")
                        return value
                    parent = stack[-1]
                    if parent[0] == _OBJ:
                        key = parent[2]
                        assert key is not None
                        if key in parent[1]:
                            raise JsonInputError("duplicate-member-name", key)
                        parent[1][key] = value
                        phase = _OBJ_NEXT
                    else:
                        parent[1].append(value)
                        phase = _ARR_NEXT
                    continue
                raise JsonInputError("invalid-json", f"array at {i}")

            raise AssertionError("unreachable phase")

    def _string(self, i: int) -> tuple[str, int]:
        s, n = self.s, self.n
        i += 1  # skip opening quote
        chars: list[str] = []
        while i < n:
            c = s[i]
            if c == '"':
                out = "".join(chars)
                self._check_scalars(out)
                return out, i + 1
            if c == "\\":
                i += 1
                if i >= n:
                    raise JsonInputError("invalid-json", "escape")
                e = s[i]
                i += 1
                if e == '"':
                    chars.append('"')
                elif e == "\\":
                    chars.append("\\")
                elif e == "/":
                    chars.append("/")
                elif e == "b":
                    chars.append("\b")
                elif e == "f":
                    chars.append("\f")
                elif e == "n":
                    chars.append("\n")
                elif e == "r":
                    chars.append("\r")
                elif e == "t":
                    chars.append("\t")
                elif e == "u":
                    cp = self._hex4(i)
                    i += 4
                    if 0xD800 <= cp <= 0xDBFF:
                        if s[i : i + 2] != "\\u":
                            raise JsonInputError("lone-surrogate")
                        i += 2
                        trail = self._hex4(i)
                        i += 4
                        if not (0xDC00 <= trail <= 0xDFFF):
                            raise JsonInputError("lone-surrogate")
                        chars.append(chr(0x10000 + ((cp - 0xD800) << 10) + (trail - 0xDC00)))
                    elif 0xDC00 <= cp <= 0xDFFF:
                        raise JsonInputError("lone-surrogate")
                    else:
                        chars.append(chr(cp))
                else:
                    raise JsonInputError("invalid-json", "escape")
                continue
            if ord(c) <= 0x1F:
                raise JsonInputError("invalid-json", "unescaped control")
            chars.append(c)
            i += 1
        raise JsonInputError("invalid-json", "unterminated string")

    def _hex4(self, i: int) -> int:
        h = self.s[i : i + 4]
        if len(h) < 4 or any(c not in _HEX for c in h):
            raise JsonInputError("invalid-json", "\\u")
        return int(h, 16)

    def _number(self, i: int) -> tuple[float, int]:
        s, n = self.s, self.n
        start = i
        if s[i] == "-":
            i += 1
        if i >= n or not ("0" <= s[i] <= "9"):
            raise JsonInputError("invalid-json", "number")
        if s[i] == "0":
            i += 1
        else:
            while i < n and "0" <= s[i] <= "9":
                i += 1
        if i < n and s[i] == ".":
            i += 1
            if i >= n or not ("0" <= s[i] <= "9"):
                raise JsonInputError("invalid-json", "fraction")
            while i < n and "0" <= s[i] <= "9":
                i += 1
        if i < n and (s[i] == "e" or s[i] == "E"):
            i += 1
            if i < n and (s[i] == "+" or s[i] == "-"):
                i += 1
            if i >= n or not ("0" <= s[i] <= "9"):
                raise JsonInputError("invalid-json", "exponent")
            while i < n and "0" <= s[i] <= "9":
                i += 1
        token = s[start:i]
        value = float(token)
        if not math.isfinite(value):
            raise JsonInputError("non-finite-number", token)
        if value == 0.0 and token.startswith("-"):
            raise JsonInputError("negative-zero", token)
        return value, i

    def _check_scalars(self, s: str) -> None:
        for ch in s:
            o = ord(ch)
            if 0xD800 <= o <= 0xDFFF:
                raise JsonInputError("lone-surrogate")
        if NONCHARACTER.search(s):
            raise JsonInputError("noncharacter")


def parse_utf8(data: bytes) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise JsonInputError("invalid-utf8", str(e)) from e
    for ch in text:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise JsonInputError("lone-surrogate")
        if NONCHARACTER.match(ch):
            raise JsonInputError("noncharacter")
    return _Parser(text).parse_document()


def parse_object(data: bytes) -> dict:
    v = parse_utf8(data)
    if not isinstance(v, dict):
        raise JsonInputError("not-object")
    return v
