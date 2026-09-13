"""RFC 8785 JCS. Object keys ordered by UTF-16 code units. Numbers are binary64."""

from __future__ import annotations

import math
import re
from typing import Any


class JcsError(Exception):
    pass


_SCI = re.compile(r"^(\d)(?:\.(\d+))?e([+-]\d+)$", re.I)


_REPR_SCI = re.compile(
    r"^([+-]?)(\d)(?:\.(\d+))?e([+-]?\d+)$", re.I
)
_REPR_FIXED = re.compile(
    r"^([+-]?)(\d+)(?:\.(\d+))?$"
)


def _es_number(n: float) -> str:
    """Return the ECMAScript Number::toString / JCS canonical decimal for n.

    Implements ES2022 §7.1.12.1 / RFC 8785 §3.2.2.3.

    Uses Python repr() as the shortest-round-trip source (David Gay's dtoa,
    same algorithm as V8).  Never uses the f-string precision loop, which
    can produce longer forms for some values.
    """
    if not math.isfinite(n):
        raise JcsError("non-finite")
    if n == 0.0:
        return "0"
    sign = "-" if n < 0 else ""
    n = abs(n)

    # Fast path: safe-integer range integral values.
    # For |n| < 2^53 the integer fast-path is correct because the exact
    # mathematical integer equals the ECMAScript shortest-round-trip rendering.
    # DO NOT extend this to |n| >= 2^53; for those values int(n) gives the
    # exact IEEE-754 integer which may differ from the ES shortest decimal.
    _SAFE_INT = 1 << 53  # 9007199254740992
    if n.is_integer() and n < _SAFE_INT:
        return sign + str(int(n))

    # repr(n) uses David Gay's dtoa (shortest-round-trip, same as V8).
    # Python repr always produces either:
    #   - scientific:  d.dddde±ddd  (no leading '+' on mantissa, no 'e+')
    #   - fixed:       d.dddd  or  ddddd.dddd
    # We normalise to ECMAScript NumberToString output.
    s = repr(n)  # e.g. '5.858190679279809e-244', '0.3', '1e+21', '1e-07'

    # Try scientific form first
    m = _REPR_SCI.fullmatch(s)
    if m:
        _, lead, frac, exp_s = m.groups()
        frac = frac or ""
        digits = (lead + frac).rstrip("0") or "0"
        exp = int(exp_s)
    else:
        # Fixed form: could be '0.3', '333333333.3333333', '1e+21' without sign
        # Some Python versions emit '1e+21' (scientific with '+') — handle it
        m2 = _REPR_FIXED.fullmatch(s)
        if not m2:
            # Fallback: should not occur for finite non-zero non-negative values
            raise JcsError(f"repr form: {s!r}")
        _, int_part, frac_part = m2.groups()
        frac_part = frac_part or ""
        digits = (int_part + frac_part).rstrip("0") or "0"
        exp = len(int_part) - 1  # exponent for 1.ddd form

    k = len(digits)
    # n_es is the ES exponent n such that the integer part when written in
    # fixed notation has n_es digits before the decimal point.
    n_es = exp + 1

    if 1 <= n_es <= 21:
        # Fixed notation
        if k <= n_es:
            body = digits + "0" * (n_es - k)
        else:
            body = digits[:n_es] + "." + digits[n_es:]
    elif -5 <= n_es <= 0:
        # Fixed notation with leading zeros: 0.000ddd
        body = "0." + ("0" * (-n_es)) + digits
    else:
        # Scientific notation
        exp_show = n_es - 1
        mant = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mant}e{'+' if exp_show >= 0 else ''}{exp_show}"

    return sign + body


def _escape_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canonicalize(value: Any) -> str:
    """Iterative RFC 8785 canonicalization (explicit stack, no recursion).

    Nesting depth is bounded only by memory, matching §5: deep `ext` values
    are legal and must canonicalize without hitting any interpreter stack.
    """
    out: list[str] = []
    # Markers are tuples; JSON values never are.
    _POP_ARR = ("]",)
    _POP_OBJ = ("}",)
    _COMMA = (",",)

    stack: list[Any] = [value]
    while stack:
        item = stack.pop()
        if type(item) is tuple:
            tag = item[0]
            if tag == "]":
                out.append("]")
            elif tag == "}":
                out.append("}")
            elif tag == ",":
                out.append(",")
            else:  # ("k", key): emit the escaped member name and colon
                out.append(_escape_string(item[1]) + ":")
            continue
        if item is None:
            out.append("null")
        elif item is True:
            out.append("true")
        elif item is False:
            out.append("false")
        elif isinstance(item, str):
            out.append(_escape_string(item))
        elif isinstance(item, (int, float)):
            out.append(_es_number(float(item)))
        elif isinstance(item, list):
            out.append("[")
            stack.append(_POP_ARR)
            for idx in range(len(item) - 1, -1, -1):
                stack.append(item[idx])
                if idx:
                    stack.append(_COMMA)
        elif isinstance(item, dict):
            out.append("{")
            stack.append(_POP_OBJ)
            keys = sorted(item.keys(), key=lambda k: k.encode("utf-16-be"))
            for idx in range(len(keys) - 1, -1, -1):
                k = keys[idx]
                stack.append(item[k])
                stack.append(("k", k))
                if idx:
                    stack.append(_COMMA)
        else:
            raise JcsError(f"unsupported type {type(item)!r}")
    return "".join(out)


def canonicalize_bytes(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")
