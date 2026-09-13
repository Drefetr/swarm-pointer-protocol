package main

// RFC 8785 (JCS) canonical serialization, implemented iteratively so that
// deeply nested ext (§5, RC3 totality) cannot exhaust the host stack. Number
// serialization follows RFC 8785 §3.2.2.3 / ECMA-262 Number::toString, which
// is not Go's strconv default presentation.

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Canonicalize returns JCS(v) as UTF-8 bytes.
func Canonicalize(v *Value) []byte {
	var buf bytes.Buffer
	type frame struct {
		v       *Value
		opened  bool
		members []Member // object members sorted by UTF-16 name order
		idx     int
	}
	var stack []*frame
	stack = append(stack, &frame{v: v})
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		switch f.v.Kind {
		case KindArray:
			if !f.opened {
				buf.WriteByte('[')
				f.opened = true
			}
			if f.idx < len(f.v.Arr) {
				if f.idx > 0 {
					buf.WriteByte(',')
				}
				child := f.v.Arr[f.idx]
				f.idx++
				stack = append(stack, &frame{v: child})
			} else {
				buf.WriteByte(']')
				stack = stack[:len(stack)-1]
			}
		case KindObject:
			if !f.opened {
				buf.WriteByte('{')
				f.opened = true
				f.members = make([]Member, len(f.v.Obj))
				copy(f.members, f.v.Obj)
				sort.Slice(f.members, func(i, j int) bool {
					return utf16Less(f.members[i].Name, f.members[j].Name)
				})
			}
			if f.idx < len(f.members) {
				if f.idx > 0 {
					buf.WriteByte(',')
				}
				m := f.members[f.idx]
				f.idx++
				writeJSONString(&buf, m.Name)
				buf.WriteByte(':')
				stack = append(stack, &frame{v: m.Val})
			} else {
				buf.WriteByte('}')
				stack = stack[:len(stack)-1]
			}
		case KindString:
			writeJSONString(&buf, f.v.Str)
			stack = stack[:len(stack)-1]
		case KindNumber:
			buf.WriteString(FormatNumber(f.v.Num))
			stack = stack[:len(stack)-1]
		case KindBool:
			if f.v.Bool {
				buf.WriteString("true")
			} else {
				buf.WriteString("false")
			}
			stack = stack[:len(stack)-1]
		case KindNull:
			buf.WriteString("null")
			stack = stack[:len(stack)-1]
		}
	}
	return buf.Bytes()
}

// writeJSONString serializes a string per RFC 8785 §3.2.2.2: the six short
// escapes plus \u00xx (lowercase) for the remaining C0 controls; everything
// else, including all non-ASCII, is emitted as UTF-8.
func writeJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				const hex = "0123456789abcdef"
				buf.WriteByte(hex[(r>>4)&0xF])
				buf.WriteByte(hex[r&0xF])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// utf16char is the UTF-16 encoding of a single code point (one unit for the
// BMP, a surrogate pair for supplementary code points).
type utf16char struct {
	units [2]uint16
	n     int
	next  int
}

func decodeUTF16Char(s string, pos int) utf16char {
	r, size := utf8.DecodeRuneInString(s[pos:])
	if r >= 0x10000 {
		r -= 0x10000
		return utf16char{
			units: [2]uint16{uint16(0xD800 + (r >> 10)), uint16(0xDC00 + (r & 0x3FF))},
			n:     2,
			next:  pos + size,
		}
	}
	return utf16char{units: [2]uint16{uint16(r)}, n: 1, next: pos + size}
}

// utf16Less compares two strings by UTF-16 code unit order, as RFC 8785
// requires. Sorting as UTF-8 bytes diverges for supplementary-plane names
// (A.9).
func utf16Less(a, b string) bool {
	ia, ib := 0, 0
	for ia < len(a) && ib < len(b) {
		ca := decodeUTF16Char(a, ia)
		cb := decodeUTF16Char(b, ib)
		for k := 0; k < ca.n && k < cb.n; k++ {
			if ca.units[k] != cb.units[k] {
				return ca.units[k] < cb.units[k]
			}
		}
		if ca.n != cb.n {
			// Unreachable for validated UTF-8: matching leading units with
			// different lengths would require a lone surrogate. Order by
			// length for determinism only.
			return ca.n < cb.n
		}
		ia, ib = ca.next, cb.next
	}
	return len(a) < len(b)
}

// FormatNumber returns the ECMAScript Number::toString spelling of the finite
// binary64 value x (RFC 8785 §3.2.2.3). Shortest round-trip digits are taken
// from strconv and re-presented with the ECMAScript fixed/exponent thresholds.
func FormatNumber(x float64) string {
	if x == 0 {
		return "0"
	}
	neg := false
	if x < 0 {
		neg = true
		x = -x
	}
	// 'e' with precision -1 yields the shortest decimal that round-trips in
	// the form d[.ddd]e±dd.
	s := strconv.FormatFloat(x, 'e', -1, 64)
	epos := strings.IndexByte(s, 'e')
	mant := s[:epos]
	exp, _ := strconv.Atoi(s[epos+1:])
	digits := strings.Replace(mant, ".", "", 1)
	digits = strings.TrimRight(digits, "0")
	if digits == "" {
		digits = "0"
	}
	k := len(digits)
	n := exp + 1
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		if k == 1 {
			out = digits
		} else {
			out = digits[:1] + "." + digits[1:]
		}
		e := n - 1
		if e >= 0 {
			out += "e+" + strconv.Itoa(e)
		} else {
			out += "e-" + strconv.Itoa(-e)
		}
	}
	if neg {
		out = "-" + out
	}
	return out
}
