package main

// I-JSON input scanner and value model for SPP v1.
//
// Everything in this file is hand-written and iterative. We deliberately do
// not use encoding/json: §6 requires raw-byte duplicate-name detection,
// strict UTF-8 validation, rejection of lone surrogates, noncharacters,
// non-finite numbers and negative zero, and it must survive nesting depths
// that reach ~175k levels under the 1 MiB canonical-body bound (§5, RC3
// totality). A recursive parser would blow the host stack.

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Kind classifies a parsed JSON value.
type Kind int

const (
	KindNull Kind = iota
	KindBool
	KindNumber
	KindString
	KindArray
	KindObject
)

// Member is one object member. Names are unique (duplicates are a parse
// error), and source order is preserved for diagnostics only; JCS sorts.
type Member struct {
	Name string
	Val  *Value
}

// Value is a parsed JSON value. Numbers are held as IEEE-754 binary64 (§6:
// all JSON number tokens are converted to their binary64 value before SPP
// predicates).
type Value struct {
	Kind Kind
	Bool bool
	Num  float64
	Str  string
	Arr  []*Value
	Obj  []Member
}

// Get returns the member with the given name, or nil.
func (v *Value) Get(name string) *Value {
	if v == nil || v.Kind != KindObject {
		return nil
	}
	for i := range v.Obj {
		if v.Obj[i].Name == name {
			return v.Obj[i].Val
		}
	}
	return nil
}

// Has reports whether the object has a member with the given name.
func (v *Value) Has(name string) bool {
	return v.Get(name) != nil
}

// parseError carries a §5 reason token for a JSON-input rejection.
type parseError struct{ reason string }

func (e *parseError) Error() string { return e.reason }

var (
	errInvalidJSON  = &parseError{"invalid-json"}
	errInvalidUTF8  = &parseError{"invalid-utf8"}
	errNotObject    = &parseError{"not-object"}
	errDuplicate    = &parseError{"duplicate-member-name"}
	errLoneSurrogate = &parseError{"lone-surrogate"}
	errNoncharacter = &parseError{"noncharacter"}
	errNegativeZero = &parseError{"negative-zero"}
	errNonFinite    = &parseError{"non-finite-number"}
)

// isNoncharacter reports whether r is a Unicode noncharacter (I-JSON / RFC
// 7493; spec §6 lists U+FDD0 explicitly). The set is U+FDD0..U+FDEF plus the
// final two code points of every plane (U+xFFFE, U+xFFFF).
func isNoncharacter(r rune) bool {
	if r >= 0xFDD0 && r <= 0xFDEF {
		return true
	}
	return r&0xFFFE == 0xFFFE
}

// ParseIJSON parses an SPP §6 input byte string. It validates UTF-8, rejects a
// leading BOM, requires a single top-level JSON object, and applies the I-JSON
// rules. The returned value is the received object including any top-level
// "id"/"sig" members.
func ParseIJSON(data []byte) (*Value, error) {
	// Leading BOM is not JSON whitespace and is explicitly rejected (spec §6).
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return nil, errInvalidJSON
	}
	// Strict whole-input UTF-8 validation. utf8.Valid rejects overlong forms,
	// surrogate encodings and code points above U+10FFFF.
	if !utf8.Valid(data) {
		return nil, errInvalidUTF8
	}
	p := &parser{data: data}
	p.skipWS()
	if p.pos >= len(data) {
		return nil, errInvalidJSON
	}
	root, err := p.parseDocument()
	if err != nil {
		return nil, err
	}
	if root.Kind != KindObject {
		return nil, errNotObject
	}
	return root, nil
}

type parser struct {
	data []byte
	pos  int
}

func (p *parser) skipWS() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) parseDocument() (*Value, error) {
	// Parse the single top-level value and ensure only whitespace follows.
	v, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.data) {
		return nil, errInvalidJSON
	}
	return v, nil
}

// tokenKind identifies a structural or scalar token.
type tokenKind int

const (
	tokObjOpen tokenKind = iota
	tokObjClose
	tokArrOpen
	tokArrClose
	tokComma
	tokColon
	tokScalar
)

type token struct {
	kind tokenKind
	val  *Value  // for tokScalar
	str  string  // for scalar values/keys if string; unused
	name string  // object member name for tokScalar? not used
}

// Tokenize converts the input into a flat token slice. This keeps the parser
// itself iterative with an explicit stack and no host recursion at all.
func (p *parser) tokenize() ([]token, error) {
	toks := make([]token, 0, len(p.data)/4+1)
	for {
		p.skipWS()
		if p.pos >= len(p.data) {
			return toks, nil
		}
		c := p.data[p.pos]
		switch c {
		case '{':
			toks = append(toks, token{kind: tokObjOpen})
			p.pos++
		case '}':
			toks = append(toks, token{kind: tokObjClose})
			p.pos++
		case '[':
			toks = append(toks, token{kind: tokArrOpen})
			p.pos++
		case ']':
			toks = append(toks, token{kind: tokArrClose})
			p.pos++
		case ',':
			toks = append(toks, token{kind: tokComma})
			p.pos++
		case ':':
			toks = append(toks, token{kind: tokColon})
			p.pos++
		case '"':
			s, err := p.parseString()
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{kind: tokScalar, val: &Value{Kind: KindString, Str: s}})
		case 't':
			if !p.literal("true") {
				return nil, errInvalidJSON
			}
			toks = append(toks, token{kind: tokScalar, val: &Value{Kind: KindBool, Bool: true}})
		case 'f':
			if !p.literal("false") {
				return nil, errInvalidJSON
			}
			toks = append(toks, token{kind: tokScalar, val: &Value{Kind: KindBool, Bool: false}})
		case 'n':
			if !p.literal("null") {
				return nil, errInvalidJSON
			}
			toks = append(toks, token{kind: tokScalar, val: &Value{Kind: KindNull}})
		default:
			if c == '-' || (c >= '0' && c <= '9') {
				v, err := p.parseNumber()
				if err != nil {
					return nil, err
				}
				toks = append(toks, token{kind: tokScalar, val: v})
			} else {
				return nil, errInvalidJSON
			}
		}
	}
}

func (p *parser) literal(s string) bool {
	if p.pos+len(s) > len(p.data) {
		return false
	}
	if string(p.data[p.pos:p.pos+len(s)]) != s {
		return false
	}
	p.pos += len(s)
	return true
}

func (p *parser) parseValue() (*Value, error) {
	toks, err := p.tokenize()
	if err != nil {
		return nil, err
	}
	return buildValue(toks)
}

// buildValue assembles a token stream into a tree using an explicit stack.
func buildValue(toks []token) (*Value, error) {
	type phase int
	const (
		objKeyOrClose phase = iota
		objKey
		objColon
		objValue
		objCommaOrClose
		arrValOrClose
		arrVal
		arrCommaOrClose
	)
	type frame struct {
		isObj   bool
		val     *Value
		keys    map[string]struct{}
		ph      phase
		pendKey string
	}

	var stack []*frame
	var root *Value
	rootDone := false

	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if rootDone {
			return nil, errInvalidJSON
		}
		if len(stack) == 0 {
			switch t.kind {
			case tokObjOpen:
				v := &Value{Kind: KindObject}
				root = v
				stack = append(stack, &frame{isObj: true, val: v, keys: map[string]struct{}{}, ph: objKeyOrClose})
			case tokArrOpen:
				v := &Value{Kind: KindArray}
				root = v
				stack = append(stack, &frame{isObj: false, val: v, ph: arrValOrClose})
			case tokScalar:
				root = t.val
				rootDone = true
			default:
				return nil, errInvalidJSON
			}
			continue
		}
		f := stack[len(stack)-1]
		if f.isObj {
			switch f.ph {
			case objKeyOrClose, objKey:
				if t.kind == tokObjClose && f.ph == objKeyOrClose {
					stack = stack[:len(stack)-1]
					if len(stack) == 0 {
						rootDone = true
					}
					continue
				}
				if t.kind != tokScalar || t.val.Kind != KindString {
					return nil, errInvalidJSON
				}
				if _, dup := f.keys[t.val.Str]; dup {
					return nil, errDuplicate
				}
				f.keys[t.val.Str] = struct{}{}
				f.pendKey = t.val.Str
				f.ph = objColon
			case objColon:
				if t.kind != tokColon {
					return nil, errInvalidJSON
				}
				f.ph = objValue
			case objValue:
				switch t.kind {
				case tokObjOpen:
					v := &Value{Kind: KindObject}
					f.val.Obj = append(f.val.Obj, Member{f.pendKey, v})
					f.pendKey = ""
					f.ph = objCommaOrClose
					stack = append(stack, &frame{isObj: true, val: v, keys: map[string]struct{}{}, ph: objKeyOrClose})
				case tokArrOpen:
					v := &Value{Kind: KindArray}
					f.val.Obj = append(f.val.Obj, Member{f.pendKey, v})
					f.pendKey = ""
					f.ph = objCommaOrClose
					stack = append(stack, &frame{isObj: false, val: v, ph: arrValOrClose})
				case tokScalar:
					f.val.Obj = append(f.val.Obj, Member{f.pendKey, t.val})
					f.pendKey = ""
					f.ph = objCommaOrClose
				default:
					return nil, errInvalidJSON
				}
			case objCommaOrClose:
				if t.kind == tokComma {
					f.ph = objKey
					continue
				}
				if t.kind == tokObjClose {
					stack = stack[:len(stack)-1]
					if len(stack) == 0 {
						rootDone = true
					}
					continue
				}
				return nil, errInvalidJSON
			}
		} else {
			switch f.ph {
			case arrValOrClose, arrVal:
				if t.kind == tokArrClose && f.ph == arrValOrClose {
					stack = stack[:len(stack)-1]
					if len(stack) == 0 {
						rootDone = true
					}
					continue
				}
				switch t.kind {
				case tokObjOpen:
					v := &Value{Kind: KindObject}
					f.val.Arr = append(f.val.Arr, v)
					f.ph = arrCommaOrClose
					stack = append(stack, &frame{isObj: true, val: v, keys: map[string]struct{}{}, ph: objKeyOrClose})
				case tokArrOpen:
					v := &Value{Kind: KindArray}
					f.val.Arr = append(f.val.Arr, v)
					f.ph = arrCommaOrClose
					stack = append(stack, &frame{isObj: false, val: v, ph: arrValOrClose})
				case tokScalar:
					f.val.Arr = append(f.val.Arr, t.val)
					f.ph = arrCommaOrClose
				default:
					return nil, errInvalidJSON
				}
			case arrCommaOrClose:
				if t.kind == tokComma {
					f.ph = arrVal
					continue
				}
				if t.kind == tokArrClose {
					stack = stack[:len(stack)-1]
					if len(stack) == 0 {
						rootDone = true
					}
					continue
				}
				return nil, errInvalidJSON
			}
		}
	}
	if len(stack) != 0 || !rootDone {
		return nil, errInvalidJSON
	}
	return root, nil
}

func isHex4(b []byte) bool {
	for i := 0; i < 4; i++ {
		c := b[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func hexVal(c byte) rune {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0')
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10
	default:
		return rune(c-'A') + 10
	}
}

func (p *parser) readHex4() (rune, error) {
	if p.pos+4 > len(p.data) || !isHex4(p.data[p.pos:p.pos+4]) {
		return 0, errInvalidJSON
	}
	var r rune
	for i := 0; i < 4; i++ {
		r = r<<4 | hexVal(p.data[p.pos+i])
	}
	p.pos += 4
	return r, nil
}

// parseString decodes a JSON string starting at the opening quote. It rejects
// lone surrogates, noncharacters, and unescaped control characters.
func (p *parser) parseString() (string, error) {
	p.pos++ // opening quote
	var b strings.Builder
	for {
		if p.pos >= len(p.data) {
			return "", errInvalidJSON
		}
		c := p.data[p.pos]
		if c == '"' {
			p.pos++
			return b.String(), nil
		}
		if c == '\\' {
			p.pos++
			if p.pos >= len(p.data) {
				return "", errInvalidJSON
			}
			e := p.data[p.pos]
			switch e {
			case '"':
				b.WriteByte('"')
				p.pos++
			case '\\':
				b.WriteByte('\\')
				p.pos++
			case '/':
				b.WriteByte('/')
				p.pos++
			case 'b':
				b.WriteByte('\b')
				p.pos++
			case 'f':
				b.WriteByte('\f')
				p.pos++
			case 'n':
				b.WriteByte('\n')
				p.pos++
			case 'r':
				b.WriteByte('\r')
				p.pos++
			case 't':
				b.WriteByte('\t')
				p.pos++
			case 'u':
				p.pos++
				r, err := p.readHex4()
				if err != nil {
					return "", err
				}
				if r >= 0xD800 && r <= 0xDBFF {
					if p.pos+1 < len(p.data) && p.data[p.pos] == '\\' && p.data[p.pos+1] == 'u' {
						p.pos += 2
						r2, err := p.readHex4()
						if err != nil {
							return "", err
						}
						if r2 < 0xDC00 || r2 > 0xDFFF {
							return "", errLoneSurrogate
						}
						cp := 0x10000 + (r-0xD800)<<10 + (r2 - 0xDC00)
						if isNoncharacter(cp) {
							return "", errNoncharacter
						}
						b.WriteRune(cp)
					} else {
						return "", errLoneSurrogate
					}
				} else if r >= 0xDC00 && r <= 0xDFFF {
					return "", errLoneSurrogate
				} else {
					if isNoncharacter(r) {
						return "", errNoncharacter
					}
					b.WriteRune(r)
				}
			default:
				return "", errInvalidJSON
			}
			continue
		}
		if c < 0x20 {
			// Unescaped control character in a JSON string.
			return "", errInvalidJSON
		}
		r, size := utf8.DecodeRune(p.data[p.pos:])
		if r == utf8.RuneError && size == 1 {
			return "", errInvalidUTF8
		}
		if isNoncharacter(r) {
			return "", errNoncharacter
		}
		b.Write(p.data[p.pos : p.pos+size])
		p.pos += size
	}
}

// parseNumber scans a JSON number token and converts it to binary64. Overflow
// to a non-finite value is a non-finite-number rejection; a token whose value
// is negative zero is a negative-zero rejection (§6, §18, RFC 8785 errata).
func (p *parser) parseNumber() (*Value, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
		return nil, errInvalidJSON
	}
	if p.data[p.pos] == '0' {
		p.pos++
	} else {
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
			return nil, errInvalidJSON
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
			return nil, errInvalidJSON
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	tok := string(p.data[start:p.pos])
	f, err := strconv.ParseFloat(tok, 64)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
			return nil, errNonFinite
		}
		return nil, errInvalidJSON
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, errNonFinite
	}
	if f == 0 && math.Signbit(f) {
		return nil, errNegativeZero
	}
	return &Value{Kind: KindNumber, Num: f}, nil
}
