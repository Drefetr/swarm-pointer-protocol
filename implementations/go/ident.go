package main

import "math"

// §4 identifier grammar, §7A structural schema, §17 nonce, §18 created.
// Field-level shape and grammar checks live here; the §20 pipeline in
// verify.go drives them in order.

// isLowerHex reports whether s consists only of 0-9 a-f.
func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isSHA256ID(s string) bool {
	return len(s) == len("sha256:")+64 && s[:len("sha256:")] == "sha256:" && isLowerHex(s[len("sha256:"):])
}

func isActorID(s string) bool {
	return len(s) == len("ed25519:")+64 && s[:len("ed25519:")] == "ed25519:" && isLowerHex(s[len("ed25519:"):])
}

func isSigHex(s string) bool {
	return len(s) == 128 && isLowerHex(s)
}

// isNonce implements §17: "0", or [1-9][0-9]{0,19} with value <= 2^64-1.
func isNonce(s string) bool {
	if s == "0" {
		return true
	}
	if len(s) == 0 || len(s) > 20 {
		return false
	}
	if s[0] < '1' || s[0] > '9' {
		return false
	}
	if !isDigits(s) {
		return false
	}
	// Compare the 20-digit maximum against 18446744073709551615.
	if len(s) < 20 {
		return true
	}
	return s <= "18446744073709551615"
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isBinary64Integer reports whether x is a finite integral binary64 value.
func isBinary64Integer(x float64) bool {
	return !math.IsInf(x, 0) && !math.IsNaN(x) && x == math.Trunc(x)
}

// reference object (§7A, §9): exactly {hash, locators}, both required, no
// others, no nested ext.
func validateReferenceObject(v *Value) bool {
	if v == nil || v.Kind != KindObject {
		return false
	}
	if len(v.Obj) != 2 {
		return false
	}
	for i := range v.Obj {
		switch v.Obj[i].Name {
		case "hash":
			mv := v.Obj[i].Val
			if mv == nil || mv.Kind != KindString {
				return false
			}
		case "locators":
			mv := v.Obj[i].Val
			if mv == nil || mv.Kind != KindArray {
				return false
			}
			for _, el := range mv.Arr {
				if el == nil || el.Kind != KindString {
					return false
				}
			}
		default:
			return false
		}
	}
	return v.Get("hash") != nil && v.Get("locators") != nil
}

// validateSchema enforces §7A on the reconstructed U. It returns a §5 reason
// token, or "" when the shape is acceptable.
func validateSchema(u *Value, typ string) string {
	if u == nil || u.Kind != KindObject {
		return "schema"
	}
	// Closed core: only reserved top-level names.
	for i := range u.Obj {
		switch u.Obj[i].Name {
		case "v", "type", "actor", "created", "nonce",
			"channel", "ref", "parents", "descriptor", "ext":
		default:
			return "schema"
		}
	}
	// Common required members.
	for _, name := range []string{"v", "type", "actor", "created", "nonce"} {
		if !u.Has(name) {
			return "schema"
		}
	}
	if m := u.Get("v"); m.Kind != KindNumber {
		return "schema"
	}
	if m := u.Get("type"); m.Kind != KindString {
		return "schema"
	}
	if m := u.Get("actor"); m.Kind != KindString {
		return "schema"
	}
	if m := u.Get("created"); m.Kind != KindNumber {
		return "schema"
	}
	if m := u.Get("nonce"); m.Kind != KindString {
		return "schema"
	}
	// ext, if present, is an object.
	if m := u.Get("ext"); m != nil && m.Kind != KindObject {
		return "schema"
	}

	switch typ {
	case "pointer":
		if u.Has("descriptor") {
			return "schema"
		}
		ch := u.Get("channel")
		if ch == nil || ch.Kind != KindString {
			return "schema"
		}
		ref := u.Get("ref")
		if !validateReferenceObject(ref) {
			return "schema"
		}
		if p := u.Get("parents"); p != nil {
			if p.Kind != KindArray {
				return "schema"
			}
			for _, el := range p.Arr {
				if el == nil || el.Kind != KindString {
					return "schema"
				}
			}
		}
	case "channel":
		if u.Has("channel") || u.Has("parents") || u.Has("ref") {
			return "schema"
		}
		if d := u.Get("descriptor"); d != nil {
			if !validateReferenceObject(d) {
				return "schema"
			}
		}
	default:
		return "unknown-type"
	}
	return ""
}

// validateIdentifiers enforces §4 on every identifier field of U. It returns a
// reason token or "".
func validateIdentifiers(u *Value, typ string) string {
	switch typ {
	case "pointer":
		if ch := u.Get("channel"); ch == nil || !isSHA256ID(ch.Str) {
			return "identifier"
		}
		ref := u.Get("ref")
		if h := ref.Get("hash"); h == nil || !isSHA256ID(h.Str) {
			return "identifier"
		}
		if p := u.Get("parents"); p != nil {
			for _, el := range p.Arr {
				if !isSHA256ID(el.Str) {
					return "identifier"
				}
			}
		}
	case "channel":
		if d := u.Get("descriptor"); d != nil {
			if h := d.Get("hash"); h == nil || !isSHA256ID(h.Str) {
				return "identifier"
			}
		}
	}
	return ""
}
