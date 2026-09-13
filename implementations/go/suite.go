package main

// --suite driver for conformance/vectors/suite.json. The accepted format is
// described in conformance/README.md §"Suite format" and handoff §4.5.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
)

type suiteFile struct {
	Profile string      `json:"profile"`
	Cases   []suiteCase `json:"cases"`
}

type suiteCase struct {
	ID     string          `json:"id"`
	Class  string          `json:"class"`
	Expect string          `json:"expect"`
	Input  json.RawMessage `json:"input"`
	Want   json.RawMessage `json:"want"`
}

type suiteInput struct {
	Kind    string `json:"kind"`
	UTF8    string `json:"utf8"`
	Nonce   string `json:"nonce"`
	PadLen  int    `json:"pad_len"`
	Depth   int    `json:"depth"`
	Channel string `json:"channel"`
	Actor   string `json:"actor"`
	Created int64  `json:"created"`
	Hash    string `json:"hash"`
	Units   *int64 `json:"units"`
	HHex    string `json:"H_hex"`
	A       string `json:"A"`
	Sig     string `json:"sig"`
	D       string `json:"D"`
}

type suiteWant struct {
	ID        string   `json:"id"`
	Units     *int64   `json:"units"`
	TargetHex string   `json:"target_hex"`
	JCS       string   `json:"jcs"`
	JCSHex    string   `json:"jcs_hex"`
	JCSBytes  *int64   `json:"jcs_bytes"`
	Reasons   []string `json:"reasons"`
	Accept    *bool    `json:"accept"`
	Sig       string   `json:"sig"`
}

func runSuite(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "suite read error:", err)
		return 3
	}
	var sf suiteFile
	if err := json.Unmarshal(data, &sf); err != nil {
		fmt.Fprintln(os.Stderr, "suite parse error:", err)
		return 3
	}
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	passed := 0
	for i := range sf.Cases {
		c := sf.Cases[i]
		ok, detail := runSuiteCase(&c)
		if ok {
			passed++
			fmt.Fprintf(w, "%s PASS\n", c.ID)
		} else {
			fmt.Fprintf(w, "%s FAIL %s\n", c.ID, detail)
		}
	}
	fmt.Fprintf(w, "%d/%d passed\n", passed, len(sf.Cases))
	if passed != len(sf.Cases) {
		return 1
	}
	return 0
}

func reasonIn(want *suiteWant, reason string) bool {
	if len(want.Reasons) == 0 {
		return true
	}
	for _, r := range want.Reasons {
		if r == reason {
			return true
		}
	}
	return false
}

func runSuiteCase(c *suiteCase) (ok bool, detail string) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
			detail = fmt.Sprintf("panic: %v", r)
		}
	}()
	var in suiteInput
	var want suiteWant
	if err := json.Unmarshal(c.Input, &in); err != nil {
		return false, "input decode: " + err.Error()
	}
	if err := json.Unmarshal(c.Want, &want); err != nil {
		return false, "want decode: " + err.Error()
	}

	switch c.Class {
	case "json-input":
		_, err := ParseIJSON([]byte(in.UTF8))
		if c.Expect == "valid" {
			if err != nil {
				return false, "expected valid input, got " + err.Error()
			}
			return true, ""
		}
		if err == nil {
			return false, "expected reject, got parse success"
		}
		reason := "invalid-json"
		if pe, ok := err.(*parseError); ok {
			reason = pe.reason
		}
		if !reasonIn(&want, reason) {
			return false, "reason " + reason + " not in " + fmt.Sprint(want.Reasons)
		}
		return true, ""

	case "schema", "full-assertion":
		vd := Verify([]byte(in.UTF8))
		if c.Expect == "valid" {
			if vd.Status != StatusValid {
				return false, fmt.Sprintf("not VALID (%s/%s)", vd.Stage, vd.Reason)
			}
			if want.ID != "" && vd.IDComputed != want.ID {
				return false, "id " + vd.IDComputed + " != " + want.ID
			}
			if want.Units != nil && vd.Units != *want.Units {
				return false, fmt.Sprintf("units %d != %d", vd.Units, *want.Units)
			}
			if want.TargetHex != "" && hex.EncodeToString(vd.Target) != want.TargetHex {
				return false, "target " + hex.EncodeToString(vd.Target) + " != " + want.TargetHex
			}
			if want.JCS != "" && string(vd.JCS) != want.JCS {
				return false, "jcs mismatch"
			}
			return true, ""
		}
		if c.Expect == "unsupported" {
			if vd.Status != StatusUnsupported {
				return false, fmt.Sprintf("not UNSUPPORTED (%v/%s/%s)", vd.Status, vd.Stage, vd.Reason)
			}
			if !reasonIn(&want, vd.Reason) {
				return false, "reason " + vd.Reason + " not in " + fmt.Sprint(want.Reasons)
			}
			return true, ""
		}
		// invalid
		if vd.Status == StatusUnsupported {
			return false, "unsupported, want reject"
		}
		if vd.Status != StatusInvalid {
			return false, fmt.Sprintf("not INVALID (status %v)", vd.Status)
		}
		if c.Class == "schema" && vd.Stage != "schema" {
			return false, "rejected at " + vd.Stage + ", want schema"
		}
		if !reasonIn(&want, vd.Reason) {
			return false, "reason " + vd.Reason + " not in " + fmt.Sprint(want.Reasons)
		}
		return true, ""

	case "jcs":
		v, err := ParseIJSON([]byte(in.UTF8))
		if err != nil {
			reason := "invalid-json"
			if pe, ok := err.(*parseError); ok {
				reason = pe.reason
			}
			if c.Expect == "invalid" && reasonIn(&want, reason) {
				return true, ""
			}
			return false, "parse: " + reason
		}
		if c.Expect == "invalid" {
			return false, "expected parse reject"
		}
		jcs := Canonicalize(v)
		if want.JCS != "" && string(jcs) != want.JCS {
			return false, "jcs " + string(jcs) + " != " + want.JCS
		}
		if want.JCSHex != "" && hex.EncodeToString(jcs) != want.JCSHex {
			return false, "jcs_hex " + hex.EncodeToString(jcs) + " != " + want.JCSHex
		}
		if want.ID != "" {
			sum := sha256.Sum256(jcs)
			id := "sha256:" + hex.EncodeToString(sum[:])
			if id != want.ID {
				return false, "id " + id + " != " + want.ID
			}
		}
		return true, ""

	case "length":
		return runLengthCase(c, &in, &want)

	case "work":
		if in.Units == nil {
			return false, "missing units"
		}
		w := new(big.Int).Mul(big.NewInt(*in.Units), big.NewInt(workUnit))
		target := new(big.Int).Div(bigMax, w)
		h, ok := new(big.Int).SetString(strings.TrimSpace(in.HHex), 16)
		if !ok {
			return false, "bad H_hex"
		}
		accept := h.Cmp(target) <= 0
		if want.Accept != nil && accept != *want.Accept {
			return false, fmt.Sprintf("accept %v != %v", accept, *want.Accept)
		}
		if want.TargetHex != "" && hex.EncodeToString(leftPad32(target.Bytes())) != want.TargetHex {
			return false, "target mismatch"
		}
		return true, ""

	case "spp-ed25519-1":
		a, e1 := hex.DecodeString(in.A)
		s, e2 := hex.DecodeString(in.Sig)
		d, e3 := hex.DecodeString(in.D)
		if e1 != nil || e2 != nil || e3 != nil {
			return c.Expect == "invalid", "bad hex"
		}
		got := SPPEd25519Verify(a, s, d)
		if c.Expect == "valid" && !got {
			return false, "expected accept"
		}
		if c.Expect == "invalid" && got {
			return false, "expected reject"
		}
		return true, ""
	}
	return false, "unknown class " + c.Class
}

func runLengthCase(c *suiteCase, in *suiteInput, want *suiteWant) (bool, string) {
	if in.Kind == "json-text" {
		vd := Verify([]byte(in.UTF8))
		if c.Expect == "valid" {
			if vd.Status != StatusValid {
				return false, fmt.Sprintf("not VALID (%s/%s)", vd.Stage, vd.Reason)
			}
			return true, ""
		}
		if vd.Stage != "length" || !reasonIn(want, vd.Reason) {
			return false, fmt.Sprintf("rejected at %s/%s", vd.Stage, vd.Reason)
		}
		return true, ""
	}
	// Constructed cases: build the A.3-shaped pointer skeleton plus ext.
	var ext *Value
	switch in.Kind {
	case "construct-pad":
		ext = &Value{Kind: KindObject, Obj: []Member{
			{"pad", &Value{Kind: KindString, Str: strings.Repeat("a", in.PadLen)}},
		}}
	case "construct-depth":
		inner := &Value{Kind: KindNumber, Num: 1}
		for i := 0; i < in.Depth; i++ {
			inner = &Value{Kind: KindObject, Obj: []Member{{"a", inner}}}
		}
		ext = &Value{Kind: KindObject, Obj: []Member{{"deep", inner}}}
	default:
		return false, "unknown length input kind " + in.Kind
	}
	u := buildSkeleton(in.Actor, in.Channel, in.Hash, in.Nonce, float64(in.Created), ext)
	lr := evalLength(u)
	if want.JCSBytes != nil && int64(lr.jcsBytes) != *want.JCSBytes {
		return false, fmt.Sprintf("jcs_bytes %d != %d", lr.jcsBytes, *want.JCSBytes)
	}
	if c.Expect == "valid" {
		if lr.reason != "" {
			return false, "unexpected reject " + lr.reason
		}
		if want.Units != nil && lr.units != *want.Units {
			return false, fmt.Sprintf("units %d != %d", lr.units, *want.Units)
		}
		return true, ""
	}
	if lr.reason == "" {
		return false, "expected reject, got none"
	}
	if !reasonIn(want, lr.reason) {
		return false, "reason " + lr.reason + " not in " + fmt.Sprint(want.Reasons)
	}
	return true, ""
}

// buildSkeleton builds the A.3-shaped pointer U used by length cases.
func buildSkeleton(actor, channel, hash, nonce string, created float64, ext *Value) *Value {
	u := &Value{Kind: KindObject}
	u.Obj = []Member{
		{"v", &Value{Kind: KindNumber, Num: 1}},
		{"type", &Value{Kind: KindString, Str: "pointer"}},
		{"actor", &Value{Kind: KindString, Str: actor}},
		{"channel", &Value{Kind: KindString, Str: channel}},
		{"created", &Value{Kind: KindNumber, Num: created}},
		{"nonce", &Value{Kind: KindString, Str: nonce}},
		{"ref", &Value{Kind: KindObject, Obj: []Member{
			{"hash", &Value{Kind: KindString, Str: hash}},
			{"locators", &Value{Kind: KindArray, Arr: []*Value{}}},
		}}},
	}
	if ext != nil {
		u.Obj = append(u.Obj, Member{"ext", ext})
	}
	return u
}

type lengthResult struct {
	jcsBytes int
	units    int64
	reason   string
}

func evalLength(u *Value) lengthResult {
	jcs := Canonicalize(u)
	lr := lengthResult{jcsBytes: len(jcs)}
	locCount, parentCount, locators, _ := structuralCounts(u, "pointer")
	switch {
	case len(jcs) > maxCanonicalBody:
		lr.reason = "jcs-too-large"
	case locCount > maxLocatorCount:
		lr.reason = "too-many-locators"
	default:
		for _, loc := range locators {
			if len(loc) > maxLocatorBytes {
				lr.reason = "locator-too-long"
				break
			}
		}
		if lr.reason == "" && parentCount > maxParentCount {
			lr.reason = "too-many-parents"
		}
	}
	lr.units = 1 + int64((len(jcs)+1023)/1024) + int64(locCount) + int64(parentCount)
	return lr
}
