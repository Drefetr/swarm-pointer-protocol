package main

// Totality / robustness self-tests (handoff §6 trap 8, §4). Verify must return
// a verdict for every possible byte string with no panic.

import (
	"math/rand"
	"strings"
	"testing"
)

func runVerifyNoPanic(t *testing.T, data []byte) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on input %q...: %v", data[:min(len(data), 80)], r)
		}
	}()
	_ = Verify(data)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestTotalityRandomBytes(t *testing.T) {
	r := rand.New(rand.NewSource(12345))
	alphabet := []byte("{}[]\",:0123456789.-+eEtruefalsn \\u\x00\xff\xef\xbb\xbfabc")
	for i := 0; i < 20000; i++ {
		n := r.Intn(64)
		b := make([]byte, n)
		for j := range b {
			if r.Intn(2) == 0 {
				b[j] = alphabet[r.Intn(len(alphabet))]
			} else {
				b[j] = byte(r.Intn(256))
			}
		}
		runVerifyNoPanic(t, b)
	}
}

func TestTotalityStructureHostiles(t *testing.T) {
	inputs := []string{
		"",
		" ",
		"{",
		"}",
	"[",
		"]",
		"{}}",
		"[]",
		"\"",
		"\"\\",
		"\"\\u",
		"\"\\uD800\"",
		"\"\\uDC00\"",
		"nul",
		"null",
		"true",
		"false",
		"1",
		"-0",
		"1e309",
		"1e-999",
		"-1e-999",
		"0.0",
		"-0.0",
		"{}",
		"{\"a\":}",
		"{\"a\"}",
		"{\"a\":1,}",
		"{\"a\":1 \"b\":2}",
		"{\"a\":[}",
		"{\"a\":{}}",
		"[\"a\",\"b\"]",
		"{\"v\":1}",
		"{\"a\":1e}",
		"{\"a\":01}",
		"{\"a\":+1}",
		"{\"a\":.5}",
		"{\"a\":1.}",
		"{\"a\":\u00e9}",
	}
	for _, s := range inputs {
		runVerifyNoPanic(t, []byte(s))
	}
}

func TestTotalityTruncations(t *testing.T) {
	bases := []string{a1JCS, a2JCS, a3JCS, a6JCS, a7JCS, a8JCS}
	for _, b := range bases {
		env := envelope(b, a1ID, a1Sig)
		for i := 0; i < len(env); i++ {
			runVerifyNoPanic(t, env[:i])
		}
		// single-byte mutations
		for i := 0; i < len(env); i++ {
			m := append([]byte{}, env...)
			m[i] ^= 0xFF
			runVerifyNoPanic(t, m)
		}
	}
}

func TestTotalityDeepNesting(t *testing.T) {
	depths := []int{100, 1000, 10000, 100000, 200000}
	for _, d := range depths {
		// Deep unmatched arrays.
		runVerifyNoPanic(t, []byte(strings.Repeat("[", d)))
		// Deep unmatched objects.
		runVerifyNoPanic(t, []byte(strings.Repeat("{\"a\":", d)))
		// Deep but balanced arrays make a valid JSON value, but not an object.
		runVerifyNoPanic(t, []byte(strings.Repeat("[", d)+strings.Repeat("]", d)))
		// Deep balanced object chain inside ext: use construct-depth shape as a raw value.
		inner := "1"
		var sb strings.Builder
		for i := 0; i < d; i++ {
			sb.WriteString("{\"a\":")
		}
		sb.WriteString(inner)
		for i := 0; i < d; i++ {
			sb.WriteString("}")
		}
		runVerifyNoPanic(t, []byte(sb.String()))
	}
}

func TestTotalityBadUTF8(t *testing.T) {
	inputs := [][]byte{
		{0xEF, 0xBB, 0xBF},
		{0xEF, 0xBB},
		{0xFE, 0xFF},
		{0xFF},
		{0xC0, 0x80},
		{0xED, 0xA0, 0x80},
		{0xF4, 0x90, 0x80, 0x80},
		{0x80},
		[]byte("{\"a\":\"\xC0\x80\"}"),
		[]byte("{\"v\":1,\"x\":\"\xED\xA0\x80\"}"),
	}
	for _, b := range inputs {
		runVerifyNoPanic(t, b)
	}
}
