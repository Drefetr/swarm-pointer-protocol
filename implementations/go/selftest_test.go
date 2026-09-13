package main

// Phase A self-test corpus: every vector printed in the normative prose of
// spec/spp-v1-rc3.md — Appendix A (A.1-A.15), Appendix B (PoW boundary),
// and Appendix D (negative vectors). No machine corpus or reference
// implementation was consulted.

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

const (
	testActor = "ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	testAPub  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

	// A.1
	a1ID     = "sha256:0000058da39af8f5e2cb8c1268b45e6f198320a5e5ac53512f4b707e8672986b"
	a1JCS    = `{"actor":"ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","created":1789183927,"descriptor":{"hash":"sha256:a7d4190a569accae21892fb2a67f8ce9f83f9662aa0c93d282689534a806ee89","locators":["https://example.invalid/spp/channel-desc"]},"nonce":"1897339","type":"channel","v":1}`
	a1Sig    = "24ddc9d5e796d2dcdcc2783ec43d78e7d7a58b4d1e632ce0928605a5fbaec6db99bf5269f59f6a4f2d53ff7577d6de720a6ac419f81dc5d380b57fe2ce1e2300"
	a1Target = "00000d79435e50d79435e50d79435e50d79435e50d79435e50d79435e50d7943"

	// A.2
	a2ID     = "sha256:000018da6b416f566189390610b73b34b6d109265842a1988b3d41301490c6ae"
	a2JCS    = `{"actor":"ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","channel":"sha256:0000058da39af8f5e2cb8c1268b45e6f198320a5e5ac53512f4b707e8672986b","created":1789184927,"nonce":"81681","ref":{"hash":"sha256:64d37b3d01f65606605420c59c6f7f1bd4f5bd15d6e32b7c85aa64e5d1050328","locators":["https://example.invalid/spp/test-object"]},"type":"pointer","v":1}`
	a2Sig    = "4bb07a7738fa698c08f6b5c10c603f2bfa980f5eeecf4a4423e48f41893112c2b5d1c9bc5543d23190c6dc00108e17edc00deb693ced1dd30402335f88b3a00a"
	a2Target = "0000555555555555555555555555555555555555555555555555555555555555"

	// A.3
	a3ID     = "sha256:000012874e9c76d28405f99797c44fe3ac29ea0bc7109ad0c840b3007353ccb2"
	a3JCS    = `{"actor":"ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","channel":"sha256:cb2f8a892470979bc9b523f92279fdf7294157614e19041acaf17f4bb1a417f9","created":1789184927,"nonce":"142897","ref":{"hash":"sha256:64d37b3d01f65606605420c59c6f7f1bd4f5bd15d6e32b7c85aa64e5d1050328","locators":[]},"type":"pointer","v":1}`
	a3Sig    = "50559c554c301d8b5ca66d745cda553fd6d39f4d7214444c799cd30671575775e8424d138b554c2fa9721b9094fc65d055a7606a305912981bebe00dae6c4901"
	a3Target = "00007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	// A.6
	a6ID     = "sha256:000002d4085a685ffe7e0ab79ddd01181ae8f21c3df7dd5fb66bbbaf28ba84c9"
	a6JCS    = `{"actor":"ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","created":1789183927,"nonce":"650799","type":"channel","v":1}`
	a6Sig    = "bfc6212b3f37a7b175f5592f3f88692999c11ef54ab48903380f414ff3e0510134fe21d7bfc1293e02a921d182b27c67e84809e933e304c813cdf7b5608fe205"

	// A.7
	a7ID  = "sha256:0000062d3fd95591c2328e645568cd25142d70495b456dd34229656a331b162f"
	a7JCS = `{"actor":"ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","channel":"sha256:0000058da39af8f5e2cb8c1268b45e6f198320a5e5ac53512f4b707e8672986b","created":1789184927,"nonce":"158633","parents":["sha256:000018da6b416f566189390610b73b34b6d109265842a1988b3d41301490c6ae"],"ref":{"hash":"sha256:64d37b3d01f65606605420c59c6f7f1bd4f5bd15d6e32b7c85aa64e5d1050328","locators":[]},"type":"pointer","v":1}`
	a7Sig = "056ec7213b78190c283f630ad2f2a283e8cf818f5164886b47da3c2cd9fdec9b4da52998ed660681ad234119a1497238831d503c2f4acdb1208159949d73de0c"

	// A.8
	a8ID  = "sha256:000005d6b4d082b120e7a04e6040d46d902dca37eee478804d21a48fb6f93076"
	a8JCS = `{"actor":"ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","channel":"sha256:cb2f8a892470979bc9b523f92279fdf7294157614e19041acaf17f4bb1a417f9","created":1789184927,"ext":{"org.example.note":"authenticated metadata"},"nonce":"12019","ref":{"hash":"sha256:64d37b3d01f65606605420c59c6f7f1bd4f5bd15d6e32b7c85aa64e5d1050328","locators":[]},"type":"pointer","v":1}`
	a8Sig = "2da6143ff66b0076e122dc7f7d5614a1626166d78c07b82fd3c96cce1fa508c9e6bcdfd9aaf97de537aa7e1ea5cdf521cff62842f31393119349c42291da4d0a"
)

// envelope inserts id and sig into a canonical-U string (which ends in "}").
func envelope(jcs, id, sig string) []byte {
	return []byte(jcs[:len(jcs)-1] + `,"id":"` + id + `","sig":"` + sig + `"}`)
}

func mustParseU(t *testing.T, jcs string) *Value {
	t.Helper()
	v, err := ParseIJSON([]byte(jcs))
	if err != nil {
		t.Fatalf("parse U: %v", err)
	}
	return v
}

func TestA1ChannelDescription(t *testing.T) {
	u := mustParseU(t, a1JCS)
	if got := string(Canonicalize(u)); got != a1JCS {
		t.Fatalf("JCS mismatch\n got %s\nwant %s", got, a1JCS)
	}
	vd := Verify(envelope(a1JCS, a1ID, a1Sig))
	if vd.Status != StatusValid {
		t.Fatalf("A.1 rejected at %s/%s", vd.Stage, vd.Reason)
	}
	if vd.IDComputed != a1ID || vd.Units != 19 || hex.EncodeToString(vd.Target) != a1Target {
		t.Fatalf("A.1 fields: id=%s units=%d target=%s", vd.IDComputed, vd.Units, hex.EncodeToString(vd.Target))
	}
}

func TestA2Pointer(t *testing.T) {
	u := mustParseU(t, a2JCS)
	if got := string(Canonicalize(u)); got != a2JCS {
		t.Fatalf("JCS mismatch")
	}
	vd := Verify(envelope(a2JCS, a2ID, a2Sig))
	if vd.Status != StatusValid {
		t.Fatalf("A.2 rejected at %s/%s", vd.Stage, vd.Reason)
	}
	if vd.IDComputed != a2ID || vd.Units != 3 || hex.EncodeToString(vd.Target) != a2Target {
		t.Fatalf("A.2 fields: id=%s units=%d target=%s", vd.IDComputed, vd.Units, hex.EncodeToString(vd.Target))
	}
}

func TestA3UnlistedChannel(t *testing.T) {
	u := mustParseU(t, a3JCS)
	if got := string(Canonicalize(u)); got != a3JCS {
		t.Fatalf("JCS mismatch")
	}
	vd := Verify(envelope(a3JCS, a3ID, a3Sig))
	if vd.Status != StatusValid {
		t.Fatalf("A.3 rejected at %s/%s", vd.Stage, vd.Reason)
	}
	if vd.IDComputed != a3ID || vd.Units != 2 || hex.EncodeToString(vd.Target) != a3Target {
		t.Fatalf("A.3 fields: id=%s units=%d target=%s", vd.IDComputed, vd.Units, hex.EncodeToString(vd.Target))
	}
}

func TestA4OmittedVsEmptyParents(t *testing.T) {
	omitted := `{"actor":"ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","channel":"sha256:0000058da39af8f5e2cb8c1268b45e6f198320a5e5ac53512f4b707e8672986b","created":1789184927,"nonce":"0","ref":{"hash":"sha256:64d37b3d01f65606605420c59c6f7f1bd4f5bd15d6e32b7c85aa64e5d1050328","locators":[]},"type":"pointer","v":1}`
	empty := `{"actor":"ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","channel":"sha256:0000058da39af8f5e2cb8c1268b45e6f198320a5e5ac53512f4b707e8672986b","created":1789184927,"nonce":"0","parents":[],"ref":{"hash":"sha256:64d37b3d01f65606605420c59c6f7f1bd4f5bd15d6e32b7c85aa64e5d1050328","locators":[]},"type":"pointer","v":1}`
	idOf := func(jcs string) string {
		sum := sha256.Sum256([]byte(jcs))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	if got := idOf(omitted); got != "sha256:5d96fc34eab8de0e395ccd72fbce6f35b43944a18b3f24f5fd573f81cdc528b1" {
		t.Fatalf("omitted id = %s", got)
	}
	if got := idOf(empty); got != "sha256:f5be6d6982bc6cdbdb007040d2758747f67c32b320a0e049d28b3f385c46af48" {
		t.Fatalf("empty id = %s", got)
	}
}

func a5Body(t *testing.T, nonce string) []byte {
	t.Helper()
	pad := strings.Repeat("a", 680)
	return []byte(`{"actor":"` + testActor + `","channel":"sha256:cb2f8a892470979bc9b523f92279fdf7294157614e19041acaf17f4bb1a417f9","created":1789184927,"ext":{"pad":"` + pad + `"},"nonce":"` + nonce + `","ref":{"hash":"sha256:64d37b3d01f65606605420c59c6f7f1bd4f5bd15d6e32b7c85aa64e5d1050328","locators":[]},"type":"pointer","v":1}`)
}

func TestA5UnitsBoundary(t *testing.T) {
	v9 := mustParseU(t, string(a5Body(t, "9")))
	j9 := Canonicalize(v9)
	if len(j9) != 1024 {
		t.Fatalf("nonce 9 JCS length = %d, want 1024", len(j9))
	}
	v10 := mustParseU(t, string(a5Body(t, "10")))
	j10 := Canonicalize(v10)
	if len(j10) != 1025 {
		t.Fatalf("nonce 10 JCS length = %d, want 1025", len(j10))
	}
	// units for the two bodies (no id/sig needed to compute length-derived units)
	units := func(j []byte) int64 {
		return 1 + int64((len(j)+1023)/1024) + 0 + 0
	}
	if u := units(j9); u != 2 {
		t.Fatalf("nonce 9 units = %d", u)
	}
	if u := units(j10); u != 3 {
		t.Fatalf("nonce 10 units = %d", u)
	}
}

func TestA6ChannelNoDescriptor(t *testing.T) {
	vd := Verify(envelope(a6JCS, a6ID, a6Sig))
	if vd.Status != StatusValid {
		t.Fatalf("A.6 rejected at %s/%s", vd.Stage, vd.Reason)
	}
	if vd.IDComputed != a6ID || vd.Units != 18 {
		t.Fatalf("A.6 fields: id=%s units=%d", vd.IDComputed, vd.Units)
	}
}

func TestA7Parent(t *testing.T) {
	vd := Verify(envelope(a7JCS, a7ID, a7Sig))
	if vd.Status != StatusValid {
		t.Fatalf("A.7 rejected at %s/%s", vd.Stage, vd.Reason)
	}
	if vd.IDComputed != a7ID || vd.Units != 3 {
		t.Fatalf("A.7 fields: id=%s units=%d", vd.IDComputed, vd.Units)
	}
}

func TestA8Ext(t *testing.T) {
	vd := Verify(envelope(a8JCS, a8ID, a8Sig))
	if vd.Status != StatusValid {
		t.Fatalf("A.8 rejected at %s/%s", vd.Stage, vd.Reason)
	}
	if vd.IDComputed != a8ID || vd.Units != 2 {
		t.Fatalf("A.8 fields: id=%s units=%d", vd.IDComputed, vd.Units)
	}
}

func TestA9UTF16KeyOrder(t *testing.T) {
	// {"<U+10000>":2,"<U+E000>":1} built from raw UTF-8.
	in := "{\"\U00010000\":2,\"\uE000\":1}"
	u, err := ParseIJSON([]byte(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := hex.EncodeToString(Canonicalize(u))
	want := "7b22f0908080223a322c22ee8080223a317d"
	if got != want {
		t.Fatalf("A.9 JCS = %s, want %s", got, want)
	}
}

func TestA10MaxBody(t *testing.T) {
	body := func(n int) []byte {
		pad := strings.Repeat("a", n)
		return []byte(`{"actor":"` + testActor + `","channel":"sha256:cb2f8a892470979bc9b523f92279fdf7294157614e19041acaf17f4bb1a417f9","created":1789184927,"ext":{"pad":"` + pad + `"},"nonce":"0","ref":{"hash":"sha256:64d37b3d01f65606605420c59c6f7f1bd4f5bd15d6e32b7c85aa64e5d1050328","locators":[]},"type":"pointer","v":1}`)
	}
	j := Canonicalize(mustParseU(t, string(body(1048232))))
	if len(j) != 1048576 {
		t.Fatalf("A.10 N=1048232 JCS = %d, want 1048576", len(j))
	}
	j2 := Canonicalize(mustParseU(t, string(body(1048233))))
	if len(j2) != 1048577 {
		t.Fatalf("A.10 N=1048233 JCS = %d, want 1048577", len(j2))
	}
}

func TestA11A12VLexical(t *testing.T) {
	for _, tok := range []string{"1.0", "1e0", "1.0000000000000001"} {
		mod := strings.Replace(a2JCS, `"v":1}`, `"v":`+tok+`}`, 1)
		vd := Verify(envelope(mod, a2ID, a2Sig))
		if vd.Status != StatusValid {
			t.Fatalf("v=%s rejected at %s/%s", tok, vd.Stage, vd.Reason)
		}
		if vd.IDComputed != a2ID {
			t.Fatalf("v=%s id=%s", tok, vd.IDComputed)
		}
	}
	// created -0 is invalid at JSON input.
	mod := strings.Replace(a2JCS, `"created":1789184927`, `"created":-0`, 1)
	vd := Verify(envelope(mod, a2ID, a2Sig))
	if vd.Status != StatusInvalid || vd.Stage != "json-input" || vd.Reason != "negative-zero" {
		t.Fatalf("created -0 => %v %s/%s", vd.Status, vd.Stage, vd.Reason)
	}
}

func TestJCSNumbers(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"n":9007199254740993}`, `{"n":9007199254740992}`},   // A.13
		{`{"n":5e-324}`, `{"n":5e-324}`},                        // A.14
		{`{"n":36101157879172420000}`, `{"n":36101157879172420000}`}, // A.15
	}
	for _, c := range cases {
		u, err := ParseIJSON([]byte(c.in))
		if err != nil {
			t.Fatalf("parse %s: %v", c.in, err)
		}
		if got := string(Canonicalize(u)); got != c.want {
			t.Fatalf("JCS(%s) = %s, want %s", c.in, got, c.want)
		}
	}
	// Direct ECMAScript Number::toString spot checks.
	direct := []struct {
		x    float64
		want string
	}{
		{5e-324, "5e-324"},
		{1e21, "1e+21"},
		{1e20, "100000000000000000000"},
		{0.001, "0.001"},
		{1e-6, "0.000001"},
		{1e-7, "1e-7"},
		{1, "1"},
		{100, "100"},
		{1.5e-7, "1.5e-7"},
	}
	for _, d := range direct {
		if got := FormatNumber(d.x); got != d.want {
			t.Fatalf("FormatNumber(%v) = %s, want %s", d.x, got, d.want)
		}
	}
}

func TestAppendixBWorkBoundary(t *testing.T) {
	// target = floor(MAX / (units*65536)); H <= target accepted.
	expectTarget := func(units int64, hexTarget string) *big.Int {
		w := new(big.Int).Mul(big.NewInt(units), big.NewInt(65536))
		tgt := new(big.Int).Div(bigMax, w)
		if hex.EncodeToString(leftPad32(tgt.Bytes())) != hexTarget {
			t.Fatalf("units %d target = %s, want %s", units, hex.EncodeToString(leftPad32(tgt.Bytes())), hexTarget)
		}
		return tgt
	}
	tgt3 := expectTarget(3, "0000555555555555555555555555555555555555555555555555555555555555")
	expectTarget(2, "00007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	expectTarget(19, "00000d79435e50d79435e50d79435e50d79435e50d79435e50d79435e50d7943")

	accept := func(h *big.Int) bool { return h.Cmp(tgt3) <= 0 }
	if !accept(big.NewInt(0)) || !accept(big.NewInt(1)) {
		t.Fatal("H=0/1 should accept")
	}
	if !accept(new(big.Int).Sub(tgt3, big.NewInt(1))) {
		t.Fatal("H=target-1 should accept")
	}
	if !accept(new(big.Int).Set(tgt3)) {
		t.Fatal("H=target should accept")
	}
	if accept(new(big.Int).Add(tgt3, big.NewInt(1))) {
		t.Fatal("H=target+1 should reject")
	}
	if accept(bigMax) {
		t.Fatal("H=MAX should reject")
	}
}

// --- Appendix D negative vectors ---

func inputReason(t *testing.T, data []byte) string {
	t.Helper()
	_, err := ParseIJSON(data)
	if err == nil {
		return ""
	}
	if pe, ok := err.(*parseError); ok {
		return pe.reason
	}
	return "other"
}

func TestDJsonInput(t *testing.T) {
	// N1 duplicate v: A.2 envelope with a second "v":1 inserted.
	env := envelope(a2JCS, a2ID, a2Sig)
	dup := []byte(strings.Replace(string(env), `"v":1,`, `"v":1,"v":1,`, 1))
	if r := inputReason(t, dup); r != "duplicate-member-name" {
		t.Fatalf("N1 reason = %q", r)
	}
	// N2 lone surrogate.
	if r := inputReason(t, []byte(`"\uD800"`)); r != "lone-surrogate" {
		t.Fatalf("N2 reason = %q", r)
	}
	// N21 noncharacter.
	if r := inputReason(t, []byte(`{"ext":{"n":"\uFDD0"}}`)); r != "noncharacter" {
		t.Fatalf("N21 reason = %q", r)
	}
	// N22 negative zero.
	if r := inputReason(t, []byte(`{"v":1,"type":"pointer","actor":"`+testActor+`","created":-0,"nonce":"0","channel":"sha256:`+strings.Repeat("0", 64)+`","ref":{"hash":"sha256:`+strings.Repeat("0", 64)+`","locators":[]}}`)); r != "negative-zero" {
		t.Fatalf("N22 reason = %q", r)
	}
	// N23 leading BOM.
	if r := inputReason(t, append([]byte{0xEF, 0xBB, 0xBF}, env...)); r != "invalid-json" {
		t.Fatalf("N23 reason = %q", r)
	}
}

func TestDSchema(t *testing.T) {
	base := func() string { return a2JCS }
	cases := []struct {
		name string
		jcs  string
		typ  string
	}{
		{"N9 parents string", strings.Replace(base(), `"nonce":"81681"`, `"nonce":"81681","parents":"sha256:`+strings.Repeat("0", 64)+`"`, 1), "schema"},
		{"N10 pointer with descriptor", strings.Replace(base(), `"nonce":"81681"`, `"nonce":"81681","descriptor":{"hash":"sha256:`+strings.Repeat("0", 64)+`","locators":[]}`, 1), "schema"},
		{"N12 ref foo", strings.Replace(base(), `"locators":["https://example.invalid/spp/test-object"]`, `"locators":["https://example.invalid/spp/test-object"],"foo":1`, 1), "schema"},
	}
	for _, c := range cases {
		vd := Verify(envelope(c.jcs, a2ID, a2Sig))
		if vd.Status != StatusInvalid || vd.Stage != "schema" || vd.Reason != "schema" {
			t.Fatalf("%s => %v %s/%s", c.name, vd.Status, vd.Stage, vd.Reason)
		}
	}
	// N11 channel with ref.
	n11 := a6JCS[:len(a6JCS)-1] + `,"ref":{"hash":"sha256:` + strings.Repeat("0", 64) + `","locators":[]}}`
	vd := Verify(envelope(n11, a6ID, a6Sig))
	if vd.Stage != "schema" {
		t.Fatalf("N11 => %v %s/%s", vd.Status, vd.Stage, vd.Reason)
	}
	// N13 unknown top-level name.
	n13 := strings.Replace(a2JCS, `"v":1}`, `"v":1,"x":"not-ext"}`, 1)
	vd = Verify(envelope(n13, a2ID, a2Sig))
	if vd.Stage != "schema" {
		t.Fatalf("N13 => %v %s/%s", vd.Status, vd.Stage, vd.Reason)
	}
	// N18 unknown type.
	n18 := strings.Replace(a2JCS, `"type":"pointer"`, `"type":"futureThing"`, 1)
	vd = Verify(envelope(n18, a2ID, a2Sig))
	if vd.Status != StatusInvalid || vd.Stage != "schema" || vd.Reason != "unknown-type" {
		t.Fatalf("N18 => %v %s/%s", vd.Status, vd.Stage, vd.Reason)
	}
}

func TestDFullAssertion(t *testing.T) {
	cases := []struct {
		name   string
		modify func(string) string
		stage  string
	}{
		{"N3 created -1", func(s string) string { return strings.Replace(s, `"created":1789184927`, `"created":-1`, 1) }, "created"},
		{"N4 created 2^53", func(s string) string { return strings.Replace(s, `"created":1789184927`, `"created":9007199254740992`, 1) }, "created"},
		{"N5 nonce 2^64", func(s string) string { return strings.Replace(s, `"nonce":"81681"`, `"nonce":"18446744073709551616"`, 1) }, "nonce"},
		{"N6 nonce 018", func(s string) string { return strings.Replace(s, `"nonce":"81681"`, `"nonce":"018"`, 1) }, "nonce"},
		{"N7 uppercase hex", func(s string) string {
			return strings.Replace(s, `"channel":"sha256:0000058da39af8f5e2cb8c1268b45e6f198320a5e5ac53512f4b707e8672986b"`,
				`"channel":"sha256:0000058DA39AF8F5E2CB8C1268B45E6F198320A5E5AC53512F4B707E8672986B"`, 1)
		}, "identifier"},
		{"N8 short sha256", func(s string) string {
			return strings.Replace(s, `"channel":"sha256:0000058da39af8f5e2cb8c1268b45e6f198320a5e5ac53512f4b707e8672986b"`,
				`"channel":"sha256:0000058da39af8f5e2cb8c1268b45e6f198320a5e5ac53512f4b707e8672986"`, 1)
		}, "identifier"},
	}
	for _, c := range cases {
		vd := Verify(envelope(c.modify(a2JCS), a2ID, a2Sig))
		if vd.Status != StatusInvalid || vd.Stage != c.stage {
			t.Fatalf("%s => %v %s/%s (want stage %s)", c.name, vd.Status, vd.Stage, vd.Reason, c.stage)
		}
	}
}

func TestDEd25519(t *testing.T) {
	d, _ := hex.DecodeString("0000058da39af8f5e2cb8c1268b45e6f198320a5e5ac53512f4b707e8672986b")
	// Honest A.1 signature must verify as a raw triple.
	a1A, _ := hex.DecodeString(testAPub)
	a1S, _ := hex.DecodeString(a1Sig)
	if !SPPEd25519Verify(a1A, a1S, d) {
		t.Fatal("honest A.1 triple should verify")
	}
	// N14: S := S + L (both little-endian integers).
	sl := new(big.Int).SetBytes(reverseBytes(a1S[32:]))
	sl.Add(sl, groupL)
	n14sig := append(append([]byte{}, a1S[:32]...), reverseBytes(sl.FillBytes(make([]byte, 32)))...)
	if SPPEd25519Verify(a1A, n14sig, d) {
		t.Fatal("N14 S>=L should reject")
	}
	// N15: identity A.
	ident, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	if SPPEd25519Verify(ident, a1S, d) {
		t.Fatal("N15 identity A should reject")
	}
	// N19: mixed-order A.
	n19A, _ := hex.DecodeString("16a567fe7d4ef5482ab4012c369bf8c5f11e8d0c2559dcda50fde59708f8aee5")
	n19S, _ := hex.DecodeString("24ddc9d5e796d2dcdcc2783ec43d78e7d7a58b4d1e632ce0928605a5fbaec6dbfa6d1cd453bafe5e95be35bff2a6672ab0120ead94e6dfafc3a8d20a77ee9b02")
	if SPPEd25519Verify(n19A, n19S, d) {
		t.Fatal("N19 mixed-order A should reject")
	}
	// N20: mixed-order R.
	n20S, _ := hex.DecodeString("c922362a18692d23233d87c13bc28718285a74b2e19cd31f6d79fa5a045139244634162365ad0c684511ddb1cbf25126fe7cd6392ecdaeb6ff40ae484f1d630f")
	if SPPEd25519Verify(a1A, n20S, d) {
		t.Fatal("N20 mixed-order R should reject")
	}
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}
