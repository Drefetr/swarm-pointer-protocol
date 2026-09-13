package main

// §20 protocol-validity decision function. The pipeline order here is the
// order mandated by the handoff §3 / spec §20.

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

type Status int

const (
	StatusValid Status = iota
	StatusInvalid
	StatusUnsupported
	StatusError
)

// Verdict is the outcome of the §20 pipeline plus the consensus-visible
// intermediates needed by --diagnostic.
type Verdict struct {
	Status Status
	Stage  string
	Reason string

	JCS        []byte
	HasJCS     bool
	D          []byte
	IDComputed string
	HHex       string
	Units      int64
	HasUnits   bool
	Wrequired  *big.Int
	Target     []byte
	PoWPass    bool
	SigPass    bool
	SigKnown   bool
}

const (
	maxCanonicalBody       = 1048576
	maxLocatorCount        = 256
	maxLocatorBytes        = 8192
	maxParentCount         = 1024
	workUnit               = 65536
	channelDescriptionCost = 16
	maxCreated             = 9007199254740991
)

var (
	bigMax = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	// signaturePrefix is ASCII("SPP/1/assertion") || 0x00 (16 bytes).
	signaturePrefix = []byte("SPP/1/assertion\x00")
)

func fail(vd *Verdict, stage, reason string) *Verdict {
	vd.Status = StatusInvalid
	vd.Stage = stage
	vd.Reason = reason
	return vd
}

// Verify runs the full §20 pipeline over a received byte string.
func Verify(data []byte) *Verdict {
	vd := &Verdict{}

	// 1. §6 JSON input.
	root, err := ParseIJSON(data)
	if err != nil {
		if pe, ok := err.(*parseError); ok {
			return fail(vd, "json-input", pe.reason)
		}
		return fail(vd, "json-input", "invalid-json")
	}

	// 2. §19 version and type classification.
	vval := root.Get("v")
	if vval == nil || vval.Kind != KindNumber {
		return fail(vd, "version", "schema")
	}
	if vval.Num != 1 {
		vd.Status = StatusUnsupported
		vd.Stage = "version"
		vd.Reason = "unknown-v"
		return vd
	}
	typv := root.Get("type")
	typ := ""
	if typv != nil && typv.Kind == KindString {
		typ = typv.Str
	}
	if typ != "channel" && typ != "pointer" {
		return fail(vd, "schema", "unknown-type")
	}

	// 3. Reconstruct U: remove only top-level "id" and "sig".
	u := &Value{Kind: KindObject}
	for _, m := range root.Obj {
		if m.Name == "id" || m.Name == "sig" {
			continue
		}
		u.Obj = append(u.Obj, m)
	}

	// 4. §7A structural schema.
	if r := validateSchema(u, typ); r != "" {
		return fail(vd, "schema", r)
	}

	// 5. §4 identifier grammar.
	if r := validateIdentifiers(u, typ); r != "" {
		return fail(vd, "identifier", r)
	}
	actor := u.Get("actor").Str
	if !isActorID(actor) {
		return fail(vd, "identifier", "identifier")
	}

	// 5b. §17 nonce and §18 created.
	if !isNonce(u.Get("nonce").Str) {
		return fail(vd, "nonce", "nonce")
	}
	created := u.Get("created").Num
	if !isBinary64Integer(created) || created < 0 || created > maxCreated {
		return fail(vd, "created", "created")
	}

	// 6. §6 JCS(U), §5 maxima.
	jcs := Canonicalize(u)
	vd.JCS = jcs
	vd.HasJCS = true
	if len(jcs) > maxCanonicalBody {
		return fail(vd, "length", "jcs-too-large")
	}
	locCount, parentCount, locators, reason := structuralCounts(u, typ)
	if reason != "" {
		return fail(vd, "length", reason)
	}
	if locCount > maxLocatorCount {
		return fail(vd, "length", "too-many-locators")
	}
	for _, loc := range locators {
		if len(loc) > maxLocatorBytes {
			return fail(vd, "length", "locator-too-long")
		}
	}
	if parentCount > maxParentCount {
		return fail(vd, "length", "too-many-parents")
	}

	// 6b. D = SHA-256(JCS(U)); recomputed id.
	sum := sha256.Sum256(jcs)
	d := sum[:]
	vd.D = d
	idComputed := "sha256:" + hex.EncodeToString(d)
	vd.IDComputed = idComputed

	// 7. Transmitted id.
	idv := root.Get("id")
	if idv == nil || idv.Kind != KindString {
		return fail(vd, "identity", "missing-id")
	}
	if !isSHA256ID(idv.Str) {
		return fail(vd, "identifier", "identifier")
	}
	if idv.Str != idComputed {
		return fail(vd, "identity", "id-mismatch")
	}

	// 8. §15/§16 units and PoW.
	units := int64(1) + int64((len(jcs)+1023)/1024) + int64(locCount) + int64(parentCount)
	if typ == "channel" {
		units += channelDescriptionCost
	}
	vd.Units = units
	vd.HasUnits = true
	wreq := new(big.Int).Mul(big.NewInt(units), big.NewInt(workUnit))
	vd.Wrequired = wreq
	target := new(big.Int).Div(bigMax, wreq)
	vd.Target = leftPad32(target.Bytes())
	h := new(big.Int).SetBytes(d)
	vd.HHex = hex.EncodeToString(d)
	vd.PoWPass = h.Cmp(target) <= 0
	if !vd.PoWPass {
		return fail(vd, "work", "insufficient-work")
	}

	// 9. §8/§8A signature.
	sigv := root.Get("sig")
	if sigv == nil || sigv.Kind != KindString || !isSigHex(sigv.Str) {
		vd.SigPass = false
		vd.SigKnown = true
		return fail(vd, "signature", "signature")
	}
	sigBytes, _ := hex.DecodeString(sigv.Str)
	abytes, _ := hex.DecodeString(actor[len("ed25519:"):])
	ok := SPPEd25519Verify(abytes, sigBytes, d)
	vd.SigPass = ok
	vd.SigKnown = true
	if !ok {
		return fail(vd, "signature", "signature")
	}

	vd.Status = StatusValid
	return vd
}

// structuralCounts computes locator_count, parent_count and the list of
// decoded locator strings for the current type (§16).
func structuralCounts(u *Value, typ string) (locCount, parentCount int, locators []string, reason string) {
	switch typ {
	case "pointer":
		ref := u.Get("ref")
		if ref != nil {
			if l := ref.Get("locators"); l != nil {
				for _, el := range l.Arr {
					locators = append(locators, el.Str)
				}
			}
		}
		locCount = len(locators)
		if p := u.Get("parents"); p != nil {
			parentCount = len(p.Arr)
		}
	case "channel":
		if d := u.Get("descriptor"); d != nil {
			if l := d.Get("locators"); l != nil {
				for _, el := range l.Arr {
					locators = append(locators, el.Str)
				}
			}
		}
		locCount = len(locators)
	}
	return locCount, parentCount, locators, ""
}

func leftPad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
