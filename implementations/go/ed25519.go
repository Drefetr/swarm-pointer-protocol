package main

// §8A SPP-Ed25519-1 verification profile. This deliberately does not use
// crypto/ed25519.Verify: that routine does not enforce canonical re-encoding
// of A and R, identity rejection, or prime-order subgroup membership, and it
// accepts the cofactored equation. SPP validity is the exact equation on the
// prime-order subgroup.

import (
	"bytes"
	"crypto/sha512"
	"math/big"

	"filippo.io/edwards25519"
)

// groupL is the prime order L = 2^252 + 27742317777372353535851937790883648493.
var groupL = func() *big.Int {
	l, ok := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	if !ok {
		panic("groupL constant")
	}
	return l
}()

// mulByL computes [L]P by double-and-add, since L is not representable as a
// reduced edwards25519.Scalar. Used only for subgroup membership checks.
func mulByL(p *edwards25519.Point) *edwards25519.Point {
	res := edwards25519.NewIdentityPoint()
	for i := groupL.BitLen() - 1; i >= 0; i-- {
		res.Double(res)
		if groupL.Bit(i) == 1 {
			res.Add(res, p)
		}
	}
	return res
}

// SPPEd25519Verify implements §8A steps 1-10. Abytes is the 32-byte public
// key, sig is the 64-byte R||S signature, and D is the 32-byte assertion
// digest. M is signaturePrefix || D.
func SPPEd25519Verify(abytes, sig, D []byte) bool {
	// Step 1.
	if len(abytes) != 32 || len(sig) != 64 || len(D) != 32 {
		return false
	}
	rbytes := sig[:32]
	sbytes := sig[32:]

	// Step 2: S < L.
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(sbytes)
	if err != nil {
		return false
	}

	// Steps 3 and 4: decode A and R (RFC 8032 §5.1.3).
	A, err := new(edwards25519.Point).SetBytes(abytes)
	if err != nil {
		return false
	}
	R, err := new(edwards25519.Point).SetBytes(rbytes)
	if err != nil {
		return false
	}

	// Steps 5 and 6: canonical re-encoding.
	if !bytes.Equal(A.Bytes(), abytes) {
		return false
	}
	if !bytes.Equal(R.Bytes(), rbytes) {
		return false
	}

	identity := edwards25519.NewIdentityPoint()

	// Step 7: A is not identity and is in the order-L subgroup.
	if A.Equal(identity) == 1 {
		return false
	}
	if mulByL(A).Equal(identity) != 1 {
		return false
	}

	// Step 8: R is not identity and is in the order-L subgroup.
	if R.Equal(identity) == 1 {
		return false
	}
	if mulByL(R).Equal(identity) != 1 {
		return false
	}

	// Step 9: k = SHA-512(R || A || M) mod L.
	h := sha512.New()
	h.Write(rbytes)
	h.Write(abytes)
	h.Write(signaturePrefix)
	h.Write(D)
	k, err := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
	if err != nil {
		return false
	}

	// Step 10: [S]B == R + [k]A exactly.
	lhs := new(edwards25519.Point).ScalarBaseMult(s)
	rhs := new(edwards25519.Point).ScalarMult(k, A)
	rhs.Add(rhs, R)
	return lhs.Equal(rhs) == 1
}
