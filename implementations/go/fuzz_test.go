package main

import "testing"

// FuzzVerify drives the §20 pipeline over arbitrary byte strings. A panic is a
// delivery blocker (handoff §6 trap 8). Run with:
//
//	go test -run=^$ -fuzz=FuzzVerify -fuzztime=60s
func FuzzVerify(f *testing.F) {
	seeds := [][]byte{
		[]byte(a1JCS), []byte(a2JCS), []byte(a3JCS),
		[]byte(a6JCS), []byte(a7JCS), []byte(a8JCS),
		envelope(a1JCS, a1ID, a1Sig),
		[]byte("{}"), []byte("[]"), []byte("null"), []byte("1"), []byte("-0"),
		[]byte("\"\\uD800\""), []byte("{\"ext\":{\"n\":\"\\uFDD0\"}}"),
		[]byte{0xEF, 0xBB, 0xBF, '{', '}'},
		[]byte("{\"v\":1,\"type\":\"pointer\"}"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = Verify(data)
	})
}
