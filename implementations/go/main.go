package main

// CLI for the RC3 clean-room verifier. See conformance/... handoff §4.
//
// Exit codes: 0 VALID, 1 INVALID, 2 UNSUPPORTED, 3 internal error.

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: spp-verify <file> | --batch <items.json> | --jcs-batch <items.json> | --ed-batch <items.json> | --suite <suite.json> | --diagnostic <file>")
		return 3
	}
	switch args[0] {
	case "--batch":
		if len(args) != 2 {
			return 3
		}
		return runBatch(args[1])
	case "--jcs-batch":
		if len(args) != 2 {
			return 3
		}
		return runJCSBatch(args[1])
	case "--ed-batch":
		if len(args) != 2 {
			return 3
		}
		return runEdBatch(args[1])
	case "--suite":
		if len(args) != 2 {
			return 3
		}
		return runSuite(args[1])
	case "--diagnostic":
		if len(args) != 2 {
			return 3
		}
		return runDiagnostic(args[1])
	default:
		if strings.HasPrefix(args[0], "--") {
			fmt.Fprintln(os.Stderr, "unknown mode:", args[0])
			return 3
		}
		return runSingle(args[0])
	}
}

// safeVerify isolates panics so the verifier is total at the process boundary.
// A final build must never reach the recover branch on any input.
func safeVerify(data []byte) (vd *Verdict) {
	defer func() {
		if r := recover(); r != nil {
			vd = &Verdict{Status: StatusError, Stage: "internal", Reason: fmt.Sprint(r)}
		}
	}()
	return Verify(data)
}

func runSingle(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read error:", err)
		return 3
	}
	vd := safeVerify(data)
	switch vd.Status {
	case StatusValid:
		fmt.Println("VALID")
		fmt.Printf("id: %s\n", vd.IDComputed)
		fmt.Printf("units: %d\n", vd.Units)
		fmt.Printf("target: %s\n", hex.EncodeToString(vd.Target))
		return 0
	case StatusUnsupported:
		fmt.Println("UNSUPPORTED")
		fmt.Println("stage: version")
		fmt.Println("reason: unknown-v")
		return 2
	case StatusInvalid:
		fmt.Println("INVALID")
		fmt.Printf("stage: %s\n", vd.Stage)
		fmt.Printf("reason: %s\n", vd.Reason)
		return 1
	default:
		fmt.Fprintln(os.Stderr, "internal error")
		return 3
	}
}

// diagLine prints label padded to a value column of 22, matching the handoff
// §4.6 layout.
func diagLine(w *bufio.Writer, label, value string) {
	fmt.Fprintf(w, "%-21s %s\n", label+":", value)
}

func runDiagnostic(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read error:", err)
		return 3
	}
	vd := safeVerify(data)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	if vd.HasJCS {
		diagLine(w, "JCS(U)", string(vd.JCS))
		diagLine(w, "canonical_body_bytes", fmt.Sprintf("%d", len(vd.JCS)))
	}
	if vd.D != nil {
		diagLine(w, "D", hex.EncodeToString(vd.D))
		diagLine(w, "id_computed", vd.IDComputed)
		diagLine(w, "H", vd.HHex)
	}
	if vd.HasUnits {
		diagLine(w, "units", fmt.Sprintf("%d", vd.Units))
		diagLine(w, "Wrequired", vd.Wrequired.String())
		diagLine(w, "target", hex.EncodeToString(vd.Target))
		if vd.PoWPass {
			diagLine(w, "PoW", "PASS")
		} else {
			diagLine(w, "PoW", "FAIL")
		}
	}
	if vd.SigKnown {
		if vd.SigPass {
			diagLine(w, "signature", "PASS")
		} else {
			diagLine(w, "signature", "FAIL")
		}
	}
	switch vd.Status {
	case StatusValid:
		diagLine(w, "status", "VALID")
	case StatusUnsupported:
		diagLine(w, "status", "UNSUPPORTED")
	case StatusInvalid:
		diagLine(w, "status", "INVALID")
	default:
		diagLine(w, "status", "ERROR")
	}
	if vd.Stage != "" {
		diagLine(w, "stage", vd.Stage)
	}
	if vd.Reason != "" {
		diagLine(w, "reason", vd.Reason)
	}
	return 0
}

// batchItem is a differential-harness record.
type batchItem struct {
	Name string `json:"name"`
	UTF8 string `json:"utf8"`
}

func readItems(path string) ([]batchItem, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var items []batchItem
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func runBatch(path string) int {
	items, err := readItems(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "items error:", err)
		return 3
	}
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for _, it := range items {
		vd := safeVerify([]byte(it.UTF8))
		switch vd.Status {
		case StatusValid:
			fmt.Fprintf(w, "{\"name\":%s,\"status\":\"VALID\",\"id\":%s,\"units\":%d,\"target_hex\":%s}\n",
				jsonStr(it.Name), jsonStr(vd.IDComputed), vd.Units, jsonStr(hex.EncodeToString(vd.Target)))
		case StatusUnsupported:
			fmt.Fprintf(w, "{\"name\":%s,\"status\":\"UNSUPPORTED\",\"stage\":\"version\",\"reason\":\"unknown-v\"}\n",
				jsonStr(it.Name))
		case StatusInvalid:
			fmt.Fprintf(w, "{\"name\":%s,\"status\":\"INVALID\",\"stage\":%s,\"reason\":%s}\n",
				jsonStr(it.Name), jsonStr(vd.Stage), jsonStr(vd.Reason))
		default:
			fmt.Fprintf(w, "{\"name\":%s,\"status\":\"ERROR\",\"stage\":\"internal\",\"reason\":%s}\n",
				jsonStr(it.Name), jsonStr(vd.Reason))
		}
	}
	return 0
}

func runJCSBatch(path string) int {
	items, err := readItems(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "items error:", err)
		return 3
	}
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for _, it := range items {
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(w, "{\"name\":%s,\"status\":\"INVALID\",\"reason\":\"internal\"}\n", jsonStr(it.Name))
				}
			}()
			v, err := ParseIJSON([]byte(it.UTF8))
			if err != nil {
				reason := "invalid-json"
				if pe, ok := err.(*parseError); ok {
					reason = pe.reason
				}
				fmt.Fprintf(w, "{\"name\":%s,\"status\":\"INVALID\",\"reason\":%s}\n", jsonStr(it.Name), jsonStr(reason))
				return
			}
			jcs := Canonicalize(v)
			fmt.Fprintf(w, "{\"name\":%s,\"status\":\"OK\",\"jcs_hex\":%s}\n", jsonStr(it.Name), jsonStr(hex.EncodeToString(jcs)))
		}()
	}
	return 0
}

type edItem struct {
	Name string `json:"name"`
	A    string `json:"A"`
	Sig  string `json:"sig"`
	D    string `json:"D"`
}

func runEdBatch(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "items error:", err)
		return 3
	}
	var items []edItem
	if err := json.Unmarshal(data, &items); err != nil {
		fmt.Fprintln(os.Stderr, "items error:", err)
		return 3
	}
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for _, it := range items {
		status := "INVALID"
		func() {
			defer func() {
				if r := recover(); r != nil {
					status = "INVALID"
				}
			}()
			a, e1 := hex.DecodeString(it.A)
			s, e2 := hex.DecodeString(it.Sig)
			d, e3 := hex.DecodeString(it.D)
			if e1 == nil && e2 == nil && e3 == nil && SPPEd25519Verify(a, s, d) {
				status = "VALID"
			}
		}()
		fmt.Fprintf(w, "{\"name\":%s,\"status\":%s}\n", jsonStr(it.Name), jsonStr(status))
	}
	return 0
}
