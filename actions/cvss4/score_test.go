package cvss4

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestAll: every vector ParseVector takes has the score of the reference
// calculator. testdata/all.sha256 is the SHA-256 of what testdata/all.js
// writes, "<vector> <score>" on a line for each, in the order below; to
// remake it (node v22 was used, and it takes about 40 seconds):
//
//	cd actions/cvss4 && node testdata/all.js | sha256sum | cut -d' ' -f1 > testdata/all.sha256
//
// When it fails, write the lines here the same way and compare them with
// the output of all.js to find the vectors that differ.
func TestAll(t *testing.T) {
	want, err := os.ReadFile("testdata/all.sha256")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	n := 0
	var walk func(i int, prefix string)
	walk = func(i int, prefix string) {
		if i == len(metrics) {
			for _, e := range []string{"", "/E:A", "/E:P", "/E:U"} {
				v, err := ParseVector(prefix + e)
				if err != nil {
					t.Fatal(err)
				}
				h.Write([]byte(prefix + e + " " + v.Score().String() + "\n"))
				n++
			}
			return
		}
		for _, x := range metrics[i].values {
			walk(i+1, prefix+"/"+metrics[i].name+":"+string(x))
		}
	}
	walk(0, "CVSS:4.0")
	if n != 419904 {
		t.Errorf("%d vectors, want 419904", n)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != strings.TrimSpace(string(want)) {
		t.Errorf("the scores differ from the calculator's: SHA-256 %s, want %s", got, want)
	}
}

// TestTables: the tables are those of the calculator, all of them, also
// what no vector of ParseVector reaches (testdata/tables.json, written by
// testdata/tables.js).
func TestTables(t *testing.T) {
	b, err := os.ReadFile("testdata/tables.json")
	if err != nil {
		t.Fatal(err)
	}
	var want any
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	mine, err := json.Marshal(map[string]any{
		"lookup": lookup,
		"maxComposed": map[string]any{
			"eq1": maxComposed.eq1, "eq2": maxComposed.eq2, "eq3": maxComposed.eq3, "eq4": maxComposed.eq4, "eq5": maxComposed.eq5,
		},
		"maxSeverity": map[string]any{
			"eq1": maxSeverity.eq1, "eq2": maxSeverity.eq2, "eq3eq6": maxSeverity.eq3eq6, "eq4": maxSeverity.eq4, "eq5": maxSeverity.eq5,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got any
	if err := json.Unmarshal(mine, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the tables differ from testdata/tables.json:\n%s", mine)
	}
}

// TestScores: the scores of the vectors of the registry, which the
// reference calculator gave, and the ends of the scale.
func TestScores(t *testing.T) {
	for v, want := range map[string]string{
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N":     "9.9",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N/E:U": "9.0",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N/E:U": "6.7",
		"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N/E:P": "7.3",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H":     "10.0",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N":     "0.0",
		"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N":     "1.0",
	} {
		p, err := ParseVector(v)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Score().String(); got != want {
			t.Errorf("%s = %s, want %s", v, got, want)
		}
	}
}

func TestScoreString(t *testing.T) {
	for tenths, want := range map[uint8]string{0: "0.0", 1: "0.1", 90: "9.0", 99: "9.9", 100: "10.0"} {
		if got := (Score{tenths}).String(); got != want {
			t.Errorf("Score{%d} = %s, want %s", tenths, got, want)
		}
	}
	if got := (Score{46}).Tenths(); got != 46 {
		t.Errorf("Tenths = %d", got)
	}
}

// TestJSRound: Math.round of JavaScript, which rounds a half up.
func TestJSRound(t *testing.T) {
	for x, want := range map[float64]float64{0: 0, 0.49999999999999994: 0, 0.5: 1, 2.5: 3, 99.49999999999999: 99, 99.5: 100} {
		if got := jsRound(x); got != want {
			t.Errorf("jsRound(%v) = %v, want %v", x, got, want)
		}
	}
}

// TestZeroVector: a Vector not made by ParseVector is no vector, and is
// not scored as one (its metrics would read as none of their values).
func TestZeroVector(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("the zero Vector was scored")
		}
	}()
	_ = Vector{}.Score()
}
