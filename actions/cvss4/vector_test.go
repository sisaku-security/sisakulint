package cvss4

import (
	"strings"
	"testing"
)

const baseVector = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:L/VA:N/SC:H/SI:N/SA:L"

func TestParseVector(t *testing.T) {
	v, err := ParseVector(baseVector)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"AV": "N", "AT": "P", "UI": "A", "VI": "L", "SA": "L", "E": "A", "CR": "H", "IR": "H", "AR": "H"} {
		if got := v.value(name); got != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
	for _, e := range []string{"A", "P", "U"} {
		v, err := ParseVector(baseVector + "/E:" + e)
		if err != nil || v.value("E") != e {
			t.Errorf("E:%s is read as %s, %v", e, v.value("E"), err)
		}
	}
}

// TestParseVectorRejects: what the registry never writes is not scored as
// something else.
func TestParseVectorRejects(t *testing.T) {
	for name, s := range map[string]string{
		"CVSS 3.1":               strings.Replace(baseVector, "4.0", "3.1", 1),
		"no prefix":              strings.TrimPrefix(baseVector, "CVSS:4.0/"),
		"a metric left out":      strings.Replace(baseVector, "/AT:P", "", 1),
		"out of order":           strings.Replace(baseVector, "AV:N/AC:L", "AC:L/AV:N", 1),
		"twice":                  baseVector + "/SA:L",
		"a value it has not":     strings.Replace(baseVector, "AV:N", "AV:X", 1),
		"two letters":            strings.Replace(baseVector, "AV:N", "AV:NN", 1),
		"no value":               strings.Replace(baseVector, "AV:N", "AV:", 1),
		"no colon":               strings.Replace(baseVector, "AV:N", "AVN", 1),
		"E not defined":          baseVector + "/E:X",
		"E twice":                baseVector + "/E:A/E:A",
		"an environmental one":   baseVector + "/E:A/CR:H",
		"environmental, no E":    baseVector + "/CR:H",
		"a supplemental one":     baseVector + "/E:A/S:N",
		"a trailing slash":       baseVector + "/",
		"empty":                  "",
		"a lower-case prefix":    strings.Replace(baseVector, "CVSS", "cvss", 1),
		"environmental before E": baseVector + "/CR:H/E:A",
	} {
		if _, err := ParseVector(s); err == nil {
			t.Errorf("%s: ParseVector(%q) took it", name, s)
		}
	}
}
