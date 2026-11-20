package rules

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// TestRangeHas: the ranges of the advisories of the actions ecosystem on
// 2026-10-15.
func TestRangeHas(t *testing.T) {
	for _, c := range []struct {
		rng, version string
		want         bool
	}{
		{">= 4.0.0, < 4.1.3", "v4.1.2", true},
		{">= 4.0.0, < 4.1.3", "4.1.3", false},
		{">= 4.0.0, < 4.1.3", "v4", true}, // GitHub reads 4 as 4.0.0
		{">= 4.0.0, < 4.1.3", "3.9.9", false},
		{"<= 45.0.7", "v44.5.1", true},
		{"< 41", "v40.2.0", true},
		{"< 41", "v41", false},
		{"= 1", "v1", true},
		{"= 1", "1.0.3", false},
		{">= 3.26.11, <= 3.28.2", "v3.28.2", true},
		{">= 2.26.11, < 3.0.0", "v3.28.2", false},
		{">= 87, < 90", "89", true},
		{"< 2.0.2", "v2.0.2-rc1", true},
	} {
		v, err := facts.ParsePackageVersion(c.version)
		if err != nil {
			t.Fatal(err)
		}
		r, _ := facts.ParseVersionRange(c.rng)
		got, err := rangeHas(r, v)
		if err != nil || got != c.want {
			t.Errorf("rangeHas(%q, %s) = %v, %v; want %v", c.rng, c.version, got, err, c.want)
		}
	}
	v, _ := facts.ParsePackageVersion("1.0.0")
	for _, bad := range []string{"1.0.0", "~> 1", "< main"} {
		r, _ := facts.ParseVersionRange(bad)
		if _, err := rangeHas(r, v); err == nil {
			t.Errorf("rangeHas(%q) took it", bad)
		}
	}
}
