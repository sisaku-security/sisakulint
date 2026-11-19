package labeler

import (
	"slices"
	"testing"
)

func TestReleaseOf(t *testing.T) {
	for _, c := range []struct {
		ref  string
		want Release
	}{
		{"v7", Release{Format: FormatKeysLimits, LocalFirst: true, TokenDefault: true, PRNumber: true}},
		{"v6.1.0", Release{Format: FormatKeysLimits, LocalFirst: true, TokenDefault: true, PRNumber: true}},
		{"v6.0.1", Release{Format: FormatKeys, LocalFirst: true, TokenDefault: true, PRNumber: true}},
		{"v5", Release{Format: FormatKeys, LocalFirst: true, TokenDefault: true, PRNumber: true}},
		{"v5.0.0", Release{Format: FormatKeys, LocalFirst: true, TokenDefault: true, PRNumber: true}},
		{"8558fd74291d67161a8a78ce36a881fa63b766a9", Release{Format: FormatKeys, LocalFirst: true, TokenDefault: true, PRNumber: true}},
		{"v4", Release{Format: FormatAnyAll, LocalFirst: true, TokenDefault: true, PRNumber: true}},
		{"v4.2.0", Release{Format: FormatAnyAll, TokenDefault: true}},
		{"0967ca812e7fdc8f5f71402a1b486d5bd061fe20", Release{Format: FormatAnyAll, TokenDefault: true}},
		{"v4.0.3", Release{Format: FormatAnyAll, TokenDefault: true}},
		{"v4.0.2", Release{Format: FormatAnyAll}},
		{"v3", Release{Format: FormatAnyAll}},
		{"2.2.0", Release{Format: FormatGlobs}},
		{"v2", Release{Format: FormatGlobs}},
		{"v2.0.0", Release{Format: FormatGlobs}},
	} {
		got, ok := ReleaseOf(c.ref)
		if !ok || len(got) != 1 || got[0] != c.want {
			t.Errorf("ReleaseOf(%s) = %v, %v; want [%v], true", c.ref, got, ok, c.want)
		}
	}
	for _, ref := range []string{"main", "v8", "v1", "v5.0.0-beta.1", "v3-preview", "0000000000000000000000000000000000000000"} {
		got, ok := ReleaseOf(ref)
		if ok {
			t.Errorf("ReleaseOf(%s) is known", ref)
		}
		if !slices.Contains(got, Release{Format: FormatGlobs}) || !slices.Contains(got, Release{Format: FormatKeysLimits, LocalFirst: true, TokenDefault: true, PRNumber: true}) {
			t.Errorf("ReleaseOf(%s) = %v, want every reading of the table", ref, got)
		}
		for i, r := range got {
			if slices.Contains(got[:i], r) {
				t.Errorf("ReleaseOf(%s) has %v twice", ref, r)
			}
		}
	}
}
