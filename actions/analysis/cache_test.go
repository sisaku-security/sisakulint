package analysis

import "testing"

// TestParseCacheMode: the four values of cache-mode, as GitHub takes them:
// written in lower case, nothing else.
func TestParseCacheMode(t *testing.T) {
	for _, c := range []struct {
		s    string
		want CacheMode
		ok   bool
	}{
		{"read", CacheModeRead, true},
		{"write", CacheModeWrite, true},
		{"write-only", CacheModeWriteOnly, true},
		{"none", CacheModeNone, true},
		{"WRITE", CacheModeUnset, false},
		{"", CacheModeUnset, false},
	} {
		got, ok := ParseCacheMode(c.s)
		if got != c.want || ok != c.ok {
			t.Errorf("%q: %v %v", c.s, got, ok)
		}
		if ok && got.String() != c.s {
			t.Errorf("%q: String %q", c.s, got.String())
		}
	}
}
