package shell

import (
	"strings"
	"testing"
)

// BenchmarkPlaces reads three places of a script of 1 MB (TestContextsLarge).
func BenchmarkPlaces(b *testing.B) {
	src := strings.Repeat("echo \"a $(date) b\" 'c' <<<x # d\n", 1<<15)
	at := []int{0, len(src) / 2, len(src) - 1}
	b.ReportAllocs()
	for b.Loop() {
		Places(src, at)
	}
}
