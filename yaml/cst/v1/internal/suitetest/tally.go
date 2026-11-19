package suitetest

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Tally counts, for each check, the suite subtests that ran and passed.
type Tally struct {
	mu sync.Mutex
	m  map[string]*counts
}

type counts struct{ pass, total int }

// Count records t under check; call it deferred, after the checks.
func (tl *Tally) Count(check string, t testing.TB) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if tl.m == nil {
		tl.m = map[string]*counts{}
	}
	c := tl.m[check]
	if c == nil {
		c = &counts{}
		tl.m[check] = c
	}
	c.total++
	if !t.Failed() {
		c.pass++
	}
}

// String is "check pass/total" for each check, sorted, or "" when nothing ran.
func (tl *Tally) String() string {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	var parts []string
	for n, c := range tl.m {
		parts = append(parts, fmt.Sprintf("%s %d/%d", n, c.pass, c.total))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
