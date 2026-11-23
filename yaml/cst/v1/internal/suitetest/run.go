package suitetest

import (
	"sync"
	"testing"
)

var cache sync.Map // root → func() ([]Case, error)

// LoadCached is Load, run once per root for the test binary.
func LoadCached(root string) ([]Case, error) {
	f, _ := cache.LoadOrStore(root, sync.OnceValues(func() ([]Case, error) { return Load(root) }))
	return f.(func() ([]Case, error))()
}

// Run runs f as a subtest of t for each case without an error, skipping
// the cases in exclude (ID → reason), and counts the others in tl under
// check.
func Run(t *testing.T, cs []Case, check string, exclude map[string]string, tl *Tally, f func(*testing.T, Case)) {
	for _, c := range cs {
		if c.Error {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			if why, ok := exclude[c.ID]; ok {
				t.Skip("excluded: " + why)
			}
			defer tl.Count(check, t)
			f(t, c)
		})
	}
}
