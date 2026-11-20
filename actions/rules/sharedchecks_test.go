package rules

import (
	"context"
	"runtime"
	"sync"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

// madeChecks makes the checks of every example once for the tests of the
// package (CheckAllExamples, about six seconds), with how much the heap in
// use grew by them: after a collection before and after, so that the
// growth is what the checks keep.
var madeChecks = sync.OnceValues(func() (*AllExampleChecks, error) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	c, err := CheckAllExamples(context.Background())
	runtime.GC()
	runtime.ReadMemStats(&after)
	checksHeapGrowth = int64(after.HeapInuse) - int64(before.HeapInuse)
	return c, err
})

// checksHeapGrowth is how many bytes of the heap in use the checks
// madeChecks made keep, for the log of the first test that reads them
// (logChecksOnce).
var checksHeapGrowth int64

var logChecksOnce sync.Once

// sharedChecks are the checks of every example of every rule and quality
// rule, made once and read by the tests of the package, which do not change
// them. They stay in memory until the tests of the package end.
func sharedChecks(t *testing.T) *AllExampleChecks {
	t.Helper()
	c, err := madeChecks()
	if err != nil {
		t.Fatal(err)
	}
	logChecksOnce.Do(func() {
		t.Logf("the shared example checks keep %d MB of the heap in use", checksHeapGrowth>>20)
	})
	return c
}

// securityRuleIDs are the IDs of the rules of All, without the quality
// rules.
func securityRuleIDs() []lint.RuleID {
	var ids []lint.RuleID
	for _, r := range All() {
		ids = append(ids, r.Meta().ID)
	}
	return ids
}
