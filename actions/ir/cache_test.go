package ir

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

// TestCacheWriteOfCaller: a called workflow's job saves to the cache on
// its callers' events when it writes cache-mode write and its caller
// writes none; a caller that writes read limits it, and one that writes
// write is reported itself.
func TestCacheWriteOfCaller(t *testing.T) {
	const called = "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    cache-mode: write\n    steps:\n      - run: make\n"
	const plain = "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
	for _, c := range []struct {
		name, called, caller string
		want                 bool
	}{
		{"the caller writes none", called, "", true},
		{"the caller writes read", called, "    cache-mode: read\n", false},
		{"the caller writes write: reported at the caller", called, "    cache-mode: write\n", false},
		{"the called writes none", plain, "", false},
	} {
		x := calledIR(t, [2]string{".github/workflows/called.yml", c.called},
			[2]string{".github/workflows/ci.yml", "on: pull_request_target\njobs:\n  c:\n" + c.caller + "    uses: ./.github/workflows/called.yml\n"})
		j := x.allJobs()[0]
		if got := len(j.cacheWriteOn) > 0; got != c.want {
			t.Errorf("%s: cacheWriteOn %v", c.name, j.cacheWriteOn)
		}
	}
}

// TestCacheSaveOfWritingCaller: a called job that writes no cache-mode
// saves to the cache on the events of a caller that writes write: its
// steps' kinds read those events, though writable-job is the
// caller's.
func TestCacheSaveOfWritingCaller(t *testing.T) {
	const called = "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/cache/save@v4\n        with: {path: build, key: \"${{ github.event.pull_request.title }}\"}\n"
	x := calledIR(t, [2]string{".github/workflows/called.yml", called},
		[2]string{".github/workflows/ci.yml", "on: pull_request_target\njobs:\n  c:\n    cache-mode: write\n    uses: ./.github/workflows/called.yml\n"})
	if j := x.allJobs()[0]; len(j.cacheWriteOn) != 0 {
		t.Errorf("writable-job on the called job: %v", j.cacheWriteOn)
	}
	s := x.allCacheSaves()
	if len(s) != 1 || len(s[0].cacheWriteOn) == 0 || len(s[0].keyRefs) == 0 {
		t.Fatalf("saves %+v", s)
	}
	// a caller that writes read limits it: the run does not start, or saves nothing
	x = calledIR(t, [2]string{".github/workflows/called.yml", called},
		[2]string{".github/workflows/ci.yml", "on: pull_request_target\njobs:\n  c:\n    cache-mode: read\n    uses: ./.github/workflows/called.yml\n"})
	if s := x.allCacheSaves(); len(s) != 0 {
		t.Errorf("a caller that writes read: saves %+v", s)
	}
}

// TestCacheWriteOn: a job of an attacker's event saves to the cache only by
// a cache-mode that writes, the job's or else the workflow's; push is none
// of the attacker's events.
func TestCacheWriteOn(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"none written", "on: pull_request_target\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: a\n", false},
		{"the job's", "on: pull_request_target\njobs:\n  j:\n    runs-on: x\n    cache-mode: write-only\n    steps:\n      - run: a\n", true},
		{"the workflow's", "on: issue_comment\ncache-mode: write\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: a\n", true},
		{"the job's read wins", "on: issue_comment\ncache-mode: write\njobs:\n  j:\n    runs-on: x\n    cache-mode: read\n    steps:\n      - run: a\n", false},
		{"push", "on: push\ncache-mode: write\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: a\n", false},
		{"an if that keeps the event out", "on: issue_comment\ncache-mode: write\njobs:\n  j:\n    if: github.event_name == 'push'\n    runs-on: x\n    steps:\n      - run: a\n", false},
	} {
		tree := cst.ParseMode([]byte(c.src), cst.ModeGitHub)
		w, _ := workflow.Parse(tree)
		x := New(".github/workflows/w.yml", tree, w, nil)
		j := x.allJobs()[0]
		if got := len(j.cacheWriteOn) > 0; got != c.want {
			t.Errorf("%s: cacheWriteOn %v", c.name, j.cacheWriteOn)
		}
		if c.want && j.cacheApproval != analysis.ApprovalNone {
			t.Errorf("%s: approval %v", c.name, j.cacheApproval)
		}
	}
}

// TestCacheModeNoWrite: the fix writes read for write and none for
// write-only, where the cache-mode that lets the job save is written; a
// cache-mode reached through an alias is left to a person.
func TestCacheModeNoWrite(t *testing.T) {
	steps := "    runs-on: x\n    steps:\n      - run: a\n"
	for _, c := range []struct {
		name, src, want string
	}{
		{"the job's write", "on: issues\njobs:\n  j:\n    cache-mode: write\n" + steps, "on: issues\njobs:\n  j:\n    cache-mode: read\n" + steps},
		{"the job's write-only", "on: issues\njobs:\n  j:\n    cache-mode: write-only\n" + steps, "on: issues\njobs:\n  j:\n    cache-mode: none\n" + steps},
		{"the workflow's", "on: issues\ncache-mode: write\njobs:\n  j:\n" + steps, "on: issues\ncache-mode: read\njobs:\n  j:\n" + steps},
		{"a literal", "on: issues\ncache-mode: ${{ 'write' }}\njobs:\n  j:\n" + steps, "on: issues\ncache-mode: read\njobs:\n  j:\n" + steps},
		{"an alias", "on: issues\ncache-mode: &m write\njobs:\n  j:\n    cache-mode: *m\n" + steps, ""},
	} {
		tree := cst.ParseMode([]byte(c.src), cst.ModeGitHub)
		w, _ := workflow.Parse(tree)
		x := New(".github/workflows/w.yml", tree, w, nil)
		p := x.allJobs()[0].cacheModeNoWrite(x.RuleAccess())
		if c.want == "" {
			if p.Fix != nil || p.NoFix == nil {
				t.Errorf("%s: %+v", c.name, p)
			}
			continue
		}
		if p.Fix == nil {
			t.Fatalf("%s: no fix: %+v", c.name, p.NoFix)
		}
		res, err := edit.Apply(x.tree, p.Fix.Edits)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := string(res.Tree.Bytes()); got != c.want {
			t.Errorf("%s: got\n%s\nwant\n%s", c.name, got, c.want)
		}
	}
}
