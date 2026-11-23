package workflow

import "testing"

// cache-mode (schema/additions.json), against what GitHub took on
// the runs of the experiment cache-mode.
// The values GitHub rejected are in TestCheckRest; what the model reads is
// in TestCacheModeField.
func TestCacheMode(t *testing.T) {
	steps := "    runs-on: x\n    steps:\n      - run: a\n"
	for _, tt := range []struct {
		name, src string
		want      []Code
	}{
		{"workflow read", "on: push\ncache-mode: read\njobs:\n  j:\n" + steps, nil},
		{"job write-only", "on: push\njobs:\n  j:\n    cache-mode: write-only\n" + steps, nil},
		{"job write", "on: push\njobs:\n  j:\n    cache-mode: write\n" + steps, nil},
		{"none", "on: push\njobs:\n  j:\n    cache-mode: none\n" + steps, nil},
		{"literal", "on: push\ncache-mode: ${{ 'none' }}\njobs:\n  j:\n" + steps, nil},
		{"call", "on: push\njobs:\n  j:\n    cache-mode: read\n    uses: ./.github/workflows/c.yml\n", nil},
		{"called", "on: workflow_call\ncache-mode: write\njobs:\n  j:\n" + steps, nil},
	} {
		_, diags, _ := parse(t, tt.src)
		wantCodes(t, tt.name, diags, tt.want...)
	}
}

// TestCacheModeField: the model reads cache-mode of the workflow and of a
// job as written; a literal ${{ }} is folded to its string.
func TestCacheModeField(t *testing.T) {
	steps := "    runs-on: x\n    steps:\n      - run: a\n"
	for _, tt := range []struct {
		name, src   string
		wf, job     string
		wfSt, jobSt Status
	}{
		{"none written", "on: push\njobs:\n  j:\n" + steps, "", "", Absent, Absent},
		{"workflow", "on: push\ncache-mode: write\njobs:\n  j:\n" + steps, "write", "", Present, Absent},
		{"job", "on: push\njobs:\n  j:\n    cache-mode: write-only\n" + steps, "", "write-only", Absent, Present},
		{"both", "on: push\ncache-mode: read\njobs:\n  j:\n    cache-mode: none\n" + steps, "read", "none", Present, Present},
		{"literal", "on: push\ncache-mode: ${{ 'write' }}\njobs:\n  j:\n" + steps, "write", "", Present, Absent},
		{"call", "on: push\njobs:\n  j:\n    cache-mode: write\n    uses: ./.github/workflows/c.yml\n", "", "write", Absent, Present},
	} {
		w, _, _ := parse(t, tt.src)
		j := w.Jobs.Value.Entries[0].Value.Value
		if w.CacheMode.Status != tt.wfSt || w.CacheMode.Value.AsString() != tt.wf {
			t.Errorf("%s: workflow %v %q, want %v %q", tt.name, w.CacheMode.Status, w.CacheMode.Value.AsString(), tt.wfSt, tt.wf)
		}
		if j.CacheMode.Status != tt.jobSt || j.CacheMode.Value.AsString() != tt.job {
			t.Errorf("%s: job %v %q, want %v %q", tt.name, j.CacheMode.Status, j.CacheMode.Value.AsString(), tt.jobSt, tt.job)
		}
	}
}
