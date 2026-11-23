package job

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
)

// TestActionsReadOf: the scope actions, read-all and write-all read the
// artifacts of another run; any other permissions written set actions to
// none; none written leaves it to the repository's default.
func TestActionsReadOf(t *testing.T) {
	for _, c := range []struct {
		job, wf string
		want    analysis.ActionsRead
	}{
		{"", "", analysis.ActionsReadUnwritten},
		{"{actions: read}", "", analysis.ActionsReadYes},
		{"{actions: write}", "", analysis.ActionsReadYes},
		{"{actions: none}", "", analysis.ActionsReadNo},
		{"{contents: read}", "", analysis.ActionsReadNo},
		{"{}", "", analysis.ActionsReadNo},
		{"read-all", "", analysis.ActionsReadYes},
		{"write-all", "", analysis.ActionsReadYes},
		{"", "{actions: read}", analysis.ActionsReadYes},
		{"{contents: read}", "{actions: read}", analysis.ActionsReadNo}, // the job's replace the workflow's
		{"'${{ inputs.p }}'", "", analysis.ActionsReadYes},              // not known: the worst case
		{"{actions: '${{ inputs.a }}'}", "", analysis.ActionsReadYes},
		{"${{ 'read-all' }}", "", analysis.ActionsReadYes},             // folded: GitHub reads the string
		{"\n      actions: ${{ 'none' }}", "", analysis.ActionsReadNo}, // a block mapping: in a flow one, {{ opens a mapping
		{"\n      actions: ${{ 'read' }}", "", analysis.ActionsReadYes},
	} {
		src := "on: push\n"
		if c.wf != "" {
			src += "permissions: " + c.wf + "\n"
		}
		src += "jobs:\n  a:\n    runs-on: ubuntu-latest\n"
		if c.job != "" {
			src += "    permissions: " + c.job + "\n"
		}
		src += "    steps:\n      - run: echo\n"
		w := parse(t, src)
		j := w.Jobs.Value.Entries[0].Value.Value
		if got := ActionsReadOf(j.Permissions, w.Permissions); got != c.want {
			t.Errorf("job %q wf %q: got %v, want %v", c.job, c.wf, got, c.want)
		}
	}
}

// TestWriteAllOf: write-all of the job's
// permissions, else the workflow's, and nothing else.
func TestWriteAllOf(t *testing.T) {
	for _, c := range []struct {
		wf, job string
		want    analysis.WriteAll
	}{
		{"permissions: write-all\n", "", analysis.WriteAllWorkflow},
		{"", "    permissions: write-all\n", analysis.WriteAllJob},
		{"", "    permissions: Write-All\n", analysis.WriteAllNo}, // GitHub runs no job of it
		{"permissions: write-all\n", "    permissions: {contents: read}\n", analysis.WriteAllNo},
		{"permissions: {contents: read}\n", "    permissions: write-all\n", analysis.WriteAllJob},
		{"permissions: read-all\n", "", analysis.WriteAllNo},
		{"permissions: {}\n", "", analysis.WriteAllNo},
		{"permissions: {contents: write}\n", "", analysis.WriteAllNo},
		{"", "", analysis.WriteAllNo},
		{"permissions: ${{ 'write-all' }}\n", "", analysis.WriteAllWorkflow}, // GitHub folds it
		{"", "    permissions: ${{ 'write-all' }}\n", analysis.WriteAllJob},
	} {
		j := one(t, "on: push\n"+c.wf+"jobs:\n  a:\n    runs-on: x\n"+c.job+"    steps:\n      - run: echo\n")
		if j.WriteAll != c.want {
			t.Errorf("%q %q: %v, want %v", c.wf, c.job, j.WriteAll, c.want)
		}
	}
}

// TestTokenWriteOf: a scope other than id-token written write, write-all,
// or a ${{ }} GitHub evaluates may write; a folded literal is its string.
func TestTokenWriteOf(t *testing.T) {
	for _, c := range []struct {
		name, job string
		want      analysis.TokenWrite
	}{
		{"unwritten", "", analysis.TokenWriteUnwritten},
		{"read-all", "read-all", analysis.TokenWriteNo},
		{"write-all", "write-all", analysis.TokenWriteYes},
		{"scope write", "{contents: write}", analysis.TokenWriteYes},
		{"id-token only", "{id-token: write}", analysis.TokenWriteNo},
		{"expression", "'${{ inputs.p }}'", analysis.TokenWriteYes},
		{"scope expression", "{contents: '${{ inputs.a }}'}", analysis.TokenWriteYes},
		{"folded read-all", "${{ 'read-all' }}", analysis.TokenWriteNo},
		{"folded write-all", "${{ 'write-all' }}", analysis.TokenWriteYes},
		{"folded read", "\n      contents: ${{ 'read' }}", analysis.TokenWriteNo}, // a block mapping: in a flow one, {{ opens a mapping
		{"folded write", "\n      contents: ${{ 'write' }}", analysis.TokenWriteYes},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
		if c.job != "" {
			src += "    permissions: " + c.job + "\n"
		}
		src += "    steps:\n      - run: echo\n"
		w := parse(t, src)
		j := w.Jobs.Value.Entries[0].Value.Value
		if got := TokenWriteOf(j.Permissions, w.Permissions); got != c.want {
			t.Errorf("%s (%q): got %v, want %v", c.name, c.job, got, c.want)
		}
	}
}

// TestCacheWriteOf: the job's cache-mode, else the workflow's; a literal
// ${{ }} is its string.
func TestCacheWriteOf(t *testing.T) {
	for _, c := range []struct {
		wf, job string
		want    analysis.CacheWrite
	}{
		{"", "", analysis.CacheWriteUnwritten},
		{"write", "", analysis.CacheWriteYes},
		{"write-only", "", analysis.CacheWriteYes},
		{"read", "", analysis.CacheWriteNo},
		{"none", "", analysis.CacheWriteNo},
		{"read", "write", analysis.CacheWriteYes}, // the job's wins
		{"write", "none", analysis.CacheWriteNo},
		{"${{ 'write' }}", "", analysis.CacheWriteYes},
		{"", "${{ 'read' }}", analysis.CacheWriteNo},
		{"", "WRITE", analysis.CacheWriteUnwritten},              // GitHub refuses the workflow
		{"write", "bogus", analysis.CacheWriteUnwritten},         // the job's is written, and refused
		{"", "${{ github.event_name }}", analysis.CacheWriteYes}, // refused too, read as the worst case
	} {
		src := "on: push\n"
		if c.wf != "" {
			src += "cache-mode: " + c.wf + "\n"
		}
		src += "jobs:\n  a:\n    runs-on: ubuntu-latest\n"
		if c.job != "" {
			src += "    cache-mode: " + c.job + "\n"
		}
		src += "    steps:\n      - run: echo\n"
		w := parse(t, src)
		j := w.Jobs.Value.Entries[0].Value.Value
		if got := CacheWriteOf(j.CacheMode, w.CacheMode); got != c.want {
			t.Errorf("wf %q job %q: got %v, want %v", c.wf, c.job, got, c.want)
		}
	}
}

// TestPullRequestsWriteOf: pull-requests write and write-all write it; any
// other permissions written set it to none or read; none written leaves it
// to the repository's default.
func TestPullRequestsWriteOf(t *testing.T) {
	for _, c := range []struct {
		job, wf string
		want    analysis.PullRequestsWrite
	}{
		{"", "", analysis.PullRequestsWriteUnwritten},
		{"write-all", "", analysis.PullRequestsWriteYes},
		{"read-all", "", analysis.PullRequestsWriteNo},
		{"{pull-requests: write}", "", analysis.PullRequestsWriteYes},
		{"{pull-requests: read}", "", analysis.PullRequestsWriteNo},
		{"{contents: write}", "", analysis.PullRequestsWriteNo},
		{"{}", "", analysis.PullRequestsWriteNo},
		{"", "{pull-requests: write}", analysis.PullRequestsWriteYes},
		{"{contents: read}", "{pull-requests: write}", analysis.PullRequestsWriteNo}, // the job's replace the workflow's
		{"'${{ inputs.p }}'", "", analysis.PullRequestsWriteYes},                     // not known: read as writing
		{"{pull-requests: '${{ inputs.a }}'}", "", analysis.PullRequestsWriteYes},
	} {
		src := "on: push\n"
		if c.wf != "" {
			src += "permissions: " + c.wf + "\n"
		}
		src += "jobs:\n  a:\n    runs-on: ubuntu-latest\n"
		if c.job != "" {
			src += "    permissions: " + c.job + "\n"
		}
		src += "    steps:\n      - run: echo\n"
		w := parse(t, src)
		j := w.Jobs.Value.Entries[0].Value.Value
		if got := PullRequestsWriteOf(j.Permissions, w.Permissions); got != c.want {
			t.Errorf("job %q wf %q: got %v, want %v", c.job, c.wf, got, c.want)
		}
	}
}
