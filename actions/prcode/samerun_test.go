package prcode

import "testing"

// TestUploadCovers reads the lines of the path of an upload by their
// syntax (PathLines).
func TestUploadCovers(t *testing.T) {
	for _, c := range []struct {
		name, path string
		dir        relDir
		want       bool
	}{
		{"runner.temp is out of the workspace", "'${{ runner.temp }}/x'", relDirOf("pr"), false},
		{"runner.temp back by ..", "'${{ runner.temp }}/..'", relDirOf("pr"), true},
		{"runner.temp back to the workspace", "'${{ runner.temp }}/../r/r/pr'", relDirOf("pr"), true},
		{"github.workspace compact", "'${{github.workspace}}/x'", relDirOf("pr"), false},
		{"github.workspace compact over pr", "'${{github.workspace}}/pr/out'", relDirOf("pr"), true},
		{"an expression", "'${{ inputs.p }}'", relDirOf("pr"), true},
		{"skipped lines", "\"!pr\\n\\nout\"", relDirOf("pr"), false},
		{"home", "'~/x'", relDirOf("pr"), false},
		{"a dir not known", "out", anyDir(), true},
	} {
		w := mustWorkflow(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/upload-artifact@v4\n        with: {path: "+c.path+"}\n")
		s := w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items[0]
		if got := uploadCovers(s, c.dir); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestSameRunRefusedCheckout: a checkout that fails on its path makes no
// upload of the current run.
func TestSameRunRefusedCheckout(t *testing.T) {
	src := "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with: {ref: '${{ github.event.pull_request.head.sha }}', path: '${{ runner.temp }}/pr'}\n      - uses: actions/upload-artifact@v4\n        with: {path: out}\n"
	if ups := sameRunUploads(nil, Analyze(mustWorkflow(t, src), nil)); len(ups) != 0 {
		t.Errorf("%+v", ups)
	}
	placed := "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with: {ref: '${{ github.event.pull_request.head.sha }}', path: pr}\n      - uses: actions/upload-artifact@v4\n        with: {path: pr}\n"
	if ups := sameRunUploads(nil, Analyze(mustWorkflow(t, placed), nil)); len(ups) != 1 {
		t.Errorf("placed: %+v", ups)
	}
}
