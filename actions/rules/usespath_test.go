package rules

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// usesPathFindings are the quality findings of uses-path on a workflow
// whose job runs steps, as "kind uses".
func usesPathFindings(t *testing.T, steps ...string) []string {
	t.Helper()
	src := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
	for _, s := range steps {
		src += "      - uses: '" + s + "'\n"
	}
	rep := qualityReportFS(t, UsesPathID, fstest.MapFS{".github/workflows/w.yml": {Data: []byte(src)}}, storeOf(t))
	var out []string
	for _, f := range rep.QualityFindings {
		s := f.Args.KindID().String()
		switch a := f.Args.(type) {
		case UsesPathUnnormalizedPath:
			s += " " + a.Uses + " " + a.Normalized
		case UsesPathOutsideRepository:
			s += " " + a.Uses
		case UsesPathOutsideWorkspace:
			s += " " + a.Uses
		}
		out = append(out, s)
	}
	return out
}

// TestUsesPath: the forms of a uses that GitHub does not read as written,
// seen on GitHub-hosted runners.
func TestUsesPath(t *testing.T) {
	sha := strings.Repeat("0123456789", 4)
	r := "o/r"
	for _, tc := range []struct {
		steps []string
		want  []string
	}{
		{[]string{r + "/acts/./a@" + sha}, []string{"uses-path.unnormalized-path " + r + "/acts/./a@" + sha + " " + r + "/acts/a@" + sha}},
		{[]string{r + "/acts//a@" + sha}, []string{"uses-path.unnormalized-path " + r + "/acts//a@" + sha + " " + r + "/acts/a@" + sha}},
		{[]string{r + "/acts/b/../a@" + sha}, []string{"uses-path.unnormalized-path " + r + "/acts/b/../a@" + sha + " " + r + "/acts/a@" + sha}},
		{[]string{"/" + r + "/acts/a@" + sha}, []string{"uses-path.unnormalized-path /" + r + "/acts/a@" + sha + " " + r + "/acts/a@" + sha}},
		{[]string{r + "/acts/b@probe/obfuscation", r + "/../probe/obfuscation/acts/b@" + sha}, []string{"uses-path.outside-repository " + r + "/../probe/obfuscation/acts/b@" + sha}},
		{[]string{"./../r/acts/a"}, []string{"uses-path.outside-workspace ./../r/acts/a"}},
		{[]string{r + "/acts/comp@" + sha, r + "/../../../actions/github-script/v7@" + sha}, []string{"uses-path.outside-repository " + r + "/../../../actions/github-script/v7@" + sha}},
		{[]string{"actions/checkout@v4", "./acts/a", "$/acts/a", "docker://alpine:3"}, nil},
	} {
		if got := usesPathFindings(t, tc.steps...); !slices.Equal(got, tc.want) {
			t.Errorf("%q: findings %q, want %q", tc.steps, got, tc.want)
		}
	}
}

// TestUsesPathJob: a job's uses is not reported; GitHub refuses the forms,
// and the model reports them as InvalidValue.
func TestUsesPathJob(t *testing.T) {
	src := "on: push\njobs:\n  j:\n    uses: o/r/.github/workflows/./c.yml@v1\n"
	rep := qualityReportFS(t, UsesPathID, fstest.MapFS{".github/workflows/w.yml": {Data: []byte(src)}}, storeOf(t))
	if len(rep.QualityFindings) != 0 {
		t.Errorf("findings %v", rep.QualityFindings)
	}
}
