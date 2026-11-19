package artifact

import (
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

func job(steps string) string {
	return "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" + steps
}

const (
	co     = "      - uses: actions/checkout@v4\n"
	upDot  = "      - uses: actions/upload-artifact@v4\n        with: {path: ., include-hidden-files: true}\n"
	upLast = upDot
	later  = "      - run: echo later\n"
)

// TestAnalyze: whether an upload after a checkout exposes the credential,
// by the version of upload-artifact, its path and include-hidden-files,
// and the gaps where a ${{ }} decides them.
func TestAnalyze(t *testing.T) {
	for _, c := range []struct {
		name, src    string
		exposes      int
		during       bool
		writes       analysis.TokenWrite
		unless, gaps int
	}{
		{"pair", job(co + upDot + later), 1, true, analysis.TokenWriteUnwritten, 0, 0},
		{"upload last", job(co + upLast), 1, true, analysis.TokenWriteUnwritten, 0, 0},
		{"upload before", job(upDot + co + later), 0, true, analysis.TokenWriteUnwritten, 0, 0},
		{"default hidden", job(co + "      - uses: actions/upload-artifact@v4\n        with: {path: .}\n" + later), 0, true, analysis.TokenWriteUnwritten, 0, 0},
		{"v4.3.6", job(co + "      - uses: actions/upload-artifact@v4.3.6\n        with: {path: .}\n" + later), 1, true, analysis.TokenWriteUnwritten, 0, 0},
		{"v3", job(co + "      - uses: actions/upload-artifact@v3.1.3\n        with: {path: .}\n" + later), 1, false, analysis.TokenWriteUnwritten, 0, 0},
		{"upload pinned unknown", job(co + "      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567\n        with: {path: .}\n" + later), 1, true, analysis.TokenWriteUnwritten, 2, 0},
		{"upload pinned with input", job(co + "      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567\n        with: {path: ., include-hidden-files: true}\n" + later), 1, true, analysis.TokenWriteUnwritten, 0, 0},
		{"checkout pinned unknown", job("      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n" + upDot + later), 1, true, analysis.TokenWriteUnwritten, 1, 0},
		{"two checkouts", job("      - uses: actions/checkout@v4\n        with: {path: a}\n      - uses: actions/checkout@v4\n        with: {path: b}\n      - uses: actions/upload-artifact@v4\n        with: {path: a, include-hidden-files: true}\n" + later), 1, true, analysis.TokenWriteUnwritten, 0, 0},
		{"comments in path", job(co + "      - uses: actions/upload-artifact@v4\n        with:\n          include-hidden-files: true\n          path: |\n            # all\n\n            ./\n" + later), 1, true, analysis.TokenWriteUnwritten, 0, 0},
		{"path expr", job(co + "      - uses: actions/upload-artifact@v4\n        with: {path: '${{ inputs.p }}', include-hidden-files: true}\n" + later), 0, true, analysis.TokenWriteUnwritten, 0, 1},
		{"workspace expr", job(co + "      - uses: actions/upload-artifact@v4\n        with: {path: '${{ github.workspace }}', include-hidden-files: true}\n" + later), 1, true, analysis.TokenWriteUnwritten, 0, 0},
		{"workspace by an index", job(co + "      - uses: actions/upload-artifact@v4\n        with: {path: '${{ github[''workspace''] }}', include-hidden-files: true}\n" + later), 1, true, analysis.TokenWriteUnwritten, 0, 0},
		{"workspace with spaces", job(co + "      - uses: actions/upload-artifact@v4\n        with: {path: '${{ GITHUB . workspace }}/', include-hidden-files: true}\n" + later), 1, true, analysis.TokenWriteUnwritten, 0, 0},
		{"hidden expr", job(co + "      - uses: actions/upload-artifact@v4\n        with: {path: ., include-hidden-files: '${{ inputs.h }}'}\n" + later), 0, true, analysis.TokenWriteUnwritten, 0, 1},
		{"windows path", job(co + "      - uses: actions/upload-artifact@v4\n        with: {path: '.\\', include-hidden-files: true}\n" + later), 0, true, analysis.TokenWriteUnwritten, 0, 1},
		{"refused line", job(co + "      - uses: actions/upload-artifact@v4\n        with:\n          include-hidden-files: true\n          path: |\n            .\n            ../x\n" + later), 0, true, analysis.TokenWriteUnwritten, 0, 0}, // the upload fails
		{"expr under a directory", job(co + "      - uses: actions/upload-artifact@v4\n        with: {path: 'dist/${{ matrix.os }}'}\n" + later), 0, true, analysis.TokenWriteUnwritten, 0, 0},                                                 // corpus: dist/* cannot take .git/config
		{"expr as the whole line", job(co + "      - uses: actions/upload-artifact@v4\n        with: {path: '${{ inputs.p }}'}\n" + later), 0, true, analysis.TokenWriteUnwritten, 0, 1},
		{"path expr, nothing left", job("      - run: make\n      - uses: actions/upload-artifact@v4\n        with: {path: '${{ inputs.p }}'}\n" + later), 0, true, analysis.TokenWriteUnwritten, 0, 0}, // corpus: no credential, nothing to analyze
		{"absolute path, nothing left", job("      - uses: actions/upload-artifact@v4\n        with: {path: /tmp/logs}\n" + later), 0, true, analysis.TokenWriteUnwritten, 0, 0},
		{"with expr", job(co + "      - uses: actions/upload-artifact@v4\n        with: '${{ fromJSON(inputs.w) }}'\n" + later), 0, true, analysis.TokenWriteUnwritten, 0, 1},
		{"credential gap", job("      - uses: actions/checkout@v4\n        with: {persist-credentials: '${{ inputs.p }}'}\n" + upDot + later), 0, true, analysis.TokenWriteUnwritten, 0, 1},
		{"auth", job("      - uses: google-github-actions/auth@v2\n        with: {credentials_json: x}\n      - uses: actions/upload-artifact@v4\n        with: {path: .}\n"), 1, true, analysis.TokenWriteUnwritten, 0, 0},
		{"merge sub-action", job(co + "      - uses: actions/upload-artifact/merge@v4\n        with: {pattern: '*'}\n" + later), -1, false, 0, 0, 0},
	} {
		us, creds := Analyze(parse(t, c.src), nil)
		if c.exposes < 0 {
			if len(us) != 0 {
				t.Errorf("%s: %+v", c.name, us)
			}
			continue
		}
		if len(us) != 1 {
			t.Errorf("%s: %d uploads", c.name, len(us))
			continue
		}
		u := us[0]
		unless := 0
		for _, e := range u.TakenCredentials {
			unless += len(creds[e.Index].MissingCommits)
			if e.Hidden {
				unless += len(u.HiddenMissingCommits)
			}
		}
		if len(u.TakenCredentials) != c.exposes || u.DownloadableDuringRun != c.during || u.TokenWrite != c.writes || unless != c.unless || len(u.Inconclusive) != c.gaps {
			t.Errorf("%s: exposes %d during %v writes %v unless %d gaps %d", c.name, len(u.TakenCredentials), u.DownloadableDuringRun, u.TokenWrite, unless, len(u.Inconclusive))
		}
	}
}

// TestGapFiles: each gap names the files of credentials its value decides,
// so that a rule gives only the gaps of its own credential; a gap that
// decides none is not given.
func TestGapFiles(t *testing.T) {
	git, other := analysis.CredentialFileGitConfig, analysis.CredentialFileOther
	auth := "      - uses: google-github-actions/auth@v2\n        with: {credentials_json: x}\n"
	upPath := func(p string) string {
		return "      - uses: actions/upload-artifact@v4\n        with: {path: '" + p + "', include-hidden-files: true}\n"
	}
	for _, c := range []struct {
		name, src string
		want      [][]analysis.CredentialFile
	}{
		{"checkout input", job("      - uses: actions/checkout@v4\n        with: {persist-credentials: '${{ vars.P }}'}\n" + upDot), [][]analysis.CredentialFile{{git}}},
		{"checkout v6 input", job("      - uses: actions/checkout@v6\n        with: {persist-credentials: '${{ vars.P }}'}\n" + upDot), nil},
		{"v6 runner.temp expr", job("      - uses: actions/checkout@v6\n" + "      - uses: actions/upload-artifact@v4\n        with: {path: '${{ runner.temp }}/${{ inputs.dir }}'}\n"), [][]analysis.CredentialFile{{analysis.CredentialFileGitCredentialsTemp}}},
		{"checkout v6 input runner.temp", job("      - uses: actions/checkout@v6\n        with: {persist-credentials: '${{ vars.P }}'}\n" + "      - uses: actions/upload-artifact@v4\n        with: {path: '${{ runner.temp }}'}\n"), [][]analysis.CredentialFile{{analysis.CredentialFileGitCredentialsTemp}}},
		{"auth input", job("      - uses: google-github-actions/auth@v2\n        with: {credentials_json: x, create_credentials_file: '${{ vars.C }}'}\n" + upDot), [][]analysis.CredentialFile{{other}}},
		{"auth input, no credential", job("      - uses: google-github-actions/auth@v2\n        with: {create_credentials_file: '${{ vars.C }}'}\n" + upDot), nil},
		{"auth whole with", job("      - uses: google-github-actions/auth@v2\n        with: '${{ fromJSON(vars.A) }}'\n" + upDot), [][]analysis.CredentialFile{{other}}},
		{"path expr, checkout", job(co + upPath("${{ inputs.p }}")), [][]analysis.CredentialFile{{git}}},
		{"path expr, both", job(co + auth + upPath("${{ inputs.p }}")), [][]analysis.CredentialFile{{git, other}}},
		{"path expr under .git", job(co + auth + upPath(".git/${{ inputs.p }}")), [][]analysis.CredentialFile{{git}}},
		{"hidden expr, checkout", job(co + "      - uses: actions/upload-artifact@v4\n        with: {path: ., include-hidden-files: '${{ inputs.h }}'}\n"), [][]analysis.CredentialFile{{git}}},
		{"hidden expr, path not of it", job(co + "      - uses: actions/upload-artifact@v4\n        with: {path: dist, include-hidden-files: '${{ inputs.h }}'}\n"), nil},
		{"hidden expr, auth", job(auth + "      - uses: actions/upload-artifact@v4\n        with: {path: ., include-hidden-files: '${{ inputs.h }}'}\n"), nil},
		{"with expr, both", job(co + auth + "      - uses: actions/upload-artifact@v4\n        with: '${{ fromJSON(inputs.w) }}'\n"), [][]analysis.CredentialFile{{git, other}}},
		{"absolute path, checkout", job(co + upPath("/tmp/x")), [][]analysis.CredentialFile{{git}}},
	} {
		us, _ := Analyze(parse(t, c.src), nil)
		if len(us) != 1 {
			t.Errorf("%s: %d uploads", c.name, len(us))
			continue
		}
		var got [][]analysis.CredentialFile
		for _, g := range us[0].Inconclusive {
			got = append(got, g.Files)
		}
		if !slices.EqualFunc(got, c.want, slices.Equal) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestWrites is the token's power by the permissions written: the job's,
// else the workflow's; id-token is not a scope the token writes with.
func TestWrites(t *testing.T) {
	for _, c := range []struct {
		wf, job string
		want    analysis.TokenWrite
	}{
		{"", "", analysis.TokenWriteUnwritten},
		{"permissions: {}\n", "", analysis.TokenWriteNo},
		{"permissions: read-all\n", "", analysis.TokenWriteNo},
		{"permissions: write-all\n", "", analysis.TokenWriteYes},
		{"permissions: {contents: write}\n", "", analysis.TokenWriteYes},
		{"permissions: {contents: read, id-token: write}\n", "", analysis.TokenWriteNo},
		{"permissions: {contents: write}\n", "    permissions: {contents: read}\n", analysis.TokenWriteNo},
		{"", "    permissions: {pull-requests: write}\n", analysis.TokenWriteYes},
	} {
		src := "on: push\n" + c.wf + "jobs:\n  a:\n    runs-on: ubuntu-latest\n" + c.job + "    steps:\n" + co + upDot + later
		us, _ := Analyze(parse(t, src), nil)
		if len(us) != 1 || us[0].TokenWrite != c.want {
			t.Errorf("%q %q: %+v, want %v", c.wf, c.job, us, c.want)
		}
	}
}

// TestAnalyzeNoSteps: a job that calls a reusable
// workflow, and one without steps, give nothing.
func TestAnalyzeNoSteps(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    uses: o/r/.github/workflows/x.yml@v1\n  b:\n    runs-on: ubuntu-latest\n"
	if us, creds := Analyze(parse(t, src), nil); len(us) != 0 || len(creds) != 0 {
		t.Errorf("%+v", us)
	}
}

// TestAnalyzeAction: in a composite action.yml the caller's token may
// write.
func TestAnalyzeAction(t *testing.T) {
	src := "name: x\ndescription: x\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n    - uses: actions/upload-artifact@v4\n      with: {path: ., include-hidden-files: true}\n"
	a, _ := workflow.ParseActionMetadata(cst.ParseMode([]byte(src), cst.ModeGitHub))
	if a == nil {
		t.Fatal("not an action")
	}
	us, _ := Analyze(nil, a)
	if len(us) != 1 || len(us[0].TakenCredentials) != 1 || us[0].TokenWrite != analysis.TokenWriteYes {
		t.Errorf("%+v", us)
	}
}

// TestRunnerTempCredential: actions/checkout v6 and later keeps the git
// credential in a file of RUNNER_TEMP, which an upload of
// ${{ runner.temp }} takes.
func TestRunnerTempCredential(t *testing.T) {
	const v6 = "      - uses: actions/checkout@v6\n"
	up := func(p string) string {
		return "      - uses: actions/upload-artifact@v4\n        with:\n          path: " + p + "\n"
	}
	for _, c := range []struct {
		name, src string
		want      []analysis.CredentialFile
	}{
		{"v6 runner.temp", job(v6 + up("${{ runner.temp }}") + later), []analysis.CredentialFile{analysis.CredentialFileGitCredentialsTemp}},
		{"v6 runner.temp glob", job(v6 + up("${{ runner.temp }}/**") + later), []analysis.CredentialFile{analysis.CredentialFileGitCredentialsTemp}},
		{"v6 runner.temp subdirectory", job(v6 + up("${{ runner.temp }}/out") + later), nil},
		{"v6 workspace", job(v6 + up(".") + later), nil},
		{"persist false", job("      - uses: actions/checkout@v6\n        with: {persist-credentials: false}\n" + up("${{ runner.temp }}") + later), nil},
		{"main runner.temp", job("      - uses: actions/checkout@main\n" + up("${{ runner.temp }}") + later), []analysis.CredentialFile{analysis.CredentialFileGitCredentialsTemp}},
		{"unknown SHA runner.temp", job("      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n" + up("${{ runner.temp }}") + later), []analysis.CredentialFile{analysis.CredentialFileGitCredentialsTemp}},
		{"v6 runner.temp by an index", job(v6 + up("\"${{ runner['temp'] }}\"") + later), []analysis.CredentialFile{analysis.CredentialFileGitCredentialsTemp}},
		{"v6 runner.temp left out", job(v6 + up("|\n            ${{ runner.temp }}\n            !${{ runner . temp }}/git-credentials-*") + later), nil},
		{"v5 runner.temp", job("      - uses: actions/checkout@v5\n" + up("${{ runner.temp }}") + later), nil},
	} {
		ups, creds := Analyze(parse(t, c.src), nil)
		if len(ups) != 1 {
			t.Fatalf("%s: %d uploads", c.name, len(ups))
		}
		var got []analysis.CredentialFile
		for _, l := range ups[0].TakenCredentials {
			got = append(got, creds[l.Index].File)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestGapTextShowsPath: the note of a gap shows the line of path as
// written, not the mark that stands for RUNNER_TEMP.
func TestGapTextShowsPath(t *testing.T) {
	src := job("      - uses: actions/checkout@v4\n      - uses: actions/upload-artifact@v4\n        with:\n          path: '${{ runner.temp }}\\\\logs'\n" + later)
	ups, _ := Analyze(parse(t, src), nil)
	if len(ups) != 1 || len(ups[0].Inconclusive) == 0 {
		t.Fatalf("%+v", ups)
	}
	for _, g := range ups[0].Inconclusive {
		if strings.Contains(g.Text, runnerTempRoot) || !strings.Contains(g.Text, "${{ runner.temp }}") {
			t.Errorf("text %q", g.Text)
		}
	}
}

// TestAnalyzeSharesCredentials: the credential a step leaves is made once,
// and each upload that takes it names it by its index, with whether the
// upload takes the file only as a hidden file (path . takes .git/config so,
// path .git/config names it); the missing commits of the upload's release
// apply to such a take only; only credentials an upload takes are given.
func TestAnalyzeSharesCredentials(t *testing.T) {
	src := job(co + upDot + upDot + "      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567\n        with: {path: .}\n" + "      - uses: actions/upload-artifact@v4\n        with: {path: .git/config}\n" + later)
	us, creds := Analyze(parse(t, src), nil)
	if len(creds) != 1 || creds[0].File != analysis.CredentialFileGitConfig || creds[0].Step == nil || !creds[0].Checkout {
		t.Fatalf("credentials %+v", creds)
	}
	want := [][]TakenCredential{{{Index: 0, Hidden: true}}, {{Index: 0, Hidden: true}}, {{Index: 0, Hidden: true}}, {{Index: 0, Hidden: false}}}
	if len(us) != len(want) {
		t.Fatalf("%d uploads", len(us))
	}
	for i, u := range us {
		if !slices.Equal(u.TakenCredentials, want[i]) {
			t.Errorf("upload %d: %+v, want %+v", i, u.TakenCredentials, want[i])
		}
	}
	if len(us[2].HiddenMissingCommits) != 2 || len(us[0].HiddenMissingCommits) != 0 {
		t.Errorf("hidden missing commits %v, %v", us[2].HiddenMissingCommits, us[0].HiddenMissingCommits)
	}
	if creds := func() []LeftCredential { _, c := Analyze(parse(t, job(co+later)), nil); return c }(); len(creds) != 0 {
		t.Errorf("a credential no upload takes: %+v", creds)
	}
}

// TestCredentialGapOnce: whether a step leaves its credential is a ${{ }}
// (persist-credentials of actions/checkout v6): the gap is given once, at
// the first upload that takes the file, not at each upload after the step.
func TestCredentialGapOnce(t *testing.T) {
	pair := "      - uses: actions/checkout@v6\n        with: {persist-credentials: '${{ inputs.p }}'}\n      - uses: actions/upload-artifact@v4\n        with: {path: '${{ runner.temp }}'}\n"
	us, _ := Analyze(parse(t, job(pair+pair+pair)), nil)
	var got []int
	for _, u := range us {
		got = append(got, len(u.Inconclusive))
	}
	if want := []int{1, 1, 1}; !slices.Equal(got, want) {
		t.Errorf("gaps by upload %v, want %v", got, want)
	}
}

// TestAnalyzeFileKeys: the files of two checkouts whose paths differ only
// by a NUL and a slash ("a\0b" and "a/b") are two files: an upload of a/b
// takes the credential of the second checkout only.
func TestAnalyzeFileKeys(t *testing.T) {
	src := job("      - uses: actions/checkout@v4\n        with: {path: \"a\\0b\"}\n      - uses: actions/checkout@v4\n        with: {path: a/b}\n      - uses: actions/upload-artifact@v4\n        with: {path: a/b, include-hidden-files: true}\n" + later)
	us, creds := Analyze(parse(t, src), nil)
	if len(us) != 1 || len(us[0].TakenCredentials) != 1 {
		t.Fatalf("%+v", us)
	}
	if s := creds[us[0].TakenCredentials[0].Index].Step; s == nil || s.Order != 1 {
		t.Errorf("the credential of %+v, want the second checkout", s)
	}
}

// TestAnalyzeIndices: the indices of the credentials taken are those of
// what Analyze gives, across jobs, with a credential no upload takes left
// out between them.
func TestAnalyzeIndices(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/upload-artifact@v4\n        with: {path: dist}\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: google-github-actions/auth@v2\n        with: {credentials_json: x}\n      - uses: actions/checkout@v4\n" + upDot
	us, creds := Analyze(parse(t, src), nil)
	if len(us) != 2 || len(us[0].TakenCredentials) != 0 || len(us[1].TakenCredentials) != 2 || len(creds) != 2 {
		t.Fatalf("uploads %+v, credentials %+v", us, creds)
	}
	for i, want := range []string{"google-github-actions/auth@v2", "actions/checkout@v4"} {
		if c := creds[us[1].TakenCredentials[i].Index]; c.UsesText != want {
			t.Errorf("taken %d: %s, want %s", i, c.UsesText, want)
		}
	}
}

// TestGapCredentials: a gap of an upload has the steps before the upload
// that leave a credential whose taking its value decides, with the file
// of each, and not among the left credentials, which no upload takes; a
// step whose leaving a ${{ }} decides is left out.
func TestGapCredentials(t *testing.T) {
	auth := "      - uses: google-github-actions/auth@v2\n        with: {credentials_json: x}\n"
	maybe := "      - uses: actions/checkout@v4\n        with: {persist-credentials: '${{ vars.P }}'}\n"
	src := job(auth + co + maybe + "      - uses: actions/upload-artifact@v4\n        with: {path: '${{ inputs.p }}'}\n")
	us, creds := Analyze(parse(t, src), nil)
	if len(us) != 1 || len(creds) != 0 {
		t.Fatalf("uploads %+v, credentials %+v: want one upload and no credential that an upload takes", us, creds)
	}
	var got []string
	for _, g := range us[0].Inconclusive {
		if g.Kind != analysis.InconclusiveUploadInput {
			continue
		}
		for _, c := range g.Credentials {
			got = append(got, c.Step.Uses.Value.AsString()+" "+c.File.String())
		}
	}
	want := []string{"google-github-actions/auth@v2 CredentialFileOther", "actions/checkout@v4 CredentialFileGitConfig"}
	if !slices.Equal(got, want) {
		t.Errorf("credentials of the gap of the upload %v, want %v", got, want)
	}
}
