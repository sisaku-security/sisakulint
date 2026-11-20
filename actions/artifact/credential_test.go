package artifact

import (
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/prcode"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// stepOf is the first step of a workflow whose only job has the step
// written as src (a mapping in flow style or block lines after "- ").
func stepOf(t *testing.T, src string) workflow.Step {
	t.Helper()
	w := parse(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - "+src+"\n")
	return w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items[0]
}

// credentialsOfStep is credentialsOf of the step src, the only step of a
// job on a hosted runner.
func credentialsOfStep(t *testing.T, src string) ([]credential, []InconclusiveUpload) {
	t.Helper()
	w := parse(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - "+src+"\n")
	j := w.Jobs.Value.Entries[0].Value.Value
	steps := j.Steps.Value.Items
	place, placed := prcode.Placement{}, true
	if steps[0].Uses.Status == workflow.Present && calls.IsCheckout(steps[0].Uses.Value) {
		place, placed = prcode.CheckoutPlacement(&j, steps, workflow.OrderOf(steps), 0)
	}
	return credentialsOf(&steps[0], place, placed)
}

func parse(t *testing.T, src string) *workflow.Workflow {
	t.Helper()
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	if w == nil {
		t.Fatalf("not a workflow: %s", src)
	}
	return w
}

// TestCredentialsOf: the file, the lifetime and the gaps of the credential
// each step of a known action leaves, by its inputs.
func TestCredentialsOf(t *testing.T) {
	for _, c := range []struct {
		name, step string
		file       string // joined by /; "" for none
		life       analysis.CredentialLifetime
		asks, gap  bool
	}{
		{"checkout default", "{uses: actions/checkout@v4}", ".git/config", analysis.CredentialLifetimeGitHubToken, false, false},
		{"persist TRUE", "{uses: actions/checkout@v4, with: {persist-credentials: 'TRUE'}}", ".git/config", analysis.CredentialLifetimeGitHubToken, false, false},
		{"persist True", "{uses: actions/checkout@v4, with: {persist-credentials: True}}", ".git/config", analysis.CredentialLifetimeGitHubToken, false, false},
		{"persist false", "{uses: actions/checkout@v4, with: {persist-credentials: false}}", "", 0, false, false},
		{"persist yes", "{uses: actions/checkout@v4, with: {persist-credentials: yes}}", "", 0, false, false},
		{"persist expr", "{uses: actions/checkout@v4, with: {persist-credentials: '${{ inputs.p }}'}}", "", 0, false, true},
		{"with expr", "{uses: actions/checkout@v4, with: '${{ fromJSON(inputs.w) }}'}", "", 0, false, true},
		{"v6", "{uses: actions/checkout@v6}", runnerTempRoot + "/" + checkoutTempCreds, analysis.CredentialLifetimeGitHubToken, false, false},
		{"v6 persist false", "{uses: actions/checkout@v6, with: {persist-credentials: false}}", "", 0, false, false},
		{"pinned unknown", "{uses: actions/checkout@0123456789abcdef0123456789abcdef01234567}", ".git/config", analysis.CredentialLifetimeGitHubToken, true, false},
		{"path", "{uses: actions/checkout@v4, with: {path: ./src/}}", "src/.git/config", analysis.CredentialLifetimeGitHubToken, false, false},
		{"path expr", "{uses: actions/checkout@v4, with: {path: '${{ matrix.d }}'}}", "", 0, false, true},
		{"path absolute", "{uses: actions/checkout@v4, with: {path: /tmp/x}}", "", 0, false, true},
		{"token github", "{uses: actions/checkout@v4, with: {token: '${{ github.token }}'}}", ".git/config", analysis.CredentialLifetimeGitHubToken, false, false},
		{"token github by an index", "{uses: actions/checkout@v4, with: {token: '${{ github[''token''] }}'}}", ".git/config", analysis.CredentialLifetimeGitHubToken, false, false},
		{"token secret GITHUB_TOKEN with spaces", "{uses: actions/checkout@v4, with: {token: '${{ secrets . GITHUB_TOKEN }}'}}", ".git/config", analysis.CredentialLifetimeGitHubToken, false, false},
		{"token secret GITHUB_TOKEN", "{uses: actions/checkout@v4, with: {token: '${{ secrets.GITHUB_TOKEN }}'}}", ".git/config", analysis.CredentialLifetimeGitHubToken, false, false},
		{"token PAT", "{uses: actions/checkout@v4, with: {token: '${{ secrets.PAT }}'}}", ".git/config", analysis.CredentialLifetimeLasting, false, false},
		{"Actions/Checkout", "{uses: Actions/Checkout@v4}", ".git/config", analysis.CredentialLifetimeGitHubToken, false, false},
		{"checkout path in uses", "{uses: actions/checkout/sub@v4}", "", 0, false, false},
		{"pages deploy", "{uses: JamesIves/github-pages-deploy-action@v4, with: {folder: build}}", ".git/config", analysis.CredentialLifetimeGitHubToken, false, false},
		{"pages deploy PAT", "{uses: JamesIves/github-pages-deploy-action@v4, with: {folder: build, token: '${{ secrets.PAT }}'}}", ".git/config", analysis.CredentialLifetimeLasting, false, false},
		{"pages deploy ssh", "{uses: JamesIves/github-pages-deploy-action@v4, with: {folder: build, ssh-key: '${{ secrets.KEY }}'}}", "", 0, false, false},
		{"auth key", "{uses: google-github-actions/auth@v2, with: {credentials_json: '${{ secrets.GCP }}'}}", "gha-creds-0123456789abcdef.json", analysis.CredentialLifetimeLasting, false, false},
		{"auth wif", "{uses: google-github-actions/auth@v2, with: {workload_identity_provider: p, service_account: s}}", "gha-creds-0123456789abcdef.json", analysis.CredentialLifetimeJob, false, false},
		{"auth no file", "{uses: google-github-actions/auth@v2, with: {credentials_json: x, create_credentials_file: false}}", "", 0, false, false},
		{"auth file 1", "{uses: google-github-actions/auth@v2, with: {credentials_json: x, create_credentials_file: 1}}", "gha-creds-0123456789abcdef.json", analysis.CredentialLifetimeLasting, false, false},
		{"auth file t", "{uses: google-github-actions/auth@v2, with: {credentials_json: x, create_credentials_file: t}}", "gha-creds-0123456789abcdef.json", analysis.CredentialLifetimeLasting, false, false},
		{"auth file tRuE", "{uses: google-github-actions/auth@v2, with: {credentials_json: x, create_credentials_file: tRuE}}", "", 0, false, false}, // parseBoolean throws: the step fails
		{"auth file expr", "{uses: google-github-actions/auth@v2, with: {credentials_json: x, create_credentials_file: '${{ inputs.f }}'}}", "", 0, false, true},
		{"dotnet source", "{uses: actions/setup-dotnet@v4, with: {source-url: 'https://nuget.pkg.github.com/o/index.json'}}", "../nuget.config", analysis.CredentialLifetimeLasting, false, false},
		{"dotnet no source", "{uses: actions/setup-dotnet@v4, with: {dotnet-version: 8}}", "", 0, false, false},
		{"run", "{run: echo}", "", 0, false, false},
		// a checkout that fails on its path writes no credential
		{"path runner.temp", "{uses: actions/checkout@v4, with: {path: '${{ runner.temp }}/pr'}}", "", 0, false, false},
		{"v6 path runner.temp", "{uses: actions/checkout@v6, with: {path: '${{ runner.temp }}/pr'}}", "", 0, false, false},
		// v1 moves github.workspace to where it puts the tree
		{"v1 path", "{uses: actions/checkout@v1, with: {path: foo}}", ".git/config", analysis.CredentialLifetimeGitHubToken, false, false},
		// a with or a path that does not fit the schema is read as no path
		{"path not a scalar", "{uses: actions/checkout@v4, with: {path: [a]}}", ".git/config", analysis.CredentialLifetimeGitHubToken, false, false},
	} {
		cs, gaps := credentialsOfStep(t, c.step)
		if c.gap != (len(gaps) > 0) {
			t.Errorf("%s: gaps %+v", c.name, gaps)
		}
		if c.file == "" {
			if len(cs) != 0 {
				t.Errorf("%s: %+v", c.name, cs)
			}
			continue
		}
		if c.name == "pinned unknown" {
			// a commit in no table may be v6 on: the file of RUNNER_TEMP too
			if len(cs) != 2 || fileOf(cs[0].file) != analysis.CredentialFileGitCredentialsTemp {
				t.Errorf("%s: %+v", c.name, cs)
				continue
			}
			cs = cs[1:]
		}
		if len(cs) != 1 {
			t.Errorf("%s: %d credentials", c.name, len(cs))
			continue
		}
		got := cs[0]
		if strings.Join(got.file, "/") != c.file || got.life != c.life || (len(got.unless) > 0) != c.asks {
			t.Errorf("%s: %v %v %+v; want %s %v asks %v", c.name, got.file, got.life, got.unless, c.file, c.life, c.asks)
		}
		if got.checkout != slices.Contains([]string{"checkout default", "persist TRUE", "persist True", "pinned unknown", "path", "token github", "token github by an index", "token secret GITHUB_TOKEN", "token secret GITHUB_TOKEN with spaces", "token PAT", "Actions/Checkout", "v6", "v1 path", "path not a scalar"}, c.name) {
			t.Errorf("%s: checkout %v", c.name, got.checkout)
		}
	}
}
