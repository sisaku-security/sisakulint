package job

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// TestHostedSudo: only labels of GitHub-hosted Linux and macOS runners,
// whose user has passwordless sudo, decide it; any other label, a group, a
// ${{ }} or a matrix with one such value does not.
func TestHostedSudo(t *testing.T) {
	for _, c := range []struct {
		name, runsOn, strategy string
		want                   bool
	}{
		{"ubuntu", "ubuntu-latest", "", true},
		{"macos", "macos-15", "", true},
		{"arm", "ubuntu-24.04-arm", "", true},
		{"upper", "Ubuntu-Latest", "", true},
		{"windows", "windows-latest", "", false},
		{"self-hosted", "[self-hosted, linux]", "", false},
		{"hosted and another", "[ubuntu-latest, gpu]", "", false},
		{"custom", "my-large-runner", "", false},
		{"expr", "${{ inputs.os }}", "", false},
		{"matrix hosted", "${{ matrix.os }}", "    strategy: {matrix: {os: [ubuntu-latest, macos-15]}}\n", true},
		{"retired", "macos-14", "", false},
		{"matrix with windows", "${{ matrix.os }}", "    strategy: {matrix: {os: [ubuntu-latest, windows-latest]}}\n", false},
		{"matrix not written", "${{ matrix.os }}", "    strategy: {matrix: {os: '${{ fromJSON(inputs.o) }}'}}\n", false},
		{"group", "{group: g}", "", false},
		{"group with a hosted label", "{group: g, labels: ubuntu-latest}", "", false},
		{"labels only", "{labels: ubuntu-latest}", "", false},
		{"container", "ubuntu-latest", "    container: node:20\n", false},
	} {
		j := one(t, "on: push\njobs:\n  a:\n    runs-on: "+c.runsOn+"\n"+c.strategy+"    steps: [{run: x}]\n")
		if got := HostedSudo(j.Job); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestHostedLabelsUpstream: each label is in the table of GitHub-hosted
// runners of the pinned github/docs.
func TestHostedLabelsUpstream(t *testing.T) {
	if os.Getenv("ACTIONS_UPSTREAM") == "" {
		t.Skip("ACTIONS_UPSTREAM is not set")
	}
	out, err := exec.Command("curl", "-sSfL", workflow.HostedRunnerLabelsSource).Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range hostedLabels {
		if !strings.Contains(string(out), ">"+l.String()+"</a></code>") {
			t.Errorf("%s is not in %s", l, workflow.HostedRunnerLabelsSource)
		}
	}
}

// valueOf is the run of the one step of a workflow whose run is src.
func valueOf(t *testing.T, src string) workflow.String {
	t.Helper()
	j := one(t, "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: "+src+"\n")
	return j.Job.Steps.Value.Items[0].Run.Value
}

// TestSecretsToken: the job's token, in any case, through secrets or the
// github context, is Token, not a name; Without leaves what held does not
// read.
func TestSecretsToken(t *testing.T) {
	for _, src := range []string{"'${{ secrets.GITHUB_TOKEN }}'", "'${{ secrets.github_token }}'", "'${{ github.token }}'", "'${{ GITHUB.TOKEN }}'", "'${{ secrets[''GITHUB_TOKEN''] }}'", "'${{ toJSON(github) }}'", "'${{ github[inputs.k] }}'"} {
		s := SecretsOf(valueOf(t, src))
		if !s.Token || len(s.Names) != 0 || s.All {
			t.Errorf("%s: %+v", src, s)
		}
	}
	s := SecretsOf(valueOf(t, "'${{ secrets.NPM }} ${{ toJSON(secrets) }}'"))
	if s.Token || !s.All || len(s.Names) != 1 {
		t.Errorf("%+v", s)
	}
	more := SecretsOf(valueOf(t, "'${{ secrets.A }} ${{ secrets.b }} ${{ github.token }}'")).Without(SecretsOf(valueOf(t, "'${{ secrets.a }}'")))
	if !slices.Equal(more.Names, []string{"b"}) || !more.Token || more.All {
		t.Errorf("without: %+v", more)
	}
	if all := SecretsOf(valueOf(t, "'${{ secrets.A }} ${{ github.token }}'")).Without(Secrets{All: true}); len(all.Names) != 0 || all.Token {
		t.Errorf("without all: %+v", all)
	}
}

// TestSecretsNotToken: a property of the github context other than token
// is not the job's token; the github context under it is not read again.
func TestSecretsNotToken(t *testing.T) {
	for _, src := range []string{"'${{ github.event.head_commit.message }}'", "'${{ github.repository }}'", "'${{ github.event[inputs.k] }}'"} {
		if s := SecretsOf(valueOf(t, src)); s.Token || s.All || len(s.Names) != 0 {
			t.Errorf("%s: %+v", src, s)
		}
	}
	if s := SecretsOf(valueOf(t, "'${{ github.event[secrets.K] }}'")); s.Token || !slices.Equal(s.Names, []string{"K"}) {
		t.Errorf("an index of a path: %+v", s)
	}
}

// TestHosted: who runs the machine of a job, by its runs-on: every label
// one of GitHub's hosted runners (a Windows one too), a self-hosted label,
// or neither.
func TestHosted(t *testing.T) {
	for _, c := range []struct {
		runsOn string
		want   analysis.RunnerHosting
	}{
		{"ubuntu-latest", analysis.RunnerHostingGitHub},
		{"windows-latest", analysis.RunnerHostingGitHub},
		{"windows-11-arm", analysis.RunnerHostingGitHub},
		{"macos-15", analysis.RunnerHostingGitHub},
		{"[self-hosted, linux]", analysis.RunnerHostingSelfHosted},
		{"macos-14", analysis.RunnerHostingUnknown},
		{"my-runner", analysis.RunnerHostingUnknown},
		{"{group: ci}", analysis.RunnerHostingUnknown},
		{"${{ inputs.os }}", analysis.RunnerHostingUnknown},
	} {
		j := one(t, "on: push\njobs:\n  a:\n    runs-on: "+c.runsOn+"\n    steps:\n      - run: x\n")
		if got := Hosted(j.Job); got != c.want {
			t.Errorf("%s: %v, want %v", c.runsOn, got, c.want)
		}
	}
}

// TestServiceNames: the names of the services of a job, which its steps
// reach by name.
func TestServiceNames(t *testing.T) {
	j := one(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    services:\n      postgres:\n        image: postgres\n      redis:\n        image: redis\n    steps:\n      - run: x\n")
	if got := ServiceNames(j.Job); !slices.Equal(got, []string{"postgres", "redis"}) {
		t.Errorf("%v", got)
	}
}
