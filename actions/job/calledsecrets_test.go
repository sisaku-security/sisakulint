package job

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/attacker"
	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/composite"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/internal/callerstest"
)

const ciPath = ".github/workflows/ci.yml"

// jobIn is the job id of the workflow at ciPath, read in g.
func jobIn(t *testing.T, g *calls.Graph, id string) Job {
	t.Helper()
	n := calls.InputNode(facts.MustCleanInputPath(ciPath))
	f, ok := g.File(n)
	if !ok || f.Workflow == nil {
		t.Fatalf("no %s", ciPath)
	}
	for _, j := range AnalyzeIn(f.Workflow, attacker.Outsider, g, n) {
		if j.Job.ID.AsString() == id {
			return j
		}
	}
	t.Fatalf("no job %s", id)
	return Job{}
}

// calledJob is the job a of ci.yml among files, the whole repository.
func calledJob(t *testing.T, files ...[2]string) Job {
	t.Helper()
	return jobIn(t, callerstest.Graph(t, true, false, files...), "a")
}

func wf(name, src string) [2]string { return [2]string{".github/workflows/" + name, src} }

// called is a reusable workflow whose one job has the step values steps.
func called(steps string) string {
	return "on:\n  workflow_call:\njobs:\n  c:\n    runs-on: x\n    steps:\n      - run: x\n" + steps
}

func env(v string) string { return "        env: {X: '${{ " + v + " }}'}\n" }

func inheritCI(target string) [2]string {
	return wf("ci.yml", "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/"+target+"\n    secrets: inherit\n")
}

func contextTexts(rs []CalledContextRead) string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Read.Text)
	}
	return strings.Join(out, ",")
}

// TestCalledSecrets: what a job that
// calls a reusable workflow of the inputs with secrets: inherit reads is
// what the called workflow's jobs read.
func TestCalledSecrets(t *testing.T) {
	mid := func(target string) string {
		return "on:\n  workflow_call:\njobs:\n  m:\n    uses: ./.github/workflows/" + target + "\n    secrets: inherit\n"
	}
	for _, c := range []struct {
		name     string
		files    [][2]string
		all      bool
		names    string
		nameless string
	}{
		{"unread", [][2]string{inheritCI("c.yml"), wf("c.yml", called(""))}, false, "", ""},
		{"named", [][2]string{inheritCI("c.yml"), wf("c.yml", called(env("secrets.A")+"      - run: ${{ secrets.a }}\n"))}, false, "A", ""},
		{"nameless", [][2]string{inheritCI("c.yml"), wf("c.yml", called(env("toJSON(secrets)")))}, true, "", "secrets"},
		{"workflow env", [][2]string{inheritCI("c.yml"), wf("c.yml", "on:\n  workflow_call:\nenv: {W: '${{ secrets.W }}'}\njobs:\n  c:\n    runs-on: x\n    steps:\n      - run: x\n")}, false, "W", ""},
		{"two jobs", [][2]string{inheritCI("c.yml"), wf("c.yml", "on:\n  workflow_call:\njobs:\n  c:\n    runs-on: x\n    steps:\n      - run: ${{ secrets.A }}\n  d:\n    runs-on: x\n    steps:\n      - run: ${{ secrets.B }}\n")}, false, "A,B", ""},
		{"nested plain", [][2]string{inheritCI("mid.yml"), wf("mid.yml", mid("inner.yml")), wf("inner.yml", called(env("secrets.A")))}, false, "A", ""},
		{"nested tojson", [][2]string{inheritCI("mid.yml"), wf("mid.yml", mid("inner.yml")), wf("inner.yml", called(env("toJSON(secrets)")))}, true, "", "secrets"},
		{"cycle", [][2]string{inheritCI("c1.yml"),
			wf("c1.yml", "on:\n  workflow_call:\njobs:\n  x:\n    runs-on: x\n    steps:\n      - run: ${{ secrets.A }}\n  y:\n    uses: ./.github/workflows/c2.yml\n    secrets: inherit\n"),
			wf("c2.yml", mid("c1.yml"))}, false, "A", ""},
		{"diamond", [][2]string{wf("ci.yml", "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/top.yml\n    secrets: inherit\n"),
			wf("top.yml", "on:\n  workflow_call:\njobs:\n  b:\n    uses: ./.github/workflows/b.yml\n    secrets: inherit\n  c:\n    uses: ./.github/workflows/c.yml\n    secrets: inherit\n"),
			wf("b.yml", mid("d.yml")), wf("c.yml", mid("d.yml")), wf("d.yml", called(env("toJSON(secrets)")))}, true, "", "secrets"},
		{"missing file", [][2]string{inheritCI("c.yml")}, true, "", ""},
		{"nested missing", [][2]string{inheritCI("mid.yml"), wf("mid.yml", mid("inner.yml"))}, true, "", ""},
		{"no workflow_call", [][2]string{inheritCI("c.yml"), wf("c.yml", "on: push\njobs:\n  c:\n    runs-on: x\n    steps:\n      - run: x\n")}, true, "", ""},
		{"token", [][2]string{inheritCI("c.yml"), wf("c.yml", called(env("secrets.GITHUB_TOKEN")))}, false, "", ""},
	} {
		j := calledJob(t, c.files...)
		if j.Secrets.All != c.all || strings.Join(j.Secrets.Names, ",") != c.names || contextTexts(j.CalledContextReads) != c.nameless {
			t.Errorf("%s: %+v %q, want %v %q %q", c.name, j.Secrets, contextTexts(j.CalledContextReads), c.all, c.names, c.nameless)
		}
		if j.Secrets.Token {
			t.Errorf("%s: the called job's token is not the calling job's", c.name)
		}
	}
}

// TestCalledSecretsNodes: the context reads are where they are written, in
// the called workflow, nested ones too.
func TestCalledSecretsNodes(t *testing.T) {
	j := calledJob(t, inheritCI("mid.yml"),
		wf("mid.yml", "on:\n  workflow_call:\njobs:\n  m:\n    uses: ./.github/workflows/inner.yml\n    secrets: inherit\n"),
		wf("inner.yml", called(env("toJSON(secrets)"))))
	if len(j.CalledContextReads) != 1 || j.CalledContextReads[0].Node.String() != ".github/workflows/inner.yml" {
		t.Fatalf("%+v", j.CalledContextReads)
	}
}

// TestCalledSecretsUnread: a call the analysis does not have the contents
// of reads every secret, as before: a full ref to the repository itself,
// and no graph.
func TestCalledSecretsUnread(t *testing.T) {
	r, err := facts.ParseRepo("o/r")
	if err != nil {
		t.Fatal(err)
	}
	fs := []calls.File{
		callerstest.File(t, ciPath, "on: issues\njobs:\n  a:\n    uses: o/r/.github/workflows/c.yml@main\n    secrets: inherit\n"),
		callerstest.File(t, ".github/workflows/c.yml", called("")),
	}
	if j := jobIn(t, calls.New(fs, true, false, r), "a"); !j.Secrets.All || len(j.CalledContextReads) != 0 {
		t.Errorf("own repo at ref: %+v", j.Secrets)
	}
	if j := one(t, "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/c.yml\n    secrets: inherit\n"); !j.Secrets.All {
		t.Errorf("no graph: %+v", j.Secrets)
	}
}

// TestCalledSecretsTwoCallers: each calling job reads by
// how it passes.
func TestCalledSecretsTwoCallers(t *testing.T) {
	g := callerstest.Graph(t, true, false,
		wf("ci.yml", "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/c.yml\n    secrets: inherit\n  b:\n    uses: ./.github/workflows/c.yml\n    secrets: {X: '${{ secrets.X }}'}\n"),
		wf("c.yml", called(env("secrets.A"))))
	if a := jobIn(t, g, "a"); strings.Join(a.Secrets.Names, ",") != "A" || a.Secrets.All {
		t.Errorf("a: %+v", a.Secrets)
	}
	if b := jobIn(t, g, "b"); len(b.Secrets.Names) != 0 || b.Secrets.All {
		t.Errorf("b: %+v", b.Secrets) // X is passed as X and not read
	}
}

// TestCalledSecretsNamed: for secrets passed by name, a key the called
// workflow does not read gives nothing.
func TestCalledSecretsNamed(t *testing.T) {
	ci := func(secrets string) [2]string {
		return wf("ci.yml", "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/c.yml\n    secrets:"+secrets)
	}
	mid := func(secrets string) [2]string {
		return wf("mid.yml", "on:\n  workflow_call:\njobs:\n  m:\n    uses: ./.github/workflows/inner.yml\n    secrets:"+secrets)
	}
	toMid := wf("ci.yml", "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/mid.yml\n    secrets: inherit\n")
	for _, c := range []struct {
		name     string
		files    [][2]string
		all      bool
		names    string
		nameless string
	}{
		{"unread", [][2]string{ci(" {A: '${{ secrets.A }}', B: '${{ secrets.B }}'}\n"), wf("c.yml", called(env("secrets.A")))}, false, "A", ""},
		{"key differs", [][2]string{ci(" {K: '${{ secrets.X }}'}\n"), wf("c.yml", called(env("secrets.k")))}, false, "X", ""},
		{"called nameless", [][2]string{ci(" {A: '${{ secrets.A }}', B: '${{ secrets.B }}'}\n"), wf("c.yml", called(env("toJSON(secrets)")))}, false, "A,B", ""},
		{"value nameless", [][2]string{ci(" {ALL: '${{ toJSON(secrets) }}'}\n"), wf("c.yml", called(env("secrets.ALL")))}, true, "", ""},
		{"value nameless unread", [][2]string{ci(" {ALL: '${{ toJSON(secrets) }}'}\n"), wf("c.yml", called(""))}, false, "", ""},
		{"missing file", [][2]string{ci(" {A: '${{ secrets.A }}'}\n")}, false, "A", ""},
		{"nested unread", [][2]string{toMid, mid(" {K: '${{ secrets.B }}'}\n"), wf("inner.yml", called(""))}, false, "", ""},
		{"nested read", [][2]string{toMid, mid(" {K: '${{ secrets.B }}'}\n"), wf("inner.yml", called(env("secrets.K")))}, false, "B", ""},
		{"nested value nameless", [][2]string{toMid, mid(" {K: '${{ toJSON(secrets) }}'}\n"), wf("inner.yml", called(env("secrets.K")))}, true, "", "secrets"},
		{"named then inherit", [][2]string{wf("ci.yml", "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/mid.yml\n    secrets: {A: '${{ secrets.A }}'}\n"),
			mid(" inherit\n"), wf("inner.yml", called(env("toJSON(secrets)")))}, false, "A", ""},
	} {
		j := calledJob(t, c.files...)
		if j.Secrets.All != c.all || strings.Join(j.Secrets.Names, ",") != c.names || contextTexts(j.CalledContextReads) != c.nameless {
			t.Errorf("%s: %+v %q, want %v %q %q", c.name, j.Secrets, contextTexts(j.CalledContextReads), c.all, c.names, c.nameless)
		}
	}
}

// TestCalledSecretsRemote: a reusable workflow of another repository whose
// contents workflow.definition answered is read as one of the inputs
// one with no answer is not in the
// graph and reads every secret.
func TestCalledSecretsRemote(t *testing.T) {
	for _, c := range []struct {
		name, called string
		answered     bool
		all          bool
		names        string
	}{
		{"named", called(env("secrets.A")), true, false, "A"},
		{"unread", called(""), true, false, ""},
		{"nameless", called(env("toJSON(secrets)")), true, true, ""},
		{"no answer", "", false, true, ""},
	} {
		g := callerstest.Graph(t, true, false, wf("ci.yml", "on: issues\njobs:\n  a:\n    uses: o/wf/.github/workflows/w.yml@v1\n    secrets: inherit\n"))
		ci, _ := g.File(calls.InputNode(facts.MustCleanInputPath(ciPath)))
		job := &ci.Workflow.Jobs.Value.Entries[0].Value.Value
		if c.answered {
			cf := callerstest.File(t, ".github/workflows/w.yml", c.called)
			repo, err := facts.ParseRepo("o/wf")
			if err != nil {
				t.Fatal(err)
			}
			path, err := facts.ParseUsesPath(".github/workflows/w.yml")
			if err != nil {
				t.Fatal(err)
			}
			q := facts.WorkflowDefinition{Repo: repo, Path: path, Ref: "v1"}
			r := &calls.RemoteCalled{Called: composite.Called{Workflow: cf.Workflow, Origin: composite.Origin{Query: q, Tree: cf.Tree}, By: job, Parent: -1}, Top: ci.Name, TopJob: job}
			g.AddRemote(r, calls.Call{Caller: ci.Node(), Job: job, StepIndex: -1, With: job.With, Resolved: true})
		}
		j := jobIn(t, g, "a")
		if j.Secrets.All != c.all || strings.Join(j.Secrets.Names, ",") != c.names {
			t.Errorf("%s: %+v, want %v %q", c.name, j.Secrets, c.all, c.names)
		}
		if c.name == "nameless" && (len(j.CalledContextReads) != 1 || j.CalledContextReads[0].Node.IsZero()) {
			t.Errorf("%s: %+v", c.name, j.CalledContextReads)
		}
	}
}

// TestCalledSecretsLoopThroughSelf: a call back to the workflow of the
// calling job is a loop, which GitHub refuses: the other jobs of that
// workflow are not read for it.
func TestCalledSecretsLoopThroughSelf(t *testing.T) {
	j := calledJob(t,
		wf("ci.yml", "on: [issues, workflow_call]\njobs:\n  a:\n    uses: ./.github/workflows/c.yml\n    secrets: inherit\n  b:\n    runs-on: x\n    steps:\n      - run: x\n"+env("toJSON(secrets)")),
		wf("c.yml", "on:\n  workflow_call:\njobs:\n  c:\n    uses: ./.github/workflows/ci.yml\n    secrets: inherit\n"))
	if j.Secrets.All || len(j.CalledContextReads) != 0 {
		t.Errorf("%+v %+v", j.Secrets, j.CalledContextReads)
	}
}
