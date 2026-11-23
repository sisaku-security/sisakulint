package rules

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/prcode"
	"github.com/gh-intel/sisakulint/actions/workflow"
	"github.com/gh-intel/sisakulint/internal/corpus"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// anyRef answers every git.ref-commit with one commit, found as the tag of
// the ref's name, so that every finding gets a fix and every fix is checked.
// With commits, it answers every git.commit-ref with refs/heads/main;
// without, not at all, as a run without the network.
type anyRef struct{ commits bool }

func (a anyRef) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	switch q := q.(type) {
	case facts.GitRefCommit:
		commit := sha
		if q.Repo == prcode.CheckoutRepo && prcode.TagGuarded(q.Ref) {
			// a release of actions/checkout with the guard is at a commit
			// that has it (v4.4.0's), as on GitHub: the pin of commit-sha
			// then makes no new finding of untrusted-checkout
			commit = "11d5960a326750d5838078e36cf38b85af677262"
		}
		// the two download actions are at a commit of prcode's tables of
		// the major the ref names, as on GitHub: the pin of commit-sha then
		// keeps the reading of artifact-poisoning
		before4 := strings.HasPrefix(q.Ref, "v1") || strings.HasPrefix(q.Ref, "v2") || strings.HasPrefix(q.Ref, "v3")
		switch {
		case q.Repo == prcode.DownloadArtifactRepo && before4:
			commit = "9bc31d5ccc31df68ecc42ccf4149144866c47d8a" // v3
		case q.Repo == prcode.DownloadArtifactRepo:
			commit = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" // v8.0.1
		case q.Repo == prcode.Dawidd6Repo && before4:
			commit = "09f2f74827fd3a8607589e5ad7f9398816f540fe" // v3
		case q.Repo == prcode.Dawidd6Repo:
			commit = "eab87c9830c39eff17e5a6eadb20bfb4bc880477" // v27
		}
		b, _ := json.Marshal(map[string]string{"sha": commit, "ref": "refs/tags/" + q.Ref})
		return facts.RawAnswer{State: facts.StateFound, Value: b}
	case facts.GitCommitRef:
		if a.commits {
			return facts.RawAnswer{State: facts.StateFound, Value: []byte(`"refs/heads/main"`)}
		}
	}
	return facts.RawAnswer{State: facts.StateUnknown, Reason: "not in the table"}
}

// TestCorpus runs every rule on each repository of yaml/corpus (real-world,
// org, sisakuintel and labeler-token): no internal error (so every fix closes
// its finding), a report that fits its schema. It logs how many inputs have
// diagnostics, which is bit 2 of the exit code; the findings of
// impostor-commit that are conditional when git.commit-ref is not known (a
// run without the network), and the time. Unless ACTIONS_CORPUS=full, one
// repository in seven of each group. The repositories are read and run in
// parallel (inOrder); the five that took longest are logged.
func TestCorpus(t *testing.T) {
	var repos []string
	for _, group := range []string{"real-world", "org", "sisakuintel", "labeler-token"} {
		dir := filepath.Join(corpus.Dir(t), "files", group)
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for i, e := range ents {
			if e.IsDir() && (corpus.Full() || i%7 == 0) {
				repos = append(repos, filepath.Join(dir, e.Name()))
			}
		}
	}
	reg, err := lint.NewRegistry(All())
	if err != nil {
		t.Fatal(err)
	}
	s := schemaSet(t)
	inputs, invalid, findings, fixes, conditional, undecided := 0, 0, 0, 0, 0, 0
	injections, injectionFixes, syntaxChecked := 0, 0, 0
	gaps := map[string]int{}
	fileCmds, fileCmdFixes := map[string]int{}, 0
	checkouts := map[string]int{} // by kind, and by kind and repository
	jobs := map[string]int{}      // dangerous-triggers and self-hosted-runner by kind; unwritten: token-write on the default
	images := map[string]int{}    // unpinned-images and credentials by kind, and by kind and site or repository
	downloads := map[string]int{} // artifact-poisoning by kind, by kind and repository, and by the input that names the run
	start := time.Now()
	// what a repository's inputs and runs are, computed in parallel
	// (inOrder); the counts are gathered in the order of the repositories
	type computed struct {
		in             lint.Inputs
		rep, offline   lint.Report
		err, schemaErr error
		took           time.Duration
	}
	took := make([]time.Duration, len(repos))
	inOrder(len(repos), func(i int) (v computed) {
		// a panic off the goroutine of the test would end the binary with
		// no test's name: it is the error of the repository instead
		defer func() {
			if p := recover(); p != nil {
				v = computed{err: fmt.Errorf("%s: panic: %v\n%s", filepath.Base(repos[i]), p, debug.Stack())}
			}
		}()
		began := time.Now()
		in, err := lint.Enumerate(os.DirFS(repos[i]))
		if err != nil {
			return computed{err: err}
		}
		v = computed{in: in, rep: lint.Run(context.Background(), in, reg, anyRef{commits: true})}
		b, err := json.Marshal(v.rep)
		if err != nil {
			return computed{err: err}
		}
		v.schemaErr = s.Validate("report-v0.json", "#", b)
		v.offline = lint.Run(context.Background(), in, reg, anyRef{})
		v.took = time.Since(began)
		return v
	}, func(i int, v computed) {
		repo := repos[i]
		if v.err != nil {
			t.Fatal(v.err)
		}
		in, rep := v.in, v.rep
		took[i] = v.took
		for _, e := range rep.Errors {
			t.Errorf("%s: %s %s: %s", filepath.Base(repo), e.Rule, e.Input, e.Message)
		}
		if v.schemaErr != nil {
			t.Errorf("%s: the report does not fit report-v0.json: %v", filepath.Base(repo), v.schemaErr)
		}
		for _, i := range in.List {
			inputs++
			if i.State != lint.InputStateRead {
				invalid++
				t.Logf("%s: %s is %v: %d diagnostics %s", filepath.Base(repo), i.Name, i.State, len(i.Diagnostics), i.Reason)
			}
		}
		repoInjections, repoGaps := 0, 0
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			findings++
			if f.Fix != nil {
				fixes++
			}
			if f.Rule == ImpostorCommitID {
				t.Errorf("%s: impostor-commit with every commit on main: %s", filepath.Base(repo), f.Detected())
			}
			switch f.Rule {
			case CodeInjectionID:
				injections++
				repoInjections++
				if f.Fix != nil {
					injectionFixes++
				}
			case EnvvarInjectionID, OutputClobberingID, EnvpathInjectionID:
				fileCmds[f.Rule.String()]++
				if f.Fix != nil {
					fileCmdFixes++
				}
			case UntrustedCheckoutID, UntrustedCheckoutToctouID:
				checkouts[f.Args.KindID().String()]++
				checkouts[f.Args.KindID().String()+" "+filepath.Base(repo)]++
			case UnpinnedImagesID, CredentialsID:
				images[f.Args.KindID().String()]++
				images[f.Args.KindID().String()+" "+filepath.Base(repo)]++
				if a, ok := f.Args.(UnpinnedImagesMutable); ok {
					images["site "+a.Site.String()]++
				}
			case ArtifactPoisoningID:
				downloads[f.Args.KindID().String()]++
				downloads[f.Args.KindID().String()+" "+filepath.Base(repo)]++
			case DangerousTriggersID, SelfHostedRunnerID:
				jobs[f.Args.KindID().String()]++
				if f.Condition != nil && slices.ContainsFunc(f.Condition.Queries(), func(q facts.Query) bool { return q.Kind() == facts.KindRepoDefaultTokenWrite }) {
					jobs["unwritten"]++
				}
			}
		}
		for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
			gaps[g.InconclusiveKind.String()]++
			repoGaps++
		}
		if repoInjections+repoGaps > 0 {
			t.Logf("%s: code-injection %d findings; %d places not examined of all the rules", filepath.Base(repo), repoInjections, repoGaps)
		}
		if corpus.Full() {
			n, _ := checkFixedSyntax(t, filepath.Base(repo), in, reg, anyRef{commits: true}, rep)
			syntaxChecked += n
		}
		offline := v.offline
		for _, f := range offline.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			if f.Rule == ImpostorCommitID && f.Certainty == lint.CertaintyConditional {
				conditional++
			}
		}
		if lint.Classify(offline, lint.SeverityInfo)&lint.UndecidedBit != 0 && lint.Classify(rep, lint.SeverityInfo)&lint.UndecidedBit == 0 {
			undecided++
		}
	})
	slowest := make([]int, len(repos))
	for i := range slowest {
		slowest[i] = i
	}
	slices.SortFunc(slowest, func(a, b int) int { return cmp.Compare(took[b], took[a]) })
	for _, i := range slowest[:min(5, len(slowest))] {
		t.Logf("%s: %v to read and run", filepath.Base(repos[i]), took[i].Round(time.Millisecond))
	}
	if findings > 0 && fixes == 0 {
		t.Error("no finding has a fix: the fixes, and that each fix closes its finding, are not checked")
	}
	t.Logf("%d repositories, %d inputs (%d not read cleanly), %d findings, %d fixes, in %v", len(repos), inputs, invalid, findings, fixes, time.Since(start))
	t.Logf("without git.commit-ref: %d conditional findings of impostor-commit; %d of %d repositories have bit 2 only for them", conditional, undecided, len(repos))
	t.Logf("code-injection: %d findings (%d with a fix); places not examined of all the rules %v; %d fixed run scripts checked with bash -n", injections, injectionFixes, gaps, syntaxChecked)
	t.Logf("file commands: %v findings (%d with a fix)", fileCmds, fileCmdFixes)
	t.Logf("checkouts: %v", checkouts)
	t.Logf("jobs: %v", jobs)
	t.Logf("images: %v", images)
	t.Logf("downloads: %v", downloads)
}

// checkFixedSyntax applies the fixes of rep (safe and to review), answered
// by r, and checks, with bash -n (which reads a script and runs nothing),
// that every run script of bash they change is still bash if it was
// before. The scripts of the corpus are not run: they would run whatever
// they say. It gives how many scripts it checked, and what the fixes
// gave.
func checkFixedSyntax(t *testing.T, label string, in lint.Inputs, reg *lint.Registry, r facts.Resolver, rep lint.Report) (int, lint.Applied) {
	t.Helper()
	applied, err := lint.ApplyFixes(context.Background(), in, reg, r, rep, lint.SafetyReview)
	if err != nil {
		t.Errorf("%s: ApplyFixes: %v", label, err)
		return 0, lint.Applied{}
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		return 0, applied
	}
	valid := func(script string) bool { return exec.Command(bash, "-n", "-c", script).Run() == nil }
	n := 0
	for file, b := range applied.Files {
		i, _ := in.Lookup(file)
		before, after := runScripts(i.Tree.Bytes(), i.InputKind), runScripts(b, i.InputKind)
		for k, s := range after {
			if old, ok := before[k]; ok && old != s {
				n++
				if valid(old) && !valid(s) {
					t.Errorf("%s: %s: the fix breaks the script of %s:\n%s", label, file, k, s)
				}
			}
		}
	}
	return n, applied
}

// runScripts are the run scripts of an input, by job and step.
func runScripts(src []byte, kind lint.InputKind) map[string]string {
	tr := cst.ParseMode(src, cst.ModeGitHub)
	out := map[string]string{}
	add := func(prefix string, steps []workflow.Step) {
		for i, s := range steps {
			if s.Run.Status == workflow.Present {
				out[fmt.Sprintf("%s step %d", prefix, i)] = s.Run.Value.Text()
			}
		}
	}
	if kind == lint.InputKindActionMetadata {
		if a, _ := workflow.ParseActionMetadata(tr); a != nil {
			add("runs", a.Runs.Value.Steps.Value.Items)
		}
		return out
	}
	if w, _ := workflow.Parse(tr); w != nil {
		for _, j := range w.Jobs.Value.Entries {
			add("job "+j.Key.AsString(), j.Value.Value.Steps.Value.Items)
		}
	}
	return out
}
