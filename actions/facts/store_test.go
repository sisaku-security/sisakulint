package facts

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func file(entries ...string) string {
	return `{"schema": "sisakulint/facts/v0", "facts": [` + strings.Join(entries, ",") + `]}`
}

func TestLoadStore(t *testing.T) {
	s, err := LoadStore([]byte(file(
		`{"query": {"kind": "test.flag", "name": "on"}, "state": "found", "value": true}`,
		`{"query": {"kind": "test.flag", "name": "gone"}, "state": "absent"}`,
		`{"query": {"kind": "test.flag", "name": "dunno"}, "state": "unknown", "reason": "rate limit"}`,
		`{"query": {"kind": "test.repo-flag", "repo": "Org/App"}, "state": "found", "value": false}`,
	)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, c := range []struct {
		q     Query
		state State
		value string
		why   string
	}{
		{TestFlag{Name: "on"}, StateFound, "true", ""},
		{TestFlag{Name: "gone"}, StateAbsent, "", ""},
		{TestFlag{Name: "dunno"}, StateUnknown, "", "rate limit"},
		{TestRepoFlag{Repo: mustRepo(t, "org/app")}, StateFound, "false", ""},
		{TestFlag{Name: "other"}, StateUnknown, "", "not in the file of facts"},
	} {
		r := s.Resolve(ctx, c.q)
		if r.State != c.state || string(r.Value) != c.value || !strings.Contains(r.Reason, c.why) {
			t.Errorf("Resolve(%#v) = %+v, want %v %s %q", c.q, r, c.state, c.value, c.why)
		}
	}
}

func TestLoadStoreRejects(t *testing.T) {
	flag := `{"kind": "test.flag", "name": "a"}`
	for _, c := range []struct{ name, src string }{
		{"another version", `{"schema": "sisakulint/facts/v1", "facts": []}`},
		{"the schema identifier of the old product name", `{"schema": "sisakulint-poc/facts/v0", "facts": []}`},
		{"unknown kind", file(`{"query": {"kind": "test.nope", "name": "a"}, "state": "absent"}`)},
		{"bad argument", file(`{"query": {"kind": "test.repo-flag", "repo": "nope"}, "state": "absent"}`)},
		{"value off x-value", file(`{"query": ` + flag + `, "state": "found", "value": "yes"}`)},
		{"found without value", file(`{"query": ` + flag + `, "state": "found"}`)},
		{"absent with value", file(`{"query": ` + flag + `, "state": "absent", "value": true}`)},
		{"unknown without reason", file(`{"query": ` + flag + `, "state": "unknown"}`)},
		{"bad state", file(`{"query": ` + flag + `, "state": "maybe"}`)},
		{"twice", file(`{"query": `+flag+`, "state": "absent"}`, `{"query": `+flag+`, "state": "found", "value": true}`)},
		{"twice after normalizing", file(
			`{"query": {"kind": "test.repo-flag", "repo": "Org/App"}, "state": "absent"}`,
			`{"query": {"kind": "test.repo-flag", "repo": "org/app"}, "state": "absent"}`)},
		{"assumed", file(`{"query": ` + flag + `, "state": "found", "value": true, "assumed": true}`)},
		{"source assumption", file(`{"query": ` + flag + `, "state": "found", "value": true, "source": "assumption"}`)},
		{"extra member", file(`{"query": ` + flag + `, "state": "absent", "when": "now"}`)},
		{"not JSON", `{`},
		{"found with reason", file(`{"query": ` + flag + `, "state": "found", "value": true, "reason": "r"}`)},
		{"absent with reason", file(`{"query": ` + flag + `, "state": "absent", "reason": "r"}`)},
		{"unknown with value", file(`{"query": ` + flag + `, "state": "unknown", "value": true, "reason": "r"}`)},
		{"allowed actions all with patterns", file(`{"query": {"kind": "repo.allowed-actions"}, "state": "found", "value": {"allowed_actions": "all", "sha_pinning_required": false, "patterns_allowed": []}}`)},
		{"allowed actions selected without verified_allowed", file(`{"query": {"kind": "repo.allowed-actions"}, "state": "found", "value": {"allowed_actions": "selected", "sha_pinning_required": false, "github_owned_allowed": true, "patterns_allowed": []}}`)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := LoadStore([]byte(c.src)); err == nil {
				t.Error("no error")
			}
		})
	}
}

func TestEncodeFile(t *testing.T) {
	ctx := context.Background()
	rec := NewRecorder(resolverFunc(func(_ context.Context, q Query) RawAnswer {
		if _, ok := q.(TestFlag); ok {
			return RawAnswer{State: StateUnknown, Reason: "rate limit"}
		}
		return RawAnswer{State: StateAbsent}
	}))
	rec.Resolve(ctx, TestFlag{Name: "a"})
	rec.Resolve(ctx, TestRepoFlag{Repo: mustRepo(t, "o/r")})
	b, err := EncodeFile(rec.Entries())
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"schema\":\"sisakulint/facts/v0\",\"facts\":[\n" +
		`{"query":{"kind":"test.flag","name":"a"},"state":"unknown","reason":"rate limit"},` + "\n" +
		`{"query":{"kind":"test.repo-flag","repo":"o/r"},"state":"absent"}` + "\n]}\n"
	if string(b) != want {
		t.Errorf("EncodeFile =\n%s\nwant\n%s", b, want)
	}
	s, err := LoadStore(b)
	if err != nil {
		t.Fatal(err)
	}
	if r := s.Resolve(ctx, TestFlag{Name: "a"}); r.State != StateUnknown || r.Reason != "rate limit" {
		t.Errorf("read back %+v", r)
	}
	empty, _ := EncodeFile([]Entry{})
	none, _ := EncodeFile(nil)
	if string(empty) != string(none) || string(none) != "{\"schema\":\"sisakulint/facts/v0\",\"facts\":[\n]}\n" {
		t.Errorf("EncodeFile(nil) = %q, EncodeFile([]) = %q", none, empty)
	}
	if _, err := LoadStore(none); err != nil {
		t.Errorf("LoadStore(EncodeFile(nil)): %v", err)
	}
}

// TestEncodeFileRejectsAState: an entry whose state is not one is an error,
// not a file of facts that cannot be read.
func TestEncodeFileRejectsAState(t *testing.T) {
	if b, err := EncodeFile([]Entry{{Query: TestFlag{Name: "a"}, RawAnswer: RawAnswer{State: State(7)}}}); err == nil {
		t.Errorf("EncodeFile = %s, want an error", b)
	}
}

func TestEncodeFileAssumed(t *testing.T) {
	ctx := context.Background()
	rec := NewRecorder(resolverFunc(func(_ context.Context, q Query) RawAnswer {
		if q.(TestFlag).Name == "assumed" {
			return RawAnswer{State: StateFound, Value: []byte("true"), Source: SourceAssumption}
		}
		return RawAnswer{State: StateFound, Value: []byte("false")}
	}))
	rec.Resolve(ctx, TestFlag{Name: "assumed"})
	rec.Resolve(ctx, TestFlag{Name: "real"})
	var lines []string
	for _, e := range rec.Entries() {
		b, err := e.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(b))
	}
	want := []string{
		`{"query":{"kind":"test.flag","name":"assumed"},"state":"found","value":true,"source":"assumption"}`,
		`{"query":{"kind":"test.flag","name":"real"},"state":"found","value":false}`,
	}
	if !slices.Equal(lines, want) {
		t.Errorf("entries\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	b, err := EncodeFile(rec.Entries())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "assumed") || !strings.Contains(string(b), `"real"`) {
		t.Errorf("a file of facts holds only what was found out:\n%s", b)
	}
	if _, err := LoadStore(b); err != nil {
		t.Error(err)
	}
}

// A file of facts says a checkout is read as data; a step that is not a
// StepPath, or an environment name that is none, is refused.
func TestLoadStoreCheckout(t *testing.T) {
	s, err := LoadStore([]byte(file(
		`{"query": {"kind": "checkout.executed", "input_path": ".github/workflows/ci.yml", "step": "jobs.build.steps[0]"}, "state": "found", "value": false}`,
		`{"query": {"kind": "repo.environment-protected", "environment": "Prod"}, "state": "found", "value": true}`,
	)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	path, _ := ParseInputPath(".github/workflows/ci.yml")
	step, _ := WorkflowStep("build", 0)
	if a := (CheckoutExecuted{InputPath: path, Step: step}).Ask(ctx, s); a.State != StateFound || a.Value {
		t.Errorf("checkout.executed = %+v, want false", a)
	}
	env, _ := ParseEnvironmentName("prod")
	if a := (RepoEnvironmentProtected{Environment: env}).Ask(ctx, s); a.State != StateFound || !a.Value {
		t.Errorf("repo.environment-protected = %+v, want true (the name compared without case)", a)
	}
	for _, src := range []string{
		file(`{"query": {"kind": "checkout.executed", "input_path": ".github/workflows/ci.yml", "step": "steps[0]"}, "state": "absent"}`),
		file(`{"query": {"kind": "checkout.executed", "input_path": "../ci.yml", "step": "runs.steps[0]"}, "state": "absent"}`),
		file(`{"query": {"kind": "repo.environment-protected", "environment": ""}, "state": "absent"}`),
	} {
		if _, err := LoadStore([]byte(src)); err == nil {
			t.Errorf("LoadStore(%s): no error", src)
		}
	}
}

func TestLoadStoreRejectsOldNames(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"state resolved", `{"schema":"sisakulint/facts/v0","facts":[{"query":{"kind":"git.ref-commit","repo":"actions/checkout","ref":"v4"},"state" : "resolved","value":{"ref":"refs/tags/v4","sha":"11d5960a326750d5838078e36cf38b85af677262"}}]}`, "/facts/0/state"},
		{"source api", `{"schema":"sisakulint/facts/v0","facts":[{"query":{"kind":"git.ref-commit","repo":"actions/checkout","ref":"v4"},"state":"found","source":"api","value":{"ref":"refs/tags/v4","sha":"11d5960a326750d5838078e36cf38b85af677262"}}]}`, "source"},
		{"assumed", `{"schema":"sisakulint/facts/v0","facts":[{"query":{"kind":"git.ref-commit","repo":"actions/checkout","ref":"v4"},"state":"found","assumed":true,"value":{"ref":"refs/tags/v4","sha":"11d5960a326750d5838078e36cf38b85af677262"}}]}`, "assumed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadStore([]byte(c.body))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("LoadStore = %v, want an error naming %q", err, c.want)
			}
		})
	}
}

func TestStoreEntries(t *testing.T) {
	file := `{"schema":"sisakulint/facts/v0","facts":[
{"query":{"kind":"repo.public"},"state":"found","value":true},
{"query":{"kind":"git.commit-ref","repo":"actions/checkout","sha":"70379aad1a8b40919ce8b382d3cd7d0315cde1d0"},"state":"absent"}
]}`
	s, err := LoadStore([]byte(file))
	if err != nil {
		t.Fatal(err)
	}
	es := s.Entries()
	if len(es) != 2 {
		t.Fatalf("%d entries", len(es))
	}
	b, err := EncodeFile(es)
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadStore(b)
	if err != nil || !reflect.DeepEqual(again.Entries(), es) {
		t.Errorf("not the same entries again: %v\n%s", err, b)
	}
	for _, e := range es {
		if e.RawAnswer.Source != SourceUnset {
			t.Errorf("%v has the source %v: where the store read it is no answer's source", e.Query, e.RawAnswer.Source)
		}
	}
	k0, _ := EncodeQuery(es[0].Query)
	k1, _ := EncodeQuery(es[1].Query)
	if bytes.Compare(k0, k1) >= 0 {
		t.Errorf("not in the order of their queries: %s, %s", k0, k1)
	}
}

// TestStoreAdvisories: the facts of known-vulnerable-actions in a file of
// facts, read as their Go types and written again as they were: the
// members of a value in the order of their names, and a range with its <
// and >.
func TestStoreAdvisories(t *testing.T) {
	file := "{\"schema\":\"sisakulint/facts/v0\",\"facts\":[\n" +
		`{"query":{"kind":"git.commit-tags","repo":"actions/download-artifact","sha":"eaceaf801fd36c7dee90939fad912460b18a1ffe"},"state":"found","value":["refs/tags/v4.1.2"]},` + "\n" +
		`{"query":{"kind":"package.advisories","package":"actions/checkout"},"state":"found","value":[]},` + "\n" +
		`{"query":{"kind":"package.advisories","package":"actions/download-artifact","version":"v4.1.2"},"state":"found","value":[{"first_patched_version":"4.1.3","ghsa_id":"GHSA-cxww-7g56-2vh6","severity":"high","vulnerable_version_range":">= 4.0.0, < 4.1.3"}]}` + "\n]}\n"
	s, err := LoadStore([]byte(file))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sha, _ := ParseSHA("eaceaf801fd36c7dee90939fad912460b18a1ffe")
	tags := GitCommitTags{Repo: mustRepo(t, "Actions/Download-Artifact"), SHA: sha}.Ask(ctx, s)
	if tags.State != StateFound || len(tags.Value) != 1 || tags.Value[0].String() != "refs/tags/v4.1.2" {
		t.Errorf("%+v", tags)
	}
	pkg, _ := ParsePackageName("Actions/Download-Artifact")
	ver, _ := ParsePackageVersion("v4.1.2")
	adv := PackageAdvisories{Package: pkg, Version: ver}.Ask(ctx, s)
	if adv.State != StateFound || len(adv.Value) != 1 || adv.Value[0].GHSAID.String() != "GHSA-cxww-7g56-2vh6" || adv.Value[0].Severity != AdvisorySeverityHigh {
		t.Errorf("%+v", adv)
	}
	checkout, _ := ParsePackageName("actions/checkout")
	if a := (PackageAdvisories{Package: checkout}.Ask(ctx, s)); a.State != StateFound || a.Value == nil || len(a.Value) != 0 {
		t.Errorf("an empty list is found and empty: %+v", a)
	}
	if a := (PackageAdvisories{Package: checkout, Version: ver}.Ask(ctx, s)); a.State != StateUnknown {
		t.Errorf("with a version, another fact: %+v", a)
	}
	b, err := EncodeFile(s.Entries())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != file {
		t.Errorf("EncodeFile =\n%s\nwant\n%s", b, file)
	}
}

func TestStoreUsesTarget(t *testing.T) {
	file := "{\"schema\":\"sisakulint/facts/v0\",\"facts\":[\n" +
		`{"query":{"kind":"action.runs-using","repo":"actions/cache","path":"restore","ref":"v4"},"state":"found","value":"node20"},` + "\n" +
		`{"query":{"kind":"action.runs-using","repo":"actions/create-release","ref":"v1"},"state":"found","value":"node12"},` + "\n" +
		`{"query":{"kind":"action.runs-using","repo":"o/r","ref":"gone"},"state":"absent"},` + "\n" +
		`{"query":{"kind":"repo.archived","repo":"actions/checkout"},"state":"found","value":false},` + "\n" +
		`{"query":{"kind":"repo.archived","repo":"actions/create-release"},"state":"found","value":true}` + "\n]}\n"
	s, err := LoadStore([]byte(file))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	restore, _ := ParseUsesPath("restore")
	if a := (ActionRunsUsing{Repo: mustRepo(t, "Actions/Cache"), Path: restore, Ref: "v4"}.Ask(ctx, s)); a.State != StateFound || a.Value != RunsUsingNode20 {
		t.Errorf("%+v", a)
	}
	if a := (ActionRunsUsing{Repo: mustRepo(t, "actions/cache"), Ref: "v4"}.Ask(ctx, s)); a.State != StateUnknown {
		t.Errorf("without the path, another fact: %+v", a)
	}
	if a := (ActionRunsUsing{Repo: mustRepo(t, "o/r"), Ref: "gone"}.Ask(ctx, s)); a.State != StateAbsent {
		t.Errorf("%+v", a)
	}
	if a := (RepoArchived{Repo: mustRepo(t, "actions/create-release")}.Ask(ctx, s)); a.State != StateFound || !a.Value {
		t.Errorf("%+v", a)
	}
	b, err := EncodeFile(s.Entries())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != file {
		t.Errorf("EncodeFile =\n%s\nwant\n%s", b, file)
	}
	for _, bad := range []string{
		`{"query":{"kind":"action.runs-using","repo":"o/r","ref":"v1"},"state":"found","value":"Node20"}`,
		`{"query":{"kind":"action.runs-using","repo":"o/r","ref":"v1"},"state":"found","value":"node18"}`,
		`{"query":{"kind":"action.runs-using","repo":"o/r","path":"../x","ref":"v1"},"state":"found","value":"node20"}`,
		`{"query":{"kind":"repo.archived"},"state":"found","value":true}`,
	} {
		if _, err := LoadStore([]byte(`{"schema":"sisakulint/facts/v0","facts":[` + bad + `]}`)); err == nil {
			t.Errorf("LoadStore took %s", bad)
		}
	}
}

func TestStoreRepoFile(t *testing.T) {
	file := "{\"schema\":\"sisakulint/facts/v0\",\"facts\":[\n" +
		`{"query":{"kind":"dependabot.version-updates","package_ecosystem":"github-actions","input_path":".github/workflows/ci.yml"},"state":"found","value":true},` + "\n" +
		`{"query":{"kind":"dependabot.version-updates","package_ecosystem":"github-actions","input_path":"a/action.yml"},"state":"unknown","reason":"a glob in directories"},` + "\n" +
		`{"query":{"kind":"renovate.manager-enabled","manager":"github-actions","input_path":".github/workflows/ci.yml"},"state":"found","value":false}` + "\n]}\n"
	s, err := LoadStore([]byte(file))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ci, _ := ParseInputPath(".github/workflows/ci.yml")
	if a := (DependabotVersionUpdates{PackageEcosystem: PackageEcosystemGitHubActions, InputPath: ci}.Ask(ctx, s)); a.State != StateFound || !a.Value {
		t.Errorf("%+v", a)
	}
	if a := (RenovateManagerEnabled{Manager: RenovateManagerGitHubActions, InputPath: ci}.Ask(ctx, s)); a.State != StateFound || a.Value {
		t.Errorf("%+v", a)
	}
	b, err := EncodeFile(s.Entries())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != file {
		t.Errorf("EncodeFile =\n%s\nwant\n%s", b, file)
	}
	for _, bad := range []string{
		`{"query":{"kind":"dependabot.version-updates","package_ecosystem":"npm","input_path":"a.yml"},"state":"found","value":true}`,
		`{"query":{"kind":"renovate.manager-enabled","manager":"npm","input_path":"a.yml"},"state":"found","value":true}`,
		`{"query":{"kind":"renovate.manager-enabled","manager":"github-actions"},"state":"found","value":true}`,
		`{"query":{"kind":"dependabot.version-updates","package_ecosystem":"github-actions","input_path":"a.yml"},"state":"found","value":"yes"}`,
	} {
		if _, err := LoadStore([]byte(`{"schema":"sisakulint/facts/v0","facts":[` + bad + `]}`)); err == nil {
			t.Errorf("LoadStore took %s", bad)
		}
	}
}

// TestLoadStoreSaysTheBranch: the error of an entry that fits no state
// says what each state wants (here found wants a value), and starts as
// every error of reading the file does.
func TestLoadStoreSaysTheBranch(t *testing.T) {
	_, err := LoadStore([]byte(file(`{"query": {"kind": "test.flag", "name": "a"}, "state": "found"}`)))
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"not a file of facts", "entry/oneOf/0/required", "entry/oneOf/1/properties/state/const", "entry/oneOf/2/"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}
