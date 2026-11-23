package rules

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// listFacts answers repo.action-list with the patterns.
func listFacts(t *testing.T, patterns ...string) facts.Resolver {
	t.Helper()
	var quoted []string
	for _, p := range patterns {
		quoted = append(quoted, `"`+p+`"`)
	}
	return storeOf(t, `{"query":{"kind":"repo.action-list"},"state":"found","value":[`+strings.Join(quoted, ",")+`]}`)
}

// actionListFindings runs action-list on files and gives each finding as
// its input, its kind and its uses, sorted; each must be confirmed.
func actionListFindings(t *testing.T, files map[string]string, r facts.Resolver) []string {
	t.Helper()
	rep, _, _ := checkRules(t, []lint.Rule{ActionList}, files, r)
	var out []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Certainty != lint.CertaintyConfirmed {
			t.Errorf("%s: %v", f.Detected(), f.Certainty)
		}
		uses := ""
		switch a := f.Args.(type) {
		case ActionListUnlisted:
			uses = a.Uses
		case ActionListUnlistedImage:
			uses = a.Uses
		case ActionListUnlistedService:
			uses = a.Uses
		}
		out = append(out, f.Location.File.Input.String()+" "+f.Args.KindID().String()+" "+uses)
	}
	slices.Sort(out)
	return out
}

func TestActionListUnlisted(t *testing.T) {
	files := map[string]string{
		".github/workflows/w.yml": `on: push
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/checkout@v4
      - uses: Actions/Checkout@v4
      - uses: actions/setup-go@v5
      - uses: ./local
      - uses: $/local
  b:
    uses: o/r/.github/workflows/w.yml@v1
`,
		"local/action.yml": "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - uses: x/y@v1\n    - uses: actions/checkout@v4\n",
	}
	got := actionListFindings(t, files, listFacts(t, "actions/checkout@*"))
	want := []string{
		".github/workflows/w.yml action-list.unlisted actions/setup-go@v5",
		".github/workflows/w.yml action-list.unlisted o/r/.github/workflows/w.yml@v1",
		"local/action.yml action-list.unlisted x/y@v1",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestActionListNormalized: the rule matches the uses as GitHub reads it,
// so empty parts and . do not take a uses past a pattern with !.
func TestActionListNormalized(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: evil//act@v1\n      - uses: evil/act/.@v1\n      - uses: good/act@v1\n"
	got := actionListFindings(t, wfFile(src), listFacts(t, "*", "!evil/act@*"))
	want := []string{
		".github/workflows/w.yml action-list.unlisted evil//act@v1",
		".github/workflows/w.yml action-list.unlisted evil/act/.@v1",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestActionListImage: the image of a docker:// step, of the container of
// a job and of a service, compared as docker:// and the image; a matrix
// value of the container is read value by value.
func TestActionListImage(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    container: node:20\n    services:\n      redis:\n        image: redis:7\n    steps:\n      - uses: docker://alpine:3.20\n  m:\n    strategy:\n      matrix:\n        img: [busybox:1.36, alpine:3.20]\n    runs-on: x\n    container: ${{ matrix.img }}\n    steps:\n      - run: make\n"
	got := actionListFindings(t, wfFile(src), listFacts(t, "actions/checkout@*"))
	want := []string{
		".github/workflows/w.yml action-list.unlisted-image docker://alpine:3.20",
		".github/workflows/w.yml action-list.unlisted-image docker://alpine:3.20",
		".github/workflows/w.yml action-list.unlisted-image docker://busybox:1.36",
		".github/workflows/w.yml action-list.unlisted-image docker://node:20",
		".github/workflows/w.yml action-list.unlisted-service docker://redis:7",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := actionListFindings(t, wfFile(src), listFacts(t, "docker://alpine:*", "docker://node:*", "docker://redis:*", "docker://busybox:*")); len(got) != 0 {
		t.Errorf("patterns of the images: %q", got)
	}
}

// TestActionListSharedMatrixImage: the container and two services that
// name the same value of the matrix get a finding each (the anchor of a
// service tells the findings at that value apart).
func TestActionListSharedMatrixImage(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    strategy:\n      matrix:\n        img: [busybox:1.36]\n    runs-on: x\n    container: ${{ matrix.img }}\n    services:\n      s1:\n        image: ${{ matrix.img }}\n      s2:\n        image: ${{ matrix.img }}\n    steps:\n      - run: make\n"
	got := actionListFindings(t, wfFile(src), listFacts(t, "actions/*"))
	want := []string{
		".github/workflows/w.yml action-list.unlisted-image docker://busybox:1.36",
		".github/workflows/w.yml action-list.unlisted-service docker://busybox:1.36",
		".github/workflows/w.yml action-list.unlisted-service docker://busybox:1.36",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestActionListNoList: with no answer of repo.action-list, or an answer of
// absent, the rule reports nothing (list-unknown).
func TestActionListNoList(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/setup-go@v5\n"
	for name, r := range map[string]facts.Resolver{
		"no answer": storeOf(t),
		"absent":    storeOf(t, `{"query":{"kind":"repo.action-list"},"state":"absent"}`),
	} {
		if got := actionListFindings(t, wfFile(src), r); len(got) != 0 {
			t.Errorf("%s: %q", name, got)
		}
	}
}

// TestActionListCondition: the condition of a finding is repo.action-list
// equal to the list, as written, so that the list of the report confirms
// it.
func TestActionListCondition(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/setup-go@v5\n"
	rep, _, _ := checkRules(t, []lint.Rule{ActionList}, wfFile(src), listFacts(t, "Actions/Checkout@*", "!evil/act@*"))
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("%d findings", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	if f.Certainty != lint.CertaintyConfirmed {
		t.Errorf("certainty %v, want confirmed", f.Certainty)
	}
	qs := f.Condition.Queries()
	if len(qs) != 1 || qs[0] != facts.Query(facts.RepoActionList{}) {
		t.Errorf("asks %#v", qs)
	}
	b, err := f.Condition.MarshalJSON()
	if err != nil || !strings.Contains(string(b), `["Actions/Checkout@*","!evil/act@*"]`) {
		t.Errorf("condition %s, %v", b, err)
	}
}

// TestActionListOutside: a uses whose path goes above the root of its
// repository is matched by the readings of the action that runs, and one
// above the directory of actions is not matched (outside-actions-directory).
func TestActionListOutside(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: gradle/actions/../../docker/x@v1\n      - uses: o/r/../../../../x@v1\n"
	got := actionListFindings(t, wfFile(src), listFacts(t, "gradle/actions@*"))
	if want := []string{".github/workflows/w.yml action-list.unlisted gradle/actions/../../docker/x@v1"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := actionListFindings(t, wfFile(src), listFacts(t, "gradle/docker@*")); len(got) != 0 {
		t.Errorf("the reading listed: %q", got)
	}
}

// TestActionListRemoteComposite: a uses inside a composite action of
// another repository that action.definition answers is reported at the
// uses of the workflow, with the evidence in the file of the fact.
func TestActionListRemoteComposite(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: example-org/node-composite@v1\n"
	def := `{"commit":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","file":"action.yml","content":"runs:\n  using: composite\n  steps:\n    - uses: other/inner@v2\n    - uses: docker://alpine:3\n","archive_substituted":false}`
	r := storeOf(t,
		`{"query":{"kind":"repo.action-list"},"state":"found","value":["example-org/*"]}`,
		`{"query":{"kind":"action.definition","repo":"example-org/node-composite","ref":"v1"},"state":"found","value":`+def+`}`)
	rep, _, _ := checkRules(t, []lint.Rule{ActionList}, wfFile(src), r)
	var got []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		inFact := slices.ContainsFunc(f.Evidence, func(e lint.Related) bool { return e.Location.File.Query != nil })
		got = append(got, f.Args.KindID().String()+" "+f.Detected()[:strings.Index(f.Detected(), " ")]+" "+map[bool]string{true: "in-fact", false: "no-evidence"}[inFact])
	}
	slices.Sort(got)
	want := []string{"action-list.unlisted other/inner@v2 in-fact", "action-list.unlisted-image docker://alpine:3 in-fact"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestActionListRemoteCalled: the steps of a reusable workflow of another
// repository that workflow.definition answers, a docker:// step and a uses
// whose path goes above the root of its repository among them, and a job
// of that workflow that calls another reusable workflow, are reported at
// the uses of the calling job.
func TestActionListRemoteCalled(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    uses: ok-org/wf/.github/workflows/w.yml@v1\n"
	called := "on: workflow_call\njobs:\n  b:\n    runs-on: x\n    steps:\n      - uses: docker://evil/image:1\n      - uses: bad/act@v1\n      - uses: gradle/actions/../../evil/x@v1\n      - uses: ok-org/fine@v1\n  c:\n    uses: bad/wf/.github/workflows/x.yml@v2\n"
	def := `{"commit":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","content":` + strconv.Quote(called) + `}`
	r := storeOf(t,
		`{"query":{"kind":"repo.action-list"},"state":"found","value":["ok-org/*","gradle/actions@*"]}`,
		`{"query":{"kind":"workflow.definition","repo":"ok-org/wf","path":".github/workflows/w.yml","ref":"v1"},"state":"found","value":`+def+`}`)
	got := actionListFindings(t, wfFile(src), r)
	want := []string{
		".github/workflows/w.yml action-list.unlisted bad/act@v1",
		".github/workflows/w.yml action-list.unlisted bad/wf/.github/workflows/x.yml@v2",
		".github/workflows/w.yml action-list.unlisted gradle/actions/../../evil/x@v1",
		".github/workflows/w.yml action-list.unlisted-image docker://evil/image:1",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestActionListRemoteDockerAction: the runs.image of a Docker container
// action of another repository that action.definition answers is reported
// at the uses of the step.
func TestActionListRemoteDockerAction(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: ok-org/scan@v1\n"
	def := `{"commit":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","file":"action.yml","content":"runs:\n  using: docker\n  image: docker://evil/image:1\n","archive_substituted":false}`
	r := storeOf(t,
		`{"query":{"kind":"repo.action-list"},"state":"found","value":["ok-org/*"]}`,
		`{"query":{"kind":"action.definition","repo":"ok-org/scan","ref":"v1"},"state":"found","value":`+def+`}`)
	got := actionListFindings(t, wfFile(src), r)
	if want := []string{".github/workflows/w.yml action-list.unlisted-image docker://evil/image:1"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
