package rules

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// artifactFacts answers the facts of the rules of artifacts: whether the
// default token writes, and whether a pinned commit has a commit.
type artifactFacts struct{ writes, contains *bool }

func (a artifactFacts) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	var v *bool
	switch q.(type) {
	case facts.RepoDefaultTokenWrite:
		v = a.writes
	case facts.GitCommitContains:
		v = a.contains
	}
	if v == nil {
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "not in the table"}
	}
	b, _ := json.Marshal(*v)
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}

func artifactJob(perms, steps string) string {
	return "on: push\n" + perms + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" + steps
}

const (
	coV4     = "      - uses: actions/checkout@v4\n"
	upHidden = "      - uses: actions/upload-artifact@v4\n        with: {path: ., include-hidden-files: true}\n"
	stepNext = "      - run: echo next\n"
	writeQ   = `{"query":{"kind":"repo.default-token-write"},"eq":true}`
)

// TestArtipacked: the kinds of artipacked on uploads after a checkout.
func TestArtipacked(t *testing.T) {
	for _, c := range []struct {
		name, perms, steps string
		kind, cond         string // kind "" for none
	}{
		{"github token", "permissions: {contents: write}\n", coV4 + upHidden + stepNext, "artipacked.github-token", ""},
		{"unwritten", "", coV4 + upHidden + stepNext, "artipacked.github-token", writeQ},
		{"read only", "permissions: {contents: read}\n", coV4 + upHidden + stepNext, "", ""},
		{"last step", "permissions: write-all\n", coV4 + upHidden, "artipacked.github-token", ""}, // the ArtiPACKED report: the post steps leave the time
		{"v6", "permissions: write-all\n", "      - uses: actions/checkout@v6\n" + upHidden + stepNext, "", ""},
		{"persist false", "permissions: write-all\n", "      - uses: actions/checkout@v4\n        with: {persist-credentials: false}\n" + upHidden + stepNext, "", ""},
		{"default hidden", "permissions: write-all\n", coV4 + "      - uses: actions/upload-artifact@v4\n        with: {path: .}\n" + stepNext, "", ""},
		{"v3 github token", "permissions: write-all\n", coV4 + "      - uses: actions/upload-artifact@v3.1.3\n        with: {path: .}\n" + stepNext, "", ""},
		{"PAT", "permissions: {contents: read}\n", "      - uses: actions/checkout@v4\n        with: {token: '${{ secrets.PAT }}'}\n" + upHidden, "artipacked.token-input", ""},
		{"PAT v3", "", "      - uses: actions/checkout@v4\n        with: {token: '${{ secrets.PAT }}'}\n      - uses: actions/upload-artifact@v3.1.3\n        with: {path: .}\n", "artipacked.token-input", ""},
		{"pinned checkout", "permissions: write-all\n", "      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n" + upHidden + stepNext, "artipacked.github-token",
			`{"query":{"kind":"git.commit-contains","repo":"actions/checkout","sha":"0123456789abcdef0123456789abcdef01234567","commit":"1af3b93b6815bc44a9784bd300feb67ff0d1eeb3"},"eq":false}`},
		{"auth is not artipacked", "permissions: write-all\n", "      - uses: google-github-actions/auth@v2\n        with: {credentials_json: x}\n      - uses: actions/upload-artifact@v4\n        with: {path: .}\n", "", ""},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{Artipacked}, wfFile(artifactJob(c.perms, c.steps)), artifactFacts{})
		if c.kind == "" {
			if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
				t.Errorf("%s: %+v", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			}
			continue
		}
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
			t.Errorf("%s: %d findings %+v", c.name, len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			continue
		}
		f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
		if f.Args.KindID().String() != c.kind || condJSON(t, f) != c.cond {
			t.Errorf("%s: %s %s; want %s %s", c.name, f.Args.KindID(), condJSON(t, f), c.kind, c.cond)
		}
	}
}

// TestArtifactGapsOwnCredential: each of artipacked and secrets-in-artifacts
// gives the inconclusive places of its own credentials only, and none of a
// step that leaves no credential whatever its inputs are.
func TestArtifactGapsOwnCredential(t *testing.T) {
	upPath := func(with string) string {
		return "      - uses: actions/upload-artifact@v4\n        with: " + with + "\n"
	}
	auth := func(with string) string {
		return "      - uses: google-github-actions/auth@v2\n        with: " + with + "\n"
	}
	for _, c := range []struct {
		name, steps string
		artipacked  []string
		secrets     []string
	}{
		{"checkout input", "      - uses: actions/checkout@v4\n        with: {persist-credentials: '${{ vars.P }}'}\n" + upHidden, []string{"credential-input-unknown"}, nil},
		{"checkout v6 input", "      - uses: actions/checkout@v6\n        with: {persist-credentials: '${{ vars.P }}'}\n" + upHidden, nil, nil},
		{"auth input", auth("{credentials_json: x, create_credentials_file: '${{ vars.C }}'}") + upHidden, nil, []string{"credential-input-unknown"}},
		{"auth input, no credential", auth("{create_credentials_file: '${{ vars.C }}'}") + upHidden, nil, nil},
		{"auth whole with", auth("'${{ fromJSON(vars.A) }}'") + upHidden, nil, []string{"credential-input-unknown"}},
		{"hidden expr after checkout", coV4 + upPath("{path: ., include-hidden-files: '${{ vars.H }}'}"), []string{"upload-input-unknown"}, nil},
		{"path expr after both", coV4 + auth("{credentials_json: x}") + upPath("{path: '${{ vars.X }}', include-hidden-files: true}"), []string{"upload-input-unknown"}, []string{"upload-input-unknown"}},
	} {
		for _, r := range []struct {
			rule lint.Rule
			want []string
		}{{Artipacked, c.artipacked}, {SecretsInArtifacts, c.secrets}} {
			rep, _, _ := checkRules(t, []lint.Rule{r.rule}, wfFile(artifactJob("permissions: write-all\n", c.steps)), artifactFacts{})
			var got []string
			for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
				got = append(got, g.InconclusiveKind.String())
			}
			if !slices.Equal(got, r.want) {
				t.Errorf("%s, %s: %v, want %v", c.name, r.rule.Meta().ID, got, r.want)
			}
		}
	}
}

// TestArtipackedAssumed: unwritten permissions hold on the assumption, are
// conditional without it, and go with the fact false.
func TestArtipackedAssumed(t *testing.T) {
	src := artifactJob("", coV4+upHidden+stepNext)
	rep, _, _ := checkRules(t, []lint.Rule{Artipacked}, wfFile(src), worstCase(artifactFacts{}))
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Certainty != lint.CertaintyConfirmed {
		t.Errorf("assumed: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	rep, _, _ = checkRules(t, []lint.Rule{Artipacked}, wfFile(src), artifactFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Certainty != lint.CertaintyConditional {
		t.Errorf("not known: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	rep, _, _ = checkRules(t, []lint.Rule{Artipacked}, wfFile(src), artifactFacts{writes: ptr(false)})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
		t.Errorf("read default: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestArtipackedFix is the completion condition 5: the fix closes the
// finding, and two uploads of one checkout give one edit.
func TestArtipackedFix(t *testing.T) {
	for _, src := range []string{
		artifactJob("permissions: write-all\n", coV4+upHidden+stepNext),
		artifactJob("permissions: write-all\n", coV4+upHidden+upHidden+stepNext),
	} {
		out := applied(t, Artipacked, src, artifactFacts{}, lint.SafetyReview)
		rep, _, _ := checkRules(t, []lint.Rule{Artipacked}, wfFile(out), artifactFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
			t.Errorf("after the fix:\n%s\n%+v", out, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
		}
	}
}

// textAt is the text of the input at l.
func textAt(t *testing.T, in lint.Inputs, l lint.Location) string {
	t.Helper()
	i, st := in.Lookup(l.File.Input)
	if st != lint.LookupFound {
		t.Fatalf("no input %s", l.File.Input)
	}
	return string(i.Tree.Bytes()[l.Span.Start:l.Span.End])
}

const upPinned = "      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567\n        with: {path: .}\n"

// TestArtipackedOnePerStep: one finding for the step that leaves the
// credential however many uploads take it, at the step, with the first
// upload as its evidence and the number of the others in the note.
func TestArtipackedOnePerStep(t *testing.T) {
	rep, in, _ := checkRules(t, []lint.Rule{Artipacked}, wfFile(artifactJob("permissions: write-all\n", coV4+upHidden+upHidden+upHidden+stepNext)), artifactFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("%d findings", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	if !strings.Contains(textAt(t, in, f.Location), "actions/checkout@v4") || len(f.Evidence) != 1 || len(f.Related) != 0 {
		t.Errorf("at %q, evidence %+v, related %+v", textAt(t, in, f.Location), f.Evidence, f.Related)
	}
	if n := f.Evidence[0].Note; !strings.Contains(n, ".git/config") || !strings.Contains(n, "2 more uploads") {
		t.Errorf("note %q", n)
	}
	if f.Anchor != f.Args.KindID().String() {
		t.Errorf("anchor %q", f.Anchor)
	}
}

// TestArtipackedBothFiles: a checkout at a branch may leave the credential
// in .git/config and in RUNNER_TEMP; an upload that takes both gives one
// finding, not two of one place (which the engine refuses).
func TestArtipackedBothFiles(t *testing.T) {
	up := "      - uses: actions/upload-artifact@v4\n        with:\n          include-hidden-files: true\n          path: |\n            .\n            ${{ runner.temp }}\n"
	rep, _, _ := checkRules(t, []lint.Rule{Artipacked}, wfFile(artifactJob("permissions: write-all\n", "      - uses: actions/checkout@main\n"+up+stepNext)), artifactFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || len(rep.Errors) != 0 {
		t.Fatalf("findings %+v, errors %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.Errors)
	}
	if n := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Evidence[0].Note; !strings.Contains(n, ".git/config") || !strings.Contains(n, "RUNNER_TEMP") {
		t.Errorf("note %q", n)
	}
}

// TestArtipackedFirstCounted: an upload before v4 does not count for the
// job's token, so the evidence and the upload of the args are the v4
// upload after it.
func TestArtipackedFirstCounted(t *testing.T) {
	src := artifactJob("permissions: write-all\n", coV4+"      - uses: actions/upload-artifact@v3.1.3\n        with: {path: .}\n"+upHidden+stepNext)
	rep, in, _ := checkRules(t, []lint.Rule{Artipacked}, wfFile(src), artifactFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("%d findings", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	if a, ok := f.Args.(ArtipackedGitHubToken); !ok || a.Upload != "actions/upload-artifact@v4" || !strings.Contains(textAt(t, in, f.Evidence[0].Location), ".") || strings.Contains(textAt(t, in, f.Evidence[0].Location), "v3") {
		t.Errorf("args %+v, evidence at %q", f.Args, textAt(t, in, f.Evidence[0].Location))
	}
}

// TestArtipackedUnconditionalEvidence: an upload that takes the file on no
// condition makes the finding hold on none, and is the evidence and the
// upload of the args, though an upload on a condition comes first.
func TestArtipackedUnconditionalEvidence(t *testing.T) {
	src := artifactJob("permissions: write-all\n", coV4+upPinned+upHidden+stepNext)
	rep, _, _ := checkRules(t, []lint.Rule{Artipacked}, wfFile(src), artifactFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("%d findings", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	if a, ok := f.Args.(ArtipackedGitHubToken); !ok || a.Upload != "actions/upload-artifact@v4" || condJSON(t, f) != "" {
		t.Errorf("args %+v, condition %s", f.Args, condJSON(t, f))
	}
}

// TestArtipackedConditions: two uploads on conditions of their own give
// the disjunction of the two.
func TestArtipackedConditions(t *testing.T) {
	other := strings.Replace(upPinned, "0123456789abcdef0123456789abcdef01234567", "89abcdef0123456789abcdef0123456789abcdef", 1)
	rep, _, _ := checkRules(t, []lint.Rule{Artipacked}, wfFile(artifactJob("permissions: write-all\n", coV4+upPinned+other+stepNext)), artifactFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("%d findings", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	if c := condJSON(t, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]); !strings.Contains(c, `"any"`) || !strings.Contains(c, "0123456789abcdef0123456789abcdef01234567") || !strings.Contains(c, "89abcdef0123456789abcdef0123456789abcdef") {
		t.Errorf("condition %s", c)
	}
}

// TestArtipackedTwoSteps: two checkouts that one upload takes are two
// findings, and their fixes close both.
func TestArtipackedTwoSteps(t *testing.T) {
	src := artifactJob("permissions: write-all\n", "      - uses: actions/checkout@v4\n        with: {path: a}\n      - uses: actions/checkout@v4\n        with: {path: b}\n"+upHidden+upHidden+stepNext)
	rep, _, _ := checkRules(t, []lint.Rule{Artipacked}, wfFile(src), artifactFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 2 {
		t.Fatalf("%d findings", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Fix == nil {
			t.Errorf("no fix: %+v", f.NoFix)
		}
	}
	out := applied(t, Artipacked, src, artifactFacts{}, lint.SafetyReview)
	if rep, _, _ := checkRules(t, []lint.Rule{Artipacked}, wfFile(out), artifactFacts{}); len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
		t.Errorf("after the fix:\n%s\n%+v", out, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestArtifactMixedTakes: one upload takes the file of a checkout's token
// only as a hidden file (on the condition of its release) and the file of
// google-github-actions/auth on none; the condition goes with the first only.
func TestArtifactMixedTakes(t *testing.T) {
	src := artifactJob("permissions: write-all\n", "      - uses: actions/checkout@v4\n        with: {token: '${{ secrets.PAT }}'}\n      - uses: google-github-actions/auth@v2\n        with: {credentials_json: x}\n"+upPinned)
	rep, _, _ := checkRules(t, []lint.Rule{Artipacked, SecretsInArtifacts}, wfFile(src), artifactFacts{})
	got := map[string]string{}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		got[f.Rule.String()] = condJSON(t, f)
	}
	if len(got) != 2 || got["artipacked"] == "" || got["secrets-in-artifacts"] != "" {
		t.Errorf("%v", got)
	}
}

// TestArtipackedUnwrittenEvidence: in a job that writes no permissions,
// the condition of the default token is the job's, not the upload's: the
// upload that takes the file on no other condition is still the evidence
// and the upload of the args, and the condition is the default token's
// alone.
func TestArtipackedUnwrittenEvidence(t *testing.T) {
	src := artifactJob("", coV4+upPinned+upHidden+stepNext)
	rep, _, _ := checkRules(t, []lint.Rule{Artipacked}, wfFile(src), artifactFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("%d findings", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	if a, ok := f.Args.(ArtipackedGitHubToken); !ok || a.Upload != "actions/upload-artifact@v4" || condJSON(t, f) != writeQ {
		t.Errorf("args %+v, condition %s", f.Args, condJSON(t, f))
	}
	if at, v4 := f.Evidence[0].Location.Span.Start, strings.Index(src, "upload-artifact@v4"); at < v4 {
		t.Errorf("evidence at %d, before the v4 upload at %d", at, v4)
	}
}

// TestArtipackedNoteFiles: the note names the files the upload of the
// evidence takes, not those other uploads take.
func TestArtipackedNoteFiles(t *testing.T) {
	temp := "      - uses: actions/upload-artifact@v4\n        with:\n          path: ${{ runner.temp }}\n"
	rep, _, _ := checkRules(t, []lint.Rule{Artipacked}, wfFile(artifactJob("permissions: write-all\n", "      - uses: actions/checkout@main\n"+upHidden+temp+stepNext)), artifactFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("%d findings", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	if n := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Evidence[0].Note; !strings.Contains(n, ".git/config") || strings.Contains(n, "RUNNER_TEMP") || !strings.Contains(n, "1 more upload") {
		t.Errorf("note %q", n)
	}
}
