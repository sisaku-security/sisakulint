package rules

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// TestUnsetConfigurationVariable: a name of no list, a name of the list in
// another case, a name of the environment's list in a step and in
// run-name, and the condition of what the rule reports.
func TestUnsetConfigurationVariable(t *testing.T) {
	fsys := fstest.MapFS{".github/workflows/w.yml": {Data: []byte(`run-name: ${{ vars.PROD_ONLY }}
on: push
jobs:
  deploy:
    runs-on: x
    environment: prod
    steps:
      - run: ./deploy.sh "${{ vars.deploy_url }}" "${{ vars.PROD_ONLY }}" "${{ vars.MISSING }}"
`)}}
	r := storeOf(t,
		`{"query":{"kind":"repo.configuration-variables"},"state":"found","value":["DEPLOY_URL"]}`,
		`{"query":{"kind":"repo.environment-configuration-variables","environment":"prod"},"state":"found","value":["PROD_ONLY"]}`)
	rep := qualityReportFS(t, UnsetConfigurationVariableID, fsys, r)
	got := map[string]string{}
	for _, f := range rep.QualityFindings {
		if f.Certainty != lint.CertaintyConfirmed {
			t.Errorf("%v: %v, want confirmed", f.Args, f.Certainty)
		}
		b, err := json.Marshal(f.Condition)
		if err != nil {
			t.Fatal(err)
		}
		args, _ := json.Marshal(f.Args)
		got[string(args)] = string(b)
	}
	want := map[string]string{
		`{"kind_id":"unset-configuration-variable.empty-value","name":"PROD_ONLY","expression":"${{ vars.PROD_ONLY }}"}`: `{"all":[{"query":{"kind":"repo.configuration-variables"},"eq":["DEPLOY_URL"]}]}`,
		`{"kind_id":"unset-configuration-variable.empty-value","name":"MISSING","expression":"${{ vars.MISSING }}"}`:     `{"all":[{"query":{"kind":"repo.configuration-variables"},"eq":["DEPLOY_URL"]},{"query":{"kind":"repo.environment-configuration-variables","environment":"prod"},"eq":["PROD_ONLY"]}]}`,
	}
	if len(got) != len(want) {
		t.Errorf("findings %v, want %v", got, want)
	}
	for args, cond := range want {
		if got[args] != cond {
			t.Errorf("%s: condition %s, want %s", args, got[args], cond)
		}
	}
	// without an answer for the environment, the step reports nothing
	// (environment-unknown), and run-name, which reads no environment, still
	// reports
	rep = qualityReportFS(t, UnsetConfigurationVariableID, fsys, storeOf(t, `{"query":{"kind":"repo.configuration-variables"},"state":"found","value":["DEPLOY_URL"]}`))
	if len(rep.QualityFindings) != 1 || !strings.Contains(rep.QualityFindings[0].Args.Detected(), "${{ vars.PROD_ONLY }}") {
		t.Errorf("without the environment: %v", rep.QualityFindings)
	}
}

// TestUnsetConfigurationVariableDefaultRun: the rule runs in a run without
// --rule only when --facts or --fact answers a kind of its facts, not with
// --online alone.
func TestUnsetConfigurationVariableDefaultRun(t *testing.T) {
	all, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		src  lint.FactSources
		runs bool
	}{
		{"no answer", lint.FactSources{}, false},
		{"--online", lint.FactSources{Online: true}, false},
		{"repository level", lint.FactSources{AnsweredKinds: []facts.Kind{facts.KindRepoConfigurationVariables}}, true},
		{"environment level", lint.FactSources{AnsweredKinds: []facts.Kind{facts.KindRepoEnvironmentConfigurationVariables}}, true},
	} {
		reg, err := all.Select(lint.Selection{}, c.src)
		if err != nil {
			t.Fatal(err)
		}
		if skipped := slices.Contains(reg.Skipped(), UnsetConfigurationVariableID); skipped == c.runs {
			t.Errorf("%s: skipped %v, want runs %v", c.name, skipped, c.runs)
		}
	}
}

// TestExpressionUndefinableConfigurationVariable: the names GitHub's API
// refused to create on 2026-11-03, read as a value and compared, and a name
// a level can define.
func TestExpressionUndefinableConfigurationVariable(t *testing.T) {
	fsys := fstest.MapFS{".github/workflows/w.yml": {Data: []byte(`on: push
jobs:
  a:
    if: vars.github_x == ''
    runs-on: x
    steps:
      - run: echo "${{ vars.GITHUB_Y }} ${{ vars.a-b }} ${{ vars['1X'] }} ${{ vars.OK_1 }} ${{ vars.Github_z == 'x' }}"
`)}}
	rep := qualityReportFS(t, ExpressionRuleID, fsys, storeOf(t))
	var names []string
	for _, f := range rep.QualityFindings {
		if a, ok := f.Args.(ExpressionUndefinableConfigurationVariable); ok {
			names = append(names, a.Name)
		}
	}
	slices.Sort(names)
	if want := []string{"1X", "GITHUB_Y", "Github_z", "a-b", "github_x"}; !slices.Equal(names, want) {
		t.Errorf("names %v, want %v", names, want)
	}
}
