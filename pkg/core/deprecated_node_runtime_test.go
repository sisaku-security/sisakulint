package core

import (
	"errors"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

func nodeRuntimeTestStep(uses string, lineComment string) *ast.Step {
	return &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{
				Value: uses,
				Pos:   &ast.Position{Line: 1, Col: 1},
				BaseNode: &yaml.Node{
					Kind:        yaml.ScalarNode,
					Value:       uses,
					LineComment: lineComment,
				},
			},
		},
		Pos: &ast.Position{Line: 1, Col: 1},
	}
}

type fakeMetadataResolver struct {
	meta map[string]*ActionMetadata
	err  error
}

func (r *fakeMetadataResolver) FindMetadata(spec string) (*ActionMetadata, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.meta[spec], nil
}

func TestNewDeprecatedNodeRuntimeRule(t *testing.T) {
	rule := NewDeprecatedNodeRuntimeRule(nil)
	if rule.RuleName != "deprecated-node-runtime" {
		t.Errorf("expected RuleName 'deprecated-node-runtime', got %q", rule.RuleName)
	}
}

func TestParseMajorFromRef(t *testing.T) {
	tests := []struct {
		ref   string
		major int
		ok    bool
	}{
		{"v4", 4, true},
		{"v4.1.2", 4, true},
		{"v10", 10, true},
		{"main", 0, false},
		{"a81bbbf8298c0fa03ea29cdc473d45769f953675", 0, false},
		{"", 0, false},
		{"4", 0, false},
	}
	for _, tt := range tests {
		major, ok := parseMajorFromRef(tt.ref)
		if major != tt.major || ok != tt.ok {
			t.Errorf("parseMajorFromRef(%q) = (%d, %v), want (%d, %v)", tt.ref, major, ok, tt.major, tt.ok)
		}
	}
}

func TestDeprecatedNodeRuntimeKnownActions(t *testing.T) {
	tests := []struct {
		name       string
		uses       string
		comment    string
		wantErrors int
		wantFixers int
	}{
		{"checkout v4 is node20", "actions/checkout@v4", "", 1, 1},
		{"checkout v4 full semver", "actions/checkout@v4.2.2", "", 1, 1},
		{"checkout v5 is node24", "actions/checkout@v5", "", 0, 0},
		{"github-script v7 is node20", "actions/github-script@v7", "", 1, 1},
		{"github-script v8 is node24", "actions/github-script@v8", "", 0, 0},
		{"download-artifact v6 is node20", "actions/download-artifact@v6", "", 1, 1},
		{"upload-artifact v5 gap major is node20", "actions/upload-artifact@v5", "", 1, 1},
		{"upload-artifact v6 is node24", "actions/upload-artifact@v6", "", 0, 0},
		{"sha pinned with tag comment detected but not fixed", "actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675", "# v4.1.1", 1, 0},
		{"sha pinned without comment falls through silently", "actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675", "", 0, 0},
		{"unknown action is not matched", "someorg/someaction@v1", "", 0, 0},
		{"branch ref is not matched", "actions/checkout@main", "", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewDeprecatedNodeRuntimeRule(nil)
			step := nodeRuntimeTestStep(tt.uses, tt.comment)
			if err := rule.VisitStep(step); err != nil {
				t.Fatalf("VisitStep returned error: %v", err)
			}
			if got := len(rule.Errors()); got != tt.wantErrors {
				t.Errorf("expected %d errors, got %d: %v", tt.wantErrors, got, rule.Errors())
			}
			if got := len(rule.AutoFixers()); got != tt.wantFixers {
				t.Errorf("expected %d autofixers, got %d", tt.wantFixers, got)
			}
		})
	}
}

func TestDeprecatedNodeRuntimeResolver(t *testing.T) {
	tests := []struct {
		name       string
		uses       string
		meta       *ActionMetadata
		resolveErr error
		wantErrors int
	}{
		{
			name:       "resolved node20 runtime is reported",
			uses:       "someorg/node20-action@v1",
			meta:       &ActionMetadata{Runs: &ActionRunsMetadata{Using: "node20"}},
			wantErrors: 1,
		},
		{
			name:       "resolved node16 runtime is reported",
			uses:       "someorg/node16-action@v1",
			meta:       &ActionMetadata{Runs: &ActionRunsMetadata{Using: "node16"}},
			wantErrors: 1,
		},
		{
			name:       "resolved node24 runtime is fine",
			uses:       "someorg/node24-action@v1",
			meta:       &ActionMetadata{Runs: &ActionRunsMetadata{Using: "node24"}},
			wantErrors: 0,
		},
		{
			name:       "composite action is fine",
			uses:       "someorg/composite-action@v1",
			meta:       &ActionMetadata{Runs: &ActionRunsMetadata{Using: "composite"}},
			wantErrors: 0,
		},
		{
			name:       "resolver failure is skipped silently",
			uses:       "someorg/unreachable@v1",
			resolveErr: errors.New("network down"),
			wantErrors: 0,
		},
		{
			name:       "local action resolved to node20 is reported",
			uses:       "./local-node20-action",
			meta:       &ActionMetadata{Runs: &ActionRunsMetadata{Using: "node20"}},
			wantErrors: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &fakeMetadataResolver{
				meta: map[string]*ActionMetadata{tt.uses: tt.meta},
				err:  tt.resolveErr,
			}
			rule := NewDeprecatedNodeRuntimeRule(resolver)
			step := nodeRuntimeTestStep(tt.uses, "")
			if err := rule.VisitStep(step); err != nil {
				t.Fatalf("VisitStep returned error: %v", err)
			}
			if got := len(rule.Errors()); got != tt.wantErrors {
				t.Errorf("expected %d errors, got %d: %v", tt.wantErrors, got, rule.Errors())
			}
		})
	}
}

// TestDeprecatedNodeRuntimeResolverFirst verifies that the resolved
// action.yml wins over the embedded-table/comment heuristic, so a stale
// version comment next to a SHA pin cannot flip the verdict either way.
func TestDeprecatedNodeRuntimeResolverFirst(t *testing.T) {
	sha := "a309ff8b426b58ec0e2a45f0f869d46889d02405"

	t.Run("stale node20 comment on node24 SHA is not flagged", func(t *testing.T) {
		uses := "actions/setup-python@" + sha
		resolver := &fakeMetadataResolver{meta: map[string]*ActionMetadata{
			uses: {Runs: &ActionRunsMetadata{Using: "node24"}},
		}}
		rule := NewDeprecatedNodeRuntimeRule(resolver)
		step := nodeRuntimeTestStep(uses, "# v5")
		if err := rule.VisitStep(step); err != nil {
			t.Fatal(err)
		}
		if len(rule.Errors()) != 0 {
			t.Errorf("expected 0 errors, got %d: %v", len(rule.Errors()), rule.Errors())
		}
	})

	t.Run("stale node24 comment on node20 SHA is flagged via resolver", func(t *testing.T) {
		uses := "actions/setup-python@" + sha
		resolver := &fakeMetadataResolver{meta: map[string]*ActionMetadata{
			uses: {Runs: &ActionRunsMetadata{Using: "node20"}},
		}}
		rule := NewDeprecatedNodeRuntimeRule(resolver)
		step := nodeRuntimeTestStep(uses, "# v6.2.0")
		if err := rule.VisitStep(step); err != nil {
			t.Fatal(err)
		}
		if len(rule.Errors()) != 1 {
			t.Errorf("expected 1 error, got %d: %v", len(rule.Errors()), rule.Errors())
		}
		if len(rule.AutoFixers()) != 0 {
			t.Errorf("SHA-pinned ref must not be auto-fixed, got %d fixers", len(rule.AutoFixers()))
		}
	})

	t.Run("resolver-confirmed node20 tag of known action gets autofixer", func(t *testing.T) {
		uses := "actions/checkout@v4"
		resolver := &fakeMetadataResolver{meta: map[string]*ActionMetadata{
			uses: {Runs: &ActionRunsMetadata{Using: "node20"}},
		}}
		rule := NewDeprecatedNodeRuntimeRule(resolver)
		step := nodeRuntimeTestStep(uses, "")
		if err := rule.VisitStep(step); err != nil {
			t.Fatal(err)
		}
		if len(rule.Errors()) != 1 || len(rule.AutoFixers()) != 1 {
			t.Errorf("expected 1 error and 1 fixer, got %d/%d", len(rule.Errors()), len(rule.AutoFixers()))
		}
	})
}

func TestDeprecatedNodeRuntimeCompositeTransitive(t *testing.T) {
	parent := "codecov/codecov-action@v5"

	t.Run("composite with node20 internal step is reported", func(t *testing.T) {
		resolver := &fakeMetadataResolver{meta: map[string]*ActionMetadata{
			parent: {Runs: &ActionRunsMetadata{Using: "composite", Steps: []*ActionStepMetadata{
				{Uses: "actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea"},
			}}},
			"actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea": {Runs: &ActionRunsMetadata{Using: "node20"}},
		}}
		rule := NewDeprecatedNodeRuntimeRule(resolver)
		step := nodeRuntimeTestStep(parent, "")
		if err := rule.VisitStep(step); err != nil {
			t.Fatal(err)
		}
		if len(rule.Errors()) != 1 {
			t.Fatalf("expected 1 error, got %d: %v", len(rule.Errors()), rule.Errors())
		}
		if len(rule.AutoFixers()) != 0 {
			t.Errorf("transitive findings must be diagnose-only, got %d fixers", len(rule.AutoFixers()))
		}
	})

	t.Run("composite-relative uses resolves within parent repo at same ref", func(t *testing.T) {
		p := "actions/attest-build-provenance@v2"
		resolver := &fakeMetadataResolver{meta: map[string]*ActionMetadata{
			p: {Runs: &ActionRunsMetadata{Using: "composite", Steps: []*ActionStepMetadata{
				{Uses: "./predicate"},
			}}},
			"actions/attest-build-provenance/predicate@v2": {Runs: &ActionRunsMetadata{Using: "node20"}},
		}}
		rule := NewDeprecatedNodeRuntimeRule(resolver)
		step := nodeRuntimeTestStep(p, "")
		if err := rule.VisitStep(step); err != nil {
			t.Fatal(err)
		}
		if len(rule.Errors()) != 1 {
			t.Errorf("expected 1 error, got %d: %v", len(rule.Errors()), rule.Errors())
		}
	})

	t.Run("nested composite is not followed beyond depth 1", func(t *testing.T) {
		resolver := &fakeMetadataResolver{meta: map[string]*ActionMetadata{
			parent: {Runs: &ActionRunsMetadata{Using: "composite", Steps: []*ActionStepMetadata{
				{Uses: "someorg/inner-composite@v1"},
			}}},
			"someorg/inner-composite@v1": {Runs: &ActionRunsMetadata{Using: "composite", Steps: []*ActionStepMetadata{
				{Uses: "someorg/deep-node20@v1"},
			}}},
			"someorg/deep-node20@v1": {Runs: &ActionRunsMetadata{Using: "node20"}},
		}}
		rule := NewDeprecatedNodeRuntimeRule(resolver)
		step := nodeRuntimeTestStep(parent, "")
		if err := rule.VisitStep(step); err != nil {
			t.Fatal(err)
		}
		if len(rule.Errors()) != 0 {
			t.Errorf("depth-1 only: expected 0 errors, got %d: %v", len(rule.Errors()), rule.Errors())
		}
	})

	t.Run("composite with healthy internals is silent", func(t *testing.T) {
		resolver := &fakeMetadataResolver{meta: map[string]*ActionMetadata{
			parent: {Runs: &ActionRunsMetadata{Using: "composite", Steps: []*ActionStepMetadata{
				{Uses: "actions/checkout@v5"},
				{Uses: "docker://alpine:3"},
			}}},
			"actions/checkout@v5": {Runs: &ActionRunsMetadata{Using: "node24"}},
		}}
		rule := NewDeprecatedNodeRuntimeRule(resolver)
		step := nodeRuntimeTestStep(parent, "")
		if err := rule.VisitStep(step); err != nil {
			t.Fatal(err)
		}
		if len(rule.Errors()) != 0 {
			t.Errorf("expected 0 errors, got %d: %v", len(rule.Errors()), rule.Errors())
		}
	})
}

func TestResolveCompositeLocalSpec(t *testing.T) {
	tests := []struct {
		parent string
		rel    string
		want   string
	}{
		{"actions/attest-build-provenance@v2", "./predicate", "actions/attest-build-provenance/predicate@v2"},
		{"owner/repo/sub@v1", "./inner", "owner/repo/sub/inner@v1"},
		{"owner/repo@v1", "../../evil", ""},
		{"owner/repo@v1", "./", "owner/repo@v1"},
		{"malformed", "./x", ""},
	}
	for _, tt := range tests {
		if got := resolveCompositeLocalSpec(tt.parent, tt.rel); got != tt.want {
			t.Errorf("resolveCompositeLocalSpec(%q, %q) = %q, want %q", tt.parent, tt.rel, got, tt.want)
		}
	}
}

func TestDeprecatedNodeRuntimeEnvFlags(t *testing.T) {
	env := func(name string) *ast.Env {
		return &ast.Env{Vars: map[string]*ast.EnvVar{
			name: {
				Name:  &ast.String{Value: name, Pos: &ast.Position{Line: 2, Col: 3}},
				Value: &ast.String{Value: "true", Pos: &ast.Position{Line: 2, Col: 10}},
			},
		}}
	}

	t.Run("unsecure opt-out on workflow env", func(t *testing.T) {
		rule := NewDeprecatedNodeRuntimeRule(nil)
		wf := &ast.Workflow{Env: env("ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION")}
		if err := rule.VisitWorkflowPre(wf); err != nil {
			t.Fatal(err)
		}
		if len(rule.Errors()) != 1 {
			t.Errorf("expected 1 error, got %d", len(rule.Errors()))
		}
	})

	t.Run("dead node20 force flag on job env", func(t *testing.T) {
		rule := NewDeprecatedNodeRuntimeRule(nil)
		job := &ast.Job{Env: env("FORCE_JAVASCRIPT_ACTIONS_TO_NODE20")}
		if err := rule.VisitJobPre(job); err != nil {
			t.Fatal(err)
		}
		if len(rule.Errors()) != 1 {
			t.Errorf("expected 1 error, got %d", len(rule.Errors()))
		}
	})

	t.Run("node24 force flag is not flagged", func(t *testing.T) {
		rule := NewDeprecatedNodeRuntimeRule(nil)
		wf := &ast.Workflow{Env: env("FORCE_JAVASCRIPT_ACTIONS_TO_NODE24")}
		if err := rule.VisitWorkflowPre(wf); err != nil {
			t.Fatal(err)
		}
		if len(rule.Errors()) != 0 {
			t.Errorf("expected 0 errors, got %d: %v", len(rule.Errors()), rule.Errors())
		}
	})
}

func TestDeprecatedNodeRuntimeEOLBuildTarget(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		wantErrors int
	}{
		{"node 20 is EOL", "20", 1},
		{"node 20.x is EOL", "20.11.1", 1},
		{"node 18 is EOL", "18", 1},
		{"node 22 is supported", "22", 0},
		{"node 24 is supported", "24", 0},
		{"expression is skipped", "${{ matrix.node }}", 0},
		{"non-numeric is skipped", "lts/*", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewDeprecatedNodeRuntimeRule(nil)
			// v6 of setup-node is node24-capable, so only the build target check fires.
			step := nodeRuntimeTestStep("actions/setup-node@v6", "")
			action := step.Exec.(*ast.ExecAction)
			action.Inputs = map[string]*ast.Input{
				"node-version": {
					Name:  &ast.String{Value: "node-version", Pos: &ast.Position{Line: 3, Col: 5}},
					Value: &ast.String{Value: tt.version, Pos: &ast.Position{Line: 3, Col: 20}},
				},
			}
			if err := rule.VisitStep(step); err != nil {
				t.Fatal(err)
			}
			if got := len(rule.Errors()); got != tt.wantErrors {
				t.Errorf("expected %d errors, got %d: %v", tt.wantErrors, got, rule.Errors())
			}
		})
	}
}

func TestDeprecatedNodeRuntimeFixStep(t *testing.T) {
	tests := []struct {
		name      string
		uses      string
		wantValue string
	}{
		{"checkout v4 bumped to v5", "actions/checkout@v4", "actions/checkout@v5"},
		{"cache restore subpath preserved", "actions/cache/restore@v4", "actions/cache/restore@v5"},
		{"cache save subpath preserved", "actions/cache/save@v4", "actions/cache/save@v5"},
		{"upload-artifact v4 bumped to v6", "actions/upload-artifact@v4", "actions/upload-artifact@v6"},
		{"upload-artifact v5 gap major bumped to v6", "actions/upload-artifact@v5", "actions/upload-artifact@v6"},
		{"github-script v7 bumped to v8", "actions/github-script@v7", "actions/github-script@v8"},
		{"already node24 untouched", "actions/checkout@v5", "actions/checkout@v5"},
		{"unknown action untouched", "someorg/someaction@v1", "someorg/someaction@v1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewDeprecatedNodeRuntimeRule(nil)
			step := nodeRuntimeTestStep(tt.uses, "")
			if err := rule.FixStep(step); err != nil {
				t.Fatalf("FixStep returned error: %v", err)
			}
			got := step.Exec.(*ast.ExecAction).Uses.BaseNode.Value
			if got != tt.wantValue {
				t.Errorf("expected %q, got %q", tt.wantValue, got)
			}
		})
	}
}
