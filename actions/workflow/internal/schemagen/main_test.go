package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/internal/webhook"
)

// TestUpToDate checks that schema_gen.go is what the schemas give; run go
// generate in actions/workflow when it fails.
func TestUpToDate(t *testing.T) {
	src, err := os.ReadFile("../../schema/workflow-v1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	over, err := os.ReadFile("../../schema/runner-workflow-v1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	adds, err := os.ReadFile("../../schema/additions.json")
	if err != nil {
		t.Fatal(err)
	}
	act, err := os.ReadFile("../../schema/runner-action_yaml.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := webhook.Read("../../../taint/schema/api.github.com.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	hooks, err := webhook.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	want, err := Generate(src, over, adds, act, hooks)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../../schema_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("schema_gen.go is out of date: run go generate in actions/workflow")
	}
	if !bytes.Contains(got, []byte(`{"on", dOnNew, true}`)) {
		t.Error("on is not on-new")
	}
	if !bytes.Contains(got, []byte(`{"shell", dActionStringStepsContext, true}`)) {
		t.Error("action:run-step lacks a required shell")
	}
	if !bytes.Contains(got, []byte(`{"cache-mode", dCacheMode, false}`)) {
		t.Error("cache-mode is not a property")
	}
}

const noAction = `{"definitions": {}}`

const noAdditions = `{"definitions": {}, "properties": []}`

const base = `{"definitions": {
	"workflow-root-strict": {"mapping": {"properties": {"on": {"type": "x", "required": true}, "jobs": "j"}}},
	"x": {"string": {}},
	"on-string-strict": {"one-of": ["pr-comment-string"]},
	"pr-comment-string": {"string": {"constant": "pull_request_comment"}},
	"j": {"string": {}}}}`

func TestUnknownField(t *testing.T) {
	src := []byte(`{"definitions": {"a": {"string": {"ignore-case": true}}}}`)
	if _, err := Generate(src, []byte(`{"definitions": {}}`), []byte(noAdditions), []byte(noAction), webhook.Spec{}); err == nil {
		t.Error("an unknown field was accepted")
	}
}

func TestOverlay(t *testing.T) {
	// on-new replaces on; a definition only on uses may change.
	over := `{"definitions": {"on-new": {"coerce-raw": true, "one-of": ["x", "on-string"]}, "on-string": {"one-of": ["x"]}, "x": {"string": {"constant": "push"}}}}`
	b, err := Generate([]byte(base), []byte(over), []byte(noAdditions), []byte(noAction), webhook.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `{"on", dOnNew, true}`) || !strings.Contains(string(b), `constant: "push"`) {
		t.Errorf("%s", b)
	}
	// the names of on-string are the constants of EventName
	for _, want := range []string{"\tEventNameUnset EventName = iota\n", "\tEventNamePush\n", "\tEventNamePullRequestComment\n", `var eventNameNames = [...]string{"", "push", "pull_request_comment"}`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("no %q in\n%s", want, b)
		}
	}
	// Event names of either schema are known.
	if !strings.Contains(string(b), `name: "on-string", kind: kindOneOf, oneOf: []defID{dX, dPrCommentString}`) {
		t.Errorf("on-string lacks pull_request_comment:\n%s", b)
	}
	// A definition used outside on must not change.
	over = `{"definitions": {"on-new": {"one-of": ["j", "on-string"]}, "on-string": {"one-of": []}, "j": {"string": {"constant": "no"}}}}`
	if _, err := Generate([]byte(base), []byte(over), []byte(noAdditions), []byte(noAction), webhook.Spec{}); err == nil {
		t.Error("a change of j, which jobs uses, was accepted")
	}
}

func TestContextNames(t *testing.T) {
	over := `{"definitions": {"on-new": {"one-of": ["x", "on-string"]}, "on-string": {"one-of": []}}}`
	gen := func(ctx, overCtx string) (string, error) {
		src := strings.Replace(base, `"j": {"string": {}}`, `"j": {"context": `+ctx+`, "string": {}}`, 1)
		o := over
		if overCtx != "" {
			o = strings.Replace(over, `"on-string": {"one-of": []}`, `"on-string": {"one-of": []}, "j": {"context": `+overCtx+`, "string": {}}`, 1)
		}
		b, err := Generate([]byte(src), []byte(o), []byte(noAdditions), []byte(noAction), webhook.Spec{})
		return strings.Join(strings.Fields(string(b)), " "), err
	}
	got, err := gen(`["github", "hashFiles(1,255)", "failure(0,MAX)"]`, "")
	if err != nil {
		t.Fatal(err)
	}
	want := `dJ: {name: "j", names: expr.Names{}.WithContext(expr.ContextGithub).WithFunc(expr.FuncHashFiles, expr.Arity{Min: 1, Max: 255}).WithFunc(expr.FuncFailure, expr.Arity{Min: 0, Max: expr.MaxArgs}), kind: kindString}`
	if !strings.Contains(got, want) {
		t.Errorf("lacks %s:\n%s", want, got)
	}
	for _, bad := range []string{`["nope"]`, `["hashFiles(1)"]`, `["withJson(0,0)"]`} {
		if _, err := gen(bad, ""); err == nil {
			t.Errorf("the context list %s was accepted", bad)
		}
	}
	// A definition both schemas have takes the contexts of either, even
	// outside on.
	got, err = gen(`["github"]`, `["github", "steps"]`)
	if err != nil {
		t.Fatal(err)
	}
	if want := `names: expr.Names{}.WithContext(expr.ContextGithub).WithContext(expr.ContextSteps)`; !strings.Contains(got, want) {
		t.Errorf("lacks %s:\n%s", want, got)
	}
	// A definition on-new reaches is replaced by the runner's, which keeps
	// the contexts of both.
	src := strings.Replace(base, `"x": {"string": {}}`, `"x": {"context": ["github", "steps"], "string": {}}`, 1)
	o := `{"definitions": {"on-new": {"one-of": ["x", "on-string"]}, "on-string": {"one-of": []}, "x": {"context": ["github", "inputs"], "string": {}}}}`
	b, err := Generate([]byte(src), []byte(o), []byte(noAdditions), []byte(noAction), webhook.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	if want := `dX: {name: "x", names: expr.Names{}.WithContext(expr.ContextGithub).WithContext(expr.ContextSteps).WithContext(expr.ContextInputs), kind: kindString}`; !strings.Contains(strings.Join(strings.Fields(string(b)), " "), want) {
		t.Errorf("lacks %s:\n%s", want, b)
	}
}

func TestAction(t *testing.T) {
	over := `{"definitions": {"on-new": {"one-of": ["x", "on-string"]}, "on-string": {"one-of": []}}}`
	// The runner's action_yaml.json starts with a byte order mark. Its
	// names are those of the workflow schema; they get the prefix action:.
	act := "\xef\xbb\xbf" + `{"definitions": {
		"action-root": {"mapping": {"properties": {"runs": "j", "name": "string"}, "loose-key-type": "non-empty-string", "loose-value-type": "any"}},
		"j": {"sequence": {"item-type": "non-empty-string"}},
		"non-empty-string": {"string": {"require-non-empty": true}}}}`
	b, err := Generate([]byte(base), []byte(over), []byte(noAdditions), []byte(act), webhook.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	// gofmt aligns the columns: compare with white space collapsed.
	got := strings.Join(strings.Fields(string(b)), " ")
	for _, want := range []string{
		`dActionActionRoot: {name: "action:action-root", kind: kindMapping, loose: true, looseKey: dActionNonEmptyString, looseValue: dAny, props: []schemaProp{{"name", dString, false}, {"runs", dActionJ, false}}}`,
		`dActionJ: {name: "action:j", kind: kindSequence, item: dActionNonEmptyString}`,
		`dJ: {name: "j", kind: kindString}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %s:\n%s", want, b)
		}
	}
	// An action definition refers only to action definitions and built-ins.
	act = `{"definitions": {"action-root": {"mapping": {"properties": {"runs": "x"}}}}}`
	if _, err := Generate([]byte(base), []byte(over), []byte(noAdditions), []byte(act), webhook.Spec{}); err == nil {
		t.Error("action-root refers to x of the workflow schema, and it was accepted")
	}
	act = `{"definitions": {"a": {"string": {"ignore-case": true}}}}`
	if _, err := Generate([]byte(base), []byte(over), []byte(noAdditions), []byte(act), webhook.Spec{}); err == nil {
		t.Error("an unknown field of the action schema was accepted")
	}
}

func TestAdditions(t *testing.T) {
	over := `{"definitions": {"on-new": {"one-of": ["x", "on-string"]}, "on-string": {"one-of": []}}}`
	doc := `{"url": "https://github.com/github/docs/blob/484d6eae00bf31f731eeada8ebc2d3b6a46e3145/content/a.md#L1", "quote": "Q", "language": "en", "retrieved": "2026-10-13"}`
	obs := `{"date": "2026-10-13", "runner": "2.337.0", "observed": "a run saw it"}`
	good := `{"definitions": {"mode": {"allowed-values": ["read", "write"], "basis": [` + doc + `]}},
		"properties": [{"definition": "workflow-root-strict", "name": "mode", "type": "mode", "basis": [` + doc + `, ` + obs + `]}]}`
	b, err := Generate([]byte(base), []byte(over), []byte(good), []byte(noAction), webhook.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(strings.Fields(string(b)), " ")
	for _, want := range []string{
		`dMode: {name: "mode", kind: kindAllowed, allowed: []string{"read", "write"}}`,
		`{"mode", dMode, false}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %s:\n%s", want, b)
		}
	}
	for _, leak := range []string{"github.com/github/docs", "a run saw it"} {
		if strings.Contains(got, leak) {
			t.Errorf("the basis %q is in the output", leak)
		}
	}
	for _, tt := range []struct{ name, additions, want string }{
		{"defined upstream", `{"definitions": {"x": {"string": {}, "basis": [` + doc + `]}}, "properties": []}`, "remove it from schema/additions.json"},
		{"property upstream", `{"definitions": {}, "properties": [{"definition": "workflow-root-strict", "name": "jobs", "type": "j", "basis": [` + doc + `]}]}`, "remove it from schema/additions.json"},
		{"no such definition", `{"definitions": {}, "properties": [{"definition": "nope", "name": "m", "type": "j", "basis": [` + doc + `]}]}`, "is no mapping definition"},
		{"not a mapping", `{"definitions": {}, "properties": [{"definition": "x", "name": "m", "type": "j", "basis": [` + doc + `]}]}`, "is no mapping definition"},
		{"undefined type", `{"definitions": {}, "properties": [{"definition": "workflow-root-strict", "name": "m", "type": "nope", "basis": [` + doc + `]}]}`, "undefined type"},
		{"built-in definition", `{"definitions": {"string": {"string": {}, "basis": [` + doc + `]}}, "properties": []}`, "a built-in"},
		{"property of a built-in", `{"definitions": {}, "properties": [{"definition": "mapping", "name": "m", "type": "null", "basis": [` + doc + `]}]}`, "a built-in"},
		{"action name", `{"definitions": {"action:j": {"boolean": {}, "basis": [` + doc + `]}}, "properties": []}`, "action:"},
		{"no basis", `{"definitions": {"m": {"string": {}}}, "properties": []}`, "has no basis"},
		{"empty basis", `{"definitions": {"m": {"string": {}, "basis": []}}, "properties": []}`, "has no basis"},
		{"blank basis", `{"definitions": {"m": {"string": {}, "basis": [{}]}}, "properties": []}`, "a basis is empty"},
		{"document without quote", `{"definitions": {"m": {"string": {}, "basis": [{"url": "https://github.com/github/docs/blob/484d6eae00bf31f731eeada8ebc2d3b6a46e3145/a.md#L1", "language": "en", "retrieved": "2026-10-13"}]}}, "properties": []}`, "a document needs"},
		{"document without language", `{"definitions": {"m": {"string": {}, "basis": [{"url": "https://github.com/github/docs/blob/484d6eae00bf31f731eeada8ebc2d3b6a46e3145/a.md#L1", "quote": "Q", "retrieved": "2026-10-13"}]}}, "properties": []}`, "a document needs"},
		{"document not https", `{"definitions": {"m": {"string": {}, "basis": [{"url": "notes/a.md", "quote": "Q", "language": "en", "retrieved": "2026-10-13"}]}}, "properties": []}`, "a document needs"},
		{"document not pinned", `{"definitions": {"m": {"string": {}, "basis": [{"url": "https://github.com/github/docs/blob/main/a.md#L1", "quote": "Q", "language": "en", "retrieved": "2026-10-13"}]}}, "properties": []}`, "a document needs"},
		{"document without line", `{"definitions": {"m": {"string": {}, "basis": [{"url": "https://github.com/github/docs/blob/484d6eae00bf31f731eeada8ebc2d3b6a46e3145/a.md", "quote": "Q", "language": "en", "retrieved": "2026-10-13"}]}}, "properties": []}`, "a document needs"},
		{"observation without date", `{"definitions": {"m": {"string": {}, "basis": [{"runner": "2.337.0", "observed": "O"}]}}, "properties": []}`, "an observation needs"},
		{"observation date not a day", `{"definitions": {"m": {"string": {}, "basis": [{"date": "13 Oct 2026", "runner": "2.337.0", "observed": "O"}]}}, "properties": []}`, "an observation needs"},
		{"observation without runner", `{"definitions": {"m": {"string": {}, "basis": [{"date": "2026-10-13", "observed": "O"}]}}, "properties": []}`, "an observation needs"},
		{"runner not a version", `{"definitions": {"m": {"string": {}, "basis": [{"date": "2026-10-13", "runner": "latest", "observed": "O"}]}}, "properties": []}`, "an observation needs"},
		{"observation without what was observed", `{"definitions": {"m": {"string": {}, "basis": [{"date": "2026-10-13", "runner": "2.337.0"}]}}, "properties": []}`, "an observation needs"},
		{"repository of an observation", `{"definitions": {"m": {"string": {}, "basis": [{"repository": "o/r", "date": "2026-10-13", "runner": "2.337.0", "observed": "O"}]}}, "properties": []}`, "unknown field"},
		{"both kinds", `{"definitions": {"m": {"string": {}, "basis": [{"url": "https://x", "quote": "Q", "language": "en", "retrieved": "2026-10-13", "date": "2026-10-13"}]}}, "properties": []}`, "not both"},
		{"unknown field", `{"definitions": {"m": {"string": {}, "basis": [` + doc + `], "note": "n"}}, "properties": []}`, "unknown field"},
	} {
		_, err := Generate([]byte(base), []byte(over), []byte(tt.additions), []byte(noAction), webhook.Spec{})
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want one with %q", tt.name, err, tt.want)
		}
	}
	// action: names are the action schema's, which addAction adds after
	// the additions and would overwrite
	act := `{"definitions": {"j": {"string": {}}}}`
	if _, err := Generate([]byte(base), []byte(over), []byte(`{"definitions": {"action:j": {"boolean": {}, "basis": [`+doc+`]}}, "properties": []}`), []byte(act), webhook.Spec{}); err == nil {
		t.Error("action:j was accepted, and addAction would overwrite it")
	}
	// what tells that languageservices caught up
	_, err = Generate([]byte(base), []byte(over), []byte(`{"definitions": {"x": {"string": {}, "basis": [`+doc+`]}}, "properties": []}`), []byte(noAction), webhook.Spec{})
	if err == nil || !strings.Contains(err.Error(), "remove it from schema/additions.json") {
		t.Errorf("err = %v", err)
	}
}
