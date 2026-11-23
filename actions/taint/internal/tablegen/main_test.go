package main

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/internal/webhook"
)

func TestUpToDate(t *testing.T) {
	spec, err := webhook.Read("../../schema/api.github.com.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	over, err := os.ReadFile("../../schema/overrides.tsv")
	if err != nil {
		t.Fatal(err)
	}
	want, err := Generate(spec, over, Events)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../../table_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("table_gen.go is not up to date; run go generate ./actions/taint/")
	}
}

func hook(sub, schema string) string {
	return `{"post": {"x-github": {"subcategory": "` + sub + `"}, "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/` + schema + `"}}}}}}`
}

var testSpec = `{
	"webhooks": {
		"issues-opened": ` + hook("issues", "w-issues-opened") + `,
		"issues-edited": ` + hook("issues", "w-issues-edited") + `,
		"push": ` + hook("push", "w-push") + `,
		"issues-assigned": ` + hook("issues", "w-issues-assigned") + `,
		"star-created": ` + hook("star", "w-push") + `,
		"pull-request-opened": ` + hook("pull_request", "w-issues-opened") + `,
		"pull-request-edited": ` + hook("pull_request", "w-issues-edited") + `,
		"pull-request-assigned": ` + hook("pull_request", "w-issues-assigned") + `
	},
	"components": {"schemas": {
		"w-issues-opened": {"type": "object", "properties": {
			"action": {"type": "string", "enum": ["opened"]},
			"issue": {"$ref": "#/components/schemas/issue"}}},
		"w-issues-edited": {"type": "object", "properties": {
			"action": {"type": "string", "enum": ["edited"]},
			"issue": {"$ref": "#/components/schemas/issue"},
			"changes": {"type": "object", "properties": {"title": {"type": "object", "properties": {"from": {"type": "string"}}}}}}},
		"issue": {"type": "object", "properties": {
			"title": {"type": "string"},
			"number": {"type": "integer"},
			"html_url": {"type": "string", "format": "uri"},
			"created_at": {"type": "string", "format": "date-time"},
			"state": {"type": "string", "enum": ["open", "closed"]},
			"labels": {"type": "array", "items": {"type": "object", "properties": {"name": {"type": "string"}}}},
			"body": {"type": ["string", "null"]},
			"parent": {"$ref": "#/components/schemas/issue"},
			"sha": {"type": "string"},
			"meta": {"type": "object", "additionalProperties": true},
			"either": {"anyOf": [{"type": "string", "enum": ["a"]}, {"type": "string"}]}}},
		"w-issues-assigned": {"oneOf": [
			{"type": "object", "properties": {"action": {"type": "string", "enum": ["assigned"]}, "assignee": {"type": "string"}}},
			{"type": "object", "properties": {"action": {"type": "string", "enum": ["assigned"]}, "team": {"type": "string"}}}]},
		"w-push": {"type": "object", "properties": {
			"after": {"type": "string"},
			"head_commit": {"type": "object", "properties": {"message": {"type": "string"}}}}}
	}}
}`

const overrides = "# pattern\tcapability\treason\n" +
	"github.event.**.sha\tfixed\ta git object ID\n" +
	"github.event.after\tfixed\ta git object ID\n" +
	"github.run_id\tfixed\ta number GitHub gives\n" +
	"github.head_ref\tstructured\tthe name of a branch\tpull_request_target\n"

var events = []string{"issues", "pull_request_target", "push"}

// dump is t as lines: event, the actions, then each row with the actions
// it is in.
func dump(tables map[string]eventTable) string {
	var b strings.Builder
	for _, name := range sortedKeys(tables) {
		e := tables[name]
		b.WriteString(name + " [" + strings.Join(e.actions, " ") + "]\n")
		for _, r := range e.rows {
			var in []string
			for i, a := range e.actions {
				if r.mask&(1<<i) != 0 {
					in = append(in, a)
				}
			}
			b.WriteString(strings.TrimRight("  "+r.path+" "+r.capability+" "+strings.Join(in, ","), " ") + "\n")
		}
	}
	return b.String()
}

func TestBuild(t *testing.T) {
	tables, top, err := build([]byte(testSpec), []byte(overrides), events)
	if err != nil {
		t.Fatal(err)
	}
	want := `issues [assigned edited opened]
  action fixed assigned,edited,opened
  assignee arbitrary assigned
  changes.title.from arbitrary edited
  issue.body arbitrary edited,opened
  issue.created_at fixed edited,opened
  issue.either arbitrary edited,opened
  issue.html_url structured edited,opened
  issue.labels.*.name arbitrary edited,opened
  issue.meta.* arbitrary edited,opened
  issue.number fixed edited,opened
  issue.parent arbitrary edited,opened
  issue.sha fixed edited,opened
  issue.state fixed edited,opened
  issue.title arbitrary edited,opened
  team arbitrary assigned
pull_request_target [assigned edited opened]
  action fixed assigned,edited,opened
  assignee arbitrary assigned
  changes.title.from arbitrary edited
  issue.body arbitrary edited,opened
  issue.created_at fixed edited,opened
  issue.either arbitrary edited,opened
  issue.html_url structured edited,opened
  issue.labels.*.name arbitrary edited,opened
  issue.meta.* arbitrary edited,opened
  issue.number fixed edited,opened
  issue.parent arbitrary edited,opened
  issue.sha fixed edited,opened
  issue.state fixed edited,opened
  issue.title arbitrary edited,opened
  team arbitrary assigned
push []
  after fixed
  head_commit.message arbitrary
`
	if got := dump(tables); got != want {
		t.Errorf("tables =\n%s\nwant\n%s", got, want)
	}
	if len(top) != 2 || top["run_id"].capability != "fixed" || top["run_id"].events != nil ||
		top["head_ref"].capability != "structured" || !slices.Equal(top["head_ref"].events, []string{"pull_request_target"}) {
		t.Errorf("top = %v", top)
	}
}

func TestBuildRejects(t *testing.T) {
	for _, c := range []struct{ name, spec, over, want string }{
		{"an override that matches nothing", testSpec, "github.event.**.nope\tfixed\tr\n", "nope"},
		{"an override without a reason", testSpec, "github.run_id\tfixed\n", "reason"},
		{"an override of an unknown capability", testSpec, "github.run_id\tsafe\tr\n", "capability"},
		{"a format not known", strings.Replace(testSpec, `"format": "uri"`, `"format": "ipv4"`, 1), overrides, "ipv4"},
		{"an event without a webhook", testSpec, overrides, "workflow_run"},
		{"a name for an event not in the table", testSpec, "github.head_ref\tstructured\tr\tpull_request\n", "pull_request"},
		{"a choice of braces that matches nothing", testSpec, "github.event.issue.{title,nope}\tfixed\tr\n", "nope"},
		{"braces inside braces", testSpec, "github.event.{issue.{title,body}}\tfixed\tr\n", "nested"},
		{"braces not closed", testSpec, "github.event.issue.{title\tfixed\tr\n", "brace"},
		{"a brace not opened", testSpec, "github.event.issue.title}\tfixed\tr\n", "brace"},
		{"braces in a name below github", testSpec, "github.{run_id,sha}\tfixed\tr\n", "brace"},
		{"an empty choice", testSpec, "github.event.issue.{title,}\tfixed\tr\n", "empty"},
		{"a choice twice", testSpec, "github.event.issue.{title,title}\tfixed\tr\n", "twice"},
		{"a path for an event not in the table", testSpec, "github.event.issue.title\tfixed\tr\tpull_request\n", "pull_request"},
		{"a path for an event it matches nothing in", testSpec, "github.event.head_commit.message\tfixed\tr\tpush,issues\n", "issues"},
		{"a choice for an event it matches nothing in", testSpec, "github.event.{issue.title,after}\tfixed\tr\tissues,push\n", "after"},
		{"login-prefixed below github", testSpec, "github.head_ref\tlogin-prefixed\tr\n", "below github.event"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ev := events
			if c.want == "workflow_run" {
				ev = []string{"workflow_run"}
			}
			_, _, err := build([]byte(c.spec), []byte(c.over), ev)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// TestOverrideBraces: a pattern with {a,b} is a pattern for each choice,
// which may hold a dot; each choice must match some path, not each
// pattern (issue.labels.*.html_url and issue.name are none).
func TestOverrideBraces(t *testing.T) {
	over := "github.event.issue.{title,number}\tfixed\tr\n" +
		"github.event.{issue.labels.*,issue}.{name,html_url}\tstructured\tr\n"
	tables, _, err := build([]byte(testSpec), []byte(over), []string{"issues"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range tables["issues"].rows {
		got[r.path] = r.capability
	}
	for p, want := range map[string]string{
		"issue.title":         "fixed",
		"issue.number":        "fixed",
		"issue.html_url":      "structured",
		"issue.labels.*.name": "structured",
		"issue.body":          "arbitrary",
	} {
		if got[p] != want {
			t.Errorf("%s = %q, want %q", p, got[p], want)
		}
	}
}

// TestOverrideEvents: a path below github.event with events is overridden
// in the tables of those events only; the others keep what the schema
// gives.
func TestOverrideEvents(t *testing.T) {
	over := "github.event.issue.title\tfixed\tr\tissues\n"
	tables, _, err := build([]byte(testSpec), []byte(over), events)
	if err != nil {
		t.Fatal(err)
	}
	for event, want := range map[string]string{"issues": "fixed", "pull_request_target": "arbitrary"} {
		found := false
		for _, r := range tables[event].rows {
			if r.path == "issue.title" {
				found = true
				if r.capability != want || r.text != want {
					t.Errorf("%s: issue.title = %q %q, want %q", event, r.capability, r.text, want)
				}
			}
		}
		if !found {
			t.Errorf("%s: no row issue.title", event)
		}
	}
}

// TestBuildShapes: a row's text is the most an attacker controls of the
// choices at its path that are not objects or arrays, over every webhook
// and the least of the branches of an allOf (fixed when there are none);
// object is whether some choice is an object without properties. A path
// is a key only when no choice makes its last * an item.
func TestBuildShapes(t *testing.T) {
	spec := `{
	"webhooks": {
		"issues-opened": ` + hook("issues", "w-opened") + `,
		"issues-edited": ` + hook("issues", "w-edited") + `
	},
	"components": {"schemas": {
		"w-opened": {"type": "object", "properties": {
			"action": {"type": "string", "enum": ["opened"]},
			"bare": {"type": "object"},
			"either": {"oneOf": [{"type": "object"}, {"type": "string"}]},
			"nullable": {"type": ["object", "null"]},
			"perhook": {"type": "object"},
			"both": {"allOf": [{"type": "object"}, {"type": "object", "properties": {"x": {"type": "string"}}}]},
			"narrowed": {"allOf": [{"type": "string"}, {"type": "string", "enum": ["a"]}]},
			"bareitems": {"type": "array", "items": {"type": "object"}},
			"free": {"type": "object", "additionalProperties": true},
			"freeobj": {"type": "object", "additionalProperties": {"type": "object", "properties": {"y": {"type": "string"}}}},
			"list": {"type": "array", "items": {"type": "string"}},
			"mixed": {"type": "object", "additionalProperties": {"type": "string"}}}},
		"w-edited": {"type": "object", "properties": {
			"action": {"type": "string", "enum": ["edited"]},
			"perhook": {"type": "string"},
			"mixed": {"type": "array", "items": {"type": "string"}}}}
	}}
}`
	over := "github.event.narrowed\tarbitrary\tr\ngithub.event.bare\tstructured\tr\n"
	tables, _, err := build([]byte(spec), []byte(over), []string{"issues"})
	if err != nil {
		t.Fatal(err)
	}
	tb := tables["issues"]
	got := map[string]string{}
	for _, r := range tb.rows {
		got[r.path] = fmt.Sprintf("%s %s %v", r.capability, r.text, r.object)
	}
	for p, want := range map[string]string{
		"bare":        "structured fixed true", // an override: no text to write over
		"either":      "arbitrary arbitrary true",
		"nullable":    "arbitrary fixed true",
		"perhook":     "arbitrary arbitrary true",
		"both":        "arbitrary fixed true",
		"narrowed":    "arbitrary arbitrary false", // an override, of its text too
		"bareitems.*": "arbitrary fixed true",
		"free.*":      "arbitrary arbitrary true", // any value: a text, or an object
		"freeobj.*.y": "arbitrary arbitrary false",
		"list.*":      "arbitrary arbitrary false",
	} {
		if got[p] != want {
			t.Errorf("%s = %q, want %q", p, got[p], want)
		}
	}
	if want := []string{"free.*", "freeobj.*"}; !slices.Equal(tb.keys, want) {
		t.Errorf("keys = %v, want %v", tb.keys, want)
	}
}
