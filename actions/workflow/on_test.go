package workflow

import (
	"slices"
	"testing"
)

func eventNames(o On) []string {
	var ns []string
	for _, e := range o.Events {
		ns = append(ns, e.Name.Text())
	}
	return ns
}

func TestOnForms(t *testing.T) {
	for _, tt := range []struct {
		on   string
		want []string
	}{
		{"push", []string{"push"}},
		{"[push, pull_request_target]", []string{"push", "pull_request_target"}},
		{"{push: {branches: [main]}, issues: {types: opened}}", []string{"push", "issues"}},
		{"\n  push:\n  workflow_dispatch:\n", []string{"push", "workflow_dispatch"}},
		// GitHub accepts it, though the schema's constant for
		// repository-dispatch-string is wrong.
		{"repository_dispatch", []string{"repository_dispatch"}},
		{"[push, repository_dispatch]", []string{"push", "repository_dispatch"}},
		{"{schedule: [{cron: '0 0 * * *'}]}", []string{"schedule"}},
	} {
		src := "on: " + tt.on + "\n" + jobsOK
		w, diags, _ := parse(t, src)
		wantCodes(t, src, diags)
		if w.On.Status != Present || !slices.Equal(eventNames(w.On.Value), tt.want) {
			t.Errorf("%q: on %v %q, want %q", src, w.On.Status, eventNames(w.On.Value), tt.want)
		}
	}
}

func TestOnInvalid(t *testing.T) {
	for _, tt := range []struct {
		on   string
		want []Code
	}{
		{"pushh", []Code{InvalidValue}},
		{"[push, pushh]", []Code{InvalidValue}},
		// an unknown event is rejected; in the mapping form it
		// is a loose key of on-mapping-new that is no on-string.
		{"{pushh: }", []Code{InvalidValue}},
		// what is in an event is read loosely.
		{"{issues: {types: [opened, foo]}}", nil},
		{"{issues: {types: foo}}", nil},
		{"{push: {types: [a], foo: 1}}", nil},
		{"{push: foo}", []Code{InvalidValue}},
		{"{repository_dispatch: {types: [anything, at-all]}}", nil},
		{"${{ github.event_name }}", []Code{ExprNotAllowed}},
		{"{push: {branches: '${{ x }}'}}", []Code{ExprNotAllowed}},
	} {
		src := "on: " + tt.on + "\n" + jobsOK
		_, diags, _ := parse(t, src)
		wantCodes(t, src, diags, tt.want...)
	}
}

func TestOnFilters(t *testing.T) {
	src := "on:\n  push:\n    branches: [main, 'releases/**']\n    paths-ignore: website/**\n  pull_request:\n    types: [opened, synchronize]\n" + jobsOK
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags)
	push, ok := w.On.Value.Event(EventNamePush)
	if !ok || len(push.Filters) != 2 {
		t.Fatalf("push = %+v", push)
	}
	if f := push.Filters[0]; f.Key.Text() != "branches" || len(f.Values.Value.Items) != 2 || f.Values.Value.Items[1].Text() != "releases/**" {
		t.Errorf("branches = %+v", f)
	}
	if f := push.Filters[1]; f.Key.Text() != "paths-ignore" || len(f.Values.Value.Items) != 1 || f.Values.Value.Items[0].Text() != "website/**" {
		t.Errorf("paths-ignore = %+v", f)
	}
	if push.Types.Status != Absent {
		t.Errorf("push types = %v", push.Types.Status)
	}
	pr, _ := w.On.Value.Event(EventNamePullRequest)
	if pr.Types.Status != Present || len(pr.Types.Value.Items) != 2 || pr.Types.Value.Items[1].Text() != "synchronize" {
		t.Errorf("pull_request types = %+v", pr.Types)
	}
}

// TestOnNull: an event with no value is there, with nothing in it.
func TestOnNull(t *testing.T) {
	src := "on:\n  push:\n" + jobsOK
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags)
	push, ok := w.On.Value.Event(EventNamePush)
	if !ok || len(push.Filters) != 0 || push.Types.Status != Absent {
		t.Errorf("push = %+v, %v", push, ok)
	}
}

// TestOnDispatchInputs: the inputs of workflow_dispatch.
func TestOnDispatchInputs(t *testing.T) {
	src := `on:
  workflow_dispatch:
    inputs:
      env:
        type: choice
        options: [dev, prod]
        required: true
        default: dev
      note:
        description: free text
` + jobsOK
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags)
	d, _ := w.On.Value.Event(EventNameWorkflowDispatch)
	if d.Inputs.Status != Present || len(d.Inputs.Value.Entries) != 2 {
		t.Fatalf("inputs = %+v", d.Inputs)
	}
	env := d.Inputs.Value.Entries[0].Value.Value
	if env.Type.Value.Text() != "choice" || env.Required.Value.Text() != "true" || env.Default.Value.Text() != "dev" || len(env.Options.Value.Items) != 2 {
		t.Errorf("env input = %+v", env)
	}
	note, ok := d.Inputs.Value.Lookup("NOTE")
	if !ok || note.Value.Value.Type.Status != Absent {
		t.Errorf("note input = %+v", note)
	}
	// GitHub reads workflow_dispatch loosely.
	for _, tt := range []struct {
		input string
		n     int
	}{
		{"      a:\n        type: text\n", 0},
		{"      a:\n        foo: 1\n", 0},
		{"      a:\n", 0},
		{"      a:\n        required: maybe\n", 1},
	} {
		src := "on:\n  workflow_dispatch:\n    inputs:\n" + tt.input + jobsOK
		_, diags, _ := parse(t, src)
		if len(diags) != tt.n {
			t.Errorf("%q: diagnostics %v, want %d", tt.input, diags, tt.n)
		}
	}
	for _, src := range []string{
		"on:\n  workflow_dispatch:\n    inputs:\n" + jobsOK,
		"on:\n  workflow_dispatch:\n    unknown-key: asdf\n" + jobsOK,
	} {
		_, diags, _ := parse(t, src)
		wantCodes(t, src, diags)
	}
}

func TestOnWorkflowCall(t *testing.T) {
	src := `on:
  workflow_call:
    inputs:
      ref: {type: string, required: false, default: main}
    secrets:
      token:
      key: {required: true}
    outputs:
      sha:
        value: ${{ jobs.a.outputs.sha }}
` + jobsOK
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags)
	c, _ := w.On.Value.Event(EventNameWorkflowCall)
	if in, ok := c.Inputs.Value.Lookup("ref"); !ok || in.Value.Value.Type.Value.Text() != "string" {
		t.Errorf("inputs = %+v", c.Inputs)
	}
	if len(c.Secrets.Value.Entries) != 2 || c.Secrets.Value.Entries[0].Value.Status != Present || c.Secrets.Value.Entries[1].Value.Value.Required.Value.Text() != "true" {
		t.Errorf("secrets = %+v", c.Secrets)
	}
	sha, _ := c.Outputs.Value.Lookup("sha")
	if v := sha.Value.Value.Value.Value; !v.IsExpr() || v.Parts[0].Tree == nil {
		t.Errorf("output value = %+v", v)
	}
	// workflow-call-input-definition requires type.
	src = "on:\n  workflow_call:\n    inputs:\n      a: {required: true}\n" + jobsOK
	_, diags, _ = parse(t, src)
	wantCodes(t, src, diags, MissingKey)
}

func TestOnAlias(t *testing.T) {
	src := "name: &o push\non: *o\n" + jobsOK
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags)
	if names := eventNames(w.On.Value); !slices.Equal(names, []string{"push"}) || !w.On.Value.Events[0].Shared() {
		t.Errorf("on = %q", names)
	}
	src = "env: &p {branches: main}\non: {push: *p}\n" + jobsOK
	w, diags, _ = parse(t, src)
	wantCodes(t, src, diags)
	push, _ := w.On.Value.Event(EventNamePush)
	if len(push.Filters) != 1 || !push.Shared() || !push.Filters[0].Values.Value.Items[0].Shared() {
		t.Errorf("push = %+v", push)
	}
}

// TestOnEvent: On.Event finds the event of a name exactly;
// a name GitHub does not know, or in capitals, is no EventName, and stays
// in Events.
func TestOnEvent(t *testing.T) {
	src := "on: {Push: {}, pull_request_targt: {}, workflow_call: {}}\n" + jobsOK
	w, _, _ := parse(t, src)
	if _, ok := w.On.Value.Event(EventNamePush); ok {
		t.Error("Push is push")
	}
	if _, ok := w.On.Value.Event(EventNamePullRequestTarget); ok {
		t.Error("pull_request_targt is pull_request_target")
	}
	if e, ok := w.On.Value.Event(EventNameWorkflowCall); !ok || e.Name.Text() != "workflow_call" {
		t.Errorf("workflow_call: %v, %v", e.Name.Text(), ok)
	}
	if got := eventNames(w.On.Value); !slices.Equal(got, []string{"Push", "pull_request_targt", "workflow_call"}) {
		t.Errorf("Events = %q", got)
	}
}
