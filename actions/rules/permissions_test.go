package rules

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// TestPermissions: the kinds of permissions by the permissions of the
// workflow and of the job.
func TestPermissions(t *testing.T) {
	type want struct {
		kind string
		args lint.FindingArgs
		cond string
	}
	job := func(on, wf, j string) string {
		return "on: " + on + "\n" + wf + "jobs:\n  a:\n    runs-on: ubuntu-latest\n" + j + "    steps:\n      - uses: actions/setup-node@v4\n"
	}
	for _, c := range []struct {
		name, src string
		want      []want
	}{
		{"unwritten", job("push", "", ""), []want{{"permissions.unwritten", PermissionsUnwritten{}, writeCond}}},
		{"workflow write-all", job("push", "permissions: write-all\n", ""), []want{{"permissions.write-all", PermissionsWriteAll{WriteAll: analysis.WriteAllWorkflow}, ""}}},
		{"job write-all", job("push", "permissions: {contents: read}\n", "    permissions: write-all\n"), []want{{"permissions.write-all", PermissionsWriteAll{WriteAll: analysis.WriteAllJob}, ""}}},
		{"job read over write-all", job("push", "permissions: write-all\n", "    permissions: {contents: read}\n"), nil},
		{"empty", job("push", "permissions: {}\n", ""), nil},
		{"read-all", job("push", "permissions: read-all\n", ""), nil},
		{"written write", job("push", "permissions: {contents: write}\n", ""), nil},
		{"called only", job("workflow_call", "", ""), nil},
		{"called mapping", job("{workflow_call: {inputs: {a: {type: string}}}}", "permissions: write-all\n", ""), nil},
		{"empty on", job("{}", "", ""), nil},
		{"folded write-all", job("push", "permissions: ${{ 'write-all' }}\n", ""), []want{{"permissions.write-all", PermissionsWriteAll{WriteAll: analysis.WriteAllWorkflow}, ""}}},
		{"called and push", job("[workflow_call, push]", "", ""), []want{{"permissions.unwritten", PermissionsUnwritten{}, writeCond}}},
		{"attacker event too", job("issues", "", ""), []want{{"permissions.unwritten", PermissionsUnwritten{}, writeCond}}},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{Permissions}, wfFile(c.src), exposureFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != len(c.want) {
			t.Errorf("%s: %d findings %+v", c.name, len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			continue
		}
		for i, w := range c.want {
			f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[i]
			if f.Args.KindID().String() != w.kind || !argsEqual(f.Args, w.args) || condJSON(t, f) != w.cond {
				t.Errorf("%s: %s %+v %s; want %s %+v %s", c.name, f.Args.KindID(), f.Args, condJSON(t, f), w.kind, w.args, w.cond)
			}
		}
	}
}

// TestPermissionsAgentkit: coinbase/agentkit
// 5e01c2d99b2077e6748342d0ca7a73ac198ce3ce .github/workflows/changelog.yml
// (lines 1-11 and 26-32; the other steps left out), whose job wrote no
// permissions and ran tj-actions/changed-files@v39 when its tag was moved
// to a malicious commit on 2025-03-14.
func TestPermissionsAgentkit(t *testing.T) {
	const src = `name: Changelog

on: [pull_request]

jobs:
  check-changelog-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Check for modified Python files in coinbase-agentkit
        if: steps.check-label.outputs.skip != 'true'
        id: changed-agent-files
        uses: tj-actions/changed-files@v39
        with:
          files: |
            python/coinbase-agentkit/**/*.py
`
	rep, _, _ := checkRules(t, []lint.Rule{Permissions}, wfFile(src), exposureFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID().String() != "permissions.unwritten" || condJSON(t, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]) != writeCond {
		t.Errorf("%+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}
