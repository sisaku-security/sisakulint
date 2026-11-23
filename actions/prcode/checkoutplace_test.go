package prcode

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/workflow"
)

func TestMayBeV1(t *testing.T) {
	for ref, want := range map[string]bool{
		"v1": true, "1.0.0": true, "Update-description": true,
		"50fbc622fc4ef5163becd7fab6573eac35f8462e": true,
		"3204e0bf8cc961de0423eafd557ab191aad42167": true,
		"v4": false, "main": false, "11bd71901bbe5b1630ceea73d27597364c9af683": false,
	} {
		w := mustWorkflow(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@"+ref+"\n")
		u := w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items[0].Uses.Value
		if got := mayBeV1(u); got != want {
			t.Errorf("%s: %v, want %v", ref, got, want)
		}
	}
}

// TestCheckoutPlacement: the reading of the path of a checkout. The
// checkout is the last step.
func TestCheckoutPlacement(t *testing.T) {
	const hosted, self = "ubuntu-latest", "[self-hosted]"
	refused := Placement{}
	for _, c := range []struct {
		name, runsOn, before, uses, with string
		want                             Placement
		placed                           bool
	}{
		{"no with", hosted, "", "v4", "", ws("."), true},
		{"literal", hosted, "", "v4", "{path: pr}", ws("pr"), true},
		{"literal with spaces", hosted, "", "v4", "{path: ' pr '}", ws("pr"), true},
		{"absolute", hosted, "", "v4", "{path: /tmp/x}", workspacePlacement(anyDir()), true},
		{"leaves", hosted, "", "v4", "{path: ../x}", workspacePlacement(anyDir()), true},
		{"backslash", hosted, "", "v4", `{path: 'a\b'}`, workspacePlacement(anyDir()), true},
		{"drive", hosted, "", "v4", `{path: 'C:\x'}`, workspacePlacement(anyDir()), true},
		{"sentinel bytes", hosted, "", "v4", `{path: "\x01runner.temp"}`, ws("\x01runner.temp"), true},
		{"whole expression", hosted, "", "v4", "{path: '${{ inputs.p }}'}", workspacePlacement(anyDir()), true},
		{"github.workspace", hosted, "", "v4", "{path: '${{ github.workspace }}/pr'}", ws("pr"), true},
		{"github.workspace glued", hosted, "", "v4", "{path: '${{ github.workspace }}x'}", workspacePlacement(anyDir()), true},
		{"runner.temp", hosted, "", "v4", "{path: '${{ runner.temp }}/pr'}", refused, false},
		{"runner.temp alone", hosted, "", "v4", "{path: '${{ runner.temp }}'}", refused, false},
		{"runner.temp other two", hosted, "", "v4", "{path: '${{ runner.temp }}/../x/y/pr'}", refused, false},
		{"runner.temp back to the workspace", hosted, "", "v4", "{path: '${{ runner.temp }}/../r/r/pr'}", ws("pr"), true},
		{"runner.temp of a repository _temp", hosted, "", "v4", "{path: '${{ runner.temp }}/_temp/pr'}", ws("pr"), true},
		{"runner.temp out of work", hosted, "", "v4", "{path: '${{ runner.temp }}/../../w/r/r'}", workspacePlacement(anyDir()), true},
		{"runner.temp with a line break", hosted, "", "v4", "\n          path: |\n            ${{ runner.temp }}/../r/r\n", ws("."), true},
		{"runner.temp backslash", hosted, "", "v4", `{path: '${{ runner.temp }}\..\r\r\x'}`, workspacePlacement(anyDir()), true},
		{"runner.temp then an expression", hosted, "", "v4", "{path: '${{ runner.temp }}/${{ inputs.dir }}'}", workspacePlacement(anyDir()), true},
		{"runner.temp on a self-hosted runner", self, "", "v4", "{path: '${{ runner.temp }}/pr'}", workspacePlacement(anyDir()), true},
		{"runner.temp after v1", hosted, "      - uses: actions/checkout@v1\n", "v4", "{path: '${{ runner.temp }}/pr'}", workspacePlacement(anyDir()), true},
		{"runner.temp after 1.0.0", hosted, "      - uses: actions/checkout@1.0.0\n", "v4", "{path: '${{ runner.temp }}/pr'}", workspacePlacement(anyDir()), true},
		{"runner.temp after another action", hosted, "      - uses: actions/setup-node@v4\n", "v4", "{path: '${{ runner.temp }}/pr'}", workspacePlacement(anyDir()), true},
		{"runner.temp after a local action", hosted, "      - uses: ./x\n", "v4", "{path: '${{ runner.temp }}/pr'}", workspacePlacement(anyDir()), true},
		{"runner.temp after runs and v4", hosted, "      - run: echo\n      - uses: actions/checkout@v4\n      - uses: actions/checkout@main\n", "v4", "{path: '${{ runner.temp }}/pr'}", refused, false},
		{"v1 path", hosted, "", "v1", "{path: foo}", ws("."), true},
		{"v1 own repository", hosted, "", "v1", "{path: foo, repository: '${{ github.repository }}'}", ws("."), true},
		{"v1 other repository", hosted, "", "v1", "{path: tools, repository: other/x}", workspacePlacement(anyDir()), true},
		{"v1 other repository without a path", hosted, "", "v1", "{repository: other/x}", workspacePlacement(anyDir()), true},
		{"v1 with no with", hosted, "", "v1", "", ws("."), true},
	} {
		with := ""
		switch {
		case strings.HasPrefix(c.with, "\n"):
			with = "        with:" + c.with
		case c.with != "":
			with = "        with: " + c.with + "\n"
		}
		src := "on: push\njobs:\n  a:\n    runs-on: " + c.runsOn + "\n    steps:\n" + c.before + "      - uses: actions/checkout@" + c.uses + "\n" + with
		w := mustWorkflow(t, src)
		j := w.Jobs.Value.Entries[0].Value.Value
		steps := j.Steps.Value.Items
		got, placed := CheckoutPlacement(&j, steps, workflow.OrderOf(steps), len(steps)-1)
		if got != c.want || placed != c.placed {
			t.Errorf("%s: %v %v; want %v %v", c.name, got, placed, c.want, c.placed)
		}
	}
	// a parallel v1 beside the checkout, and a composite action
	w := mustWorkflow(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - parallel:\n          - uses: actions/checkout@v4\n            with: {path: '${{ runner.temp }}/pr'}\n          - uses: actions/checkout@v1\n")
	if j := w.Jobs.Value.Entries[0].Value.Value; true {
		steps := j.Steps.Value.Items
		if len(steps) != 2 {
			t.Fatalf("parallel: %d steps", len(steps))
		}
		if got, placed := CheckoutPlacement(&j, steps, workflow.OrderOf(steps), 0); !placed || got != workspacePlacement(anyDir()) {
			t.Errorf("parallel v1: %v %v", got, placed)
		}
	}
	w = mustWorkflow(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with: {path: '${{ runner.temp }}/pr'}\n")
	steps := w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items
	if got, placed := CheckoutPlacement(nil, steps, workflow.OrderOf(steps), 0); !placed || got != workspacePlacement(anyDir()) {
		t.Errorf("composite: %v %v", got, placed)
	}
}
