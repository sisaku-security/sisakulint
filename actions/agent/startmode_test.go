package agent

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// envsOf are the env of a workflow, a job and a step, each written
// "KEY: value" or none for "".
func envsOf(t *testing.T, wf, job, step string) []workflow.Field[workflow.Map[workflow.String]] {
	t.Helper()
	src := "on: push\n"
	if wf != "" {
		src += "env:\n  " + wf + "\n"
	}
	src += "jobs:\n  a:\n    runs-on: x\n"
	if job != "" {
		src += "    env:\n      " + job + "\n"
	}
	src += "    steps:\n      - run: x\n"
	if step != "" {
		src += "        env:\n          " + step + "\n"
	}
	w, _ := workflow.Parse(cst.Parse([]byte(src)))
	j := w.Jobs.Value.Entries[0].Value.Value
	return []workflow.Field[workflow.Map[workflow.String]]{w.Env, j.Env, j.Steps.Value.Items[0].Env}
}

func TestStartModeOf(t *testing.T) {
	issues := []analysis.EventActivity{ev(t, workflow.EventNameIssues, workflow.ActivityTypeOpened)}
	for _, c := range []struct {
		name, with string
		env        [3]string // workflow, job, step
		want       analysis.ClaudeStartMode
		source     string
	}{
		{"no mode", "          prompt: p\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"flag auto", "          prompt: p\n          claude_args: --permission-mode auto\n", [3]string{}, analysis.ClaudeStartModeAuto, "--permission-mode auto"},
		{"flag plan", "          prompt: p\n          claude_args: --permission-mode plan\n", [3]string{}, analysis.ClaudeStartModePlan, "--permission-mode plan"},
		{"plan without the classifier", "          prompt: p\n          claude_args: --permission-mode plan\n          settings: '{\"useAutoModeDuringPlan\": false}'\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"flag default over bedrock", "          prompt: p\n          use_bedrock: 'true'\n          claude_args: --permission-mode default\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"bypass over bedrock", "          prompt: p\n          use_bedrock: 'true'\n          claude_args: --dangerously-skip-permissions\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"flag expr", "          prompt: p\n          use_bedrock: 'true'\n          claude_args: --permission-mode ${{ vars.M }}\n", [3]string{}, analysis.ClaudeStartModeUnread, ""},
		{"claude_args expr", "          prompt: p\n          use_bedrock: 'true'\n          claude_args: ${{ vars.A }}\n", [3]string{}, analysis.ClaudeStartModeUnread, ""},
		{"a flag of expr", "          prompt: p\n          use_bedrock: 'true'\n          claude_args: --model m ${{ vars.A }}\n", [3]string{}, analysis.ClaudeStartModeUnread, ""},
		{"--settings auto", "          prompt: p\n          claude_args: --settings '{\"permissions\":{\"defaultMode\":\"auto\"}}'\n", [3]string{}, analysis.ClaudeStartModeAuto, `"defaultMode": "auto"`},
		{"--settings over settings", "          prompt: p\n          claude_args: --settings '{\"permissions\":{\"defaultMode\":\"default\"}}'\n          settings: '{\"permissions\":{\"defaultMode\":\"auto\"}}'\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"settings auto", "          prompt: p\n          settings: '{\"permissions\":{\"defaultMode\":\"auto\"}}'\n", [3]string{}, analysis.ClaudeStartModeAuto, `"defaultMode": "auto"`},
		{"settings mode expr", "          prompt: p\n          use_bedrock: 'true'\n          settings: '{\"permissions\":{\"defaultMode\":\"${{ vars.M }}\"}}'\n", [3]string{}, analysis.ClaudeStartModeUnread, ""},
		{"settings expr in a hook", "          prompt: p\n          settings: '{\"permissions\":{\"defaultMode\":\"auto\"},\"hooks\":{\"Stop\":[{\"hooks\":[{\"type\":\"command\",\"command\":\"${{ github.workspace }}/x.sh\"}]}]}}'\n", [3]string{}, analysis.ClaudeStartModeAuto, `"defaultMode": "auto"`},
		{"settings expr with braces in a hook", "          prompt: p\n          settings: '{\"permissions\":{\"defaultMode\":\"auto\"},\"hooks\":{\"Stop\":[{\"hooks\":[{\"type\":\"command\",\"command\":\"${{ format(''{0}/x.sh'', github.workspace) }}\"}]}]}}'\n", [3]string{}, analysis.ClaudeStartModeAuto, `"defaultMode": "auto"`},
		{"settings file", "          prompt: p\n          use_bedrock: 'true'\n          settings: .claude/ci.json\n", [3]string{}, analysis.ClaudeStartModeUnread, ""},
		{"flag auto over a settings file", "          prompt: p\n          claude_args: --permission-mode auto --settings ./ci.json\n", [3]string{}, analysis.ClaudeStartModeAuto, "--permission-mode auto"},
		{"flag dontAsk over a settings input file", "          prompt: p\n          claude_args: --permission-mode dontAsk\n          settings: ./s.json\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"setting-sources expr", "          prompt: p\n          use_bedrock: 'true'\n          claude_args: --setting-sources ${{ vars.SRC }}\n          settings: '{\"permissions\":{\"defaultMode\":\"default\"}}'\n", [3]string{}, analysis.ClaudeStartModeUnread, ""},
		{"setting-sources expr, no settings", "          prompt: p\n          use_bedrock: 'true'\n          claude_args: --setting-sources ${{ vars.SRC }}\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"setting-sources empty", "          prompt: p\n          claude_args: --setting-sources ''\n          settings: '{\"permissions\":{\"defaultMode\":\"auto\"}}'\n", [3]string{}, analysis.ClaudeStartModeAuto, `"defaultMode": "auto"`},
		{"settings empty", "          prompt: p\n          use_bedrock: 'true'\n          settings: ''\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"settings not read", "          prompt: p\n          claude_args: --setting-sources project\n          settings: '{\"permissions\":{\"defaultMode\":\"auto\"}}'\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"disableAutoMode", "          prompt: p\n          use_bedrock: 'true'\n          settings: '{\"disableAutoMode\":\"disable\"}'\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"disableAutoMode in permissions", "          prompt: p\n          claude_args: --permission-mode auto\n          settings: '{\"permissions\":{\"disableAutoMode\":\"disable\"}}'\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"bedrock", "          prompt: p\n          use_bedrock: 'true'\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"vertex True", "          prompt: p\n          use_vertex: 'True'\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"bedrock false", "          prompt: p\n          use_bedrock: 'false'\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"foundry expr", "          prompt: p\n          use_foundry: ${{ vars.F }}\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"provider managed by host", "          prompt: p\n          use_bedrock: 'true'\n", [3]string{"", "", "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST: '1'"}, analysis.ClaudeStartModeOther, ""},
		{"job telemetry", "          prompt: p\n", [3]string{"", "DISABLE_TELEMETRY: '0'", ""}, analysis.ClaudeStartModeOther, ""},
		{"do not track 0", "          prompt: p\n", [3]string{"DO_NOT_TRACK: '0'", "", ""}, analysis.ClaudeStartModeOther, ""},
		{"do not track 1", "          prompt: p\n", [3]string{"DO_NOT_TRACK: '1'", "", ""}, analysis.ClaudeStartModeOther, ""},
		{"growthbook true", "          prompt: p\n", [3]string{"", "", "DISABLE_GROWTHBOOK: 'true'"}, analysis.ClaudeStartModeOther, ""},
		{"growthbook false", "          prompt: p\n", [3]string{"", "", "DISABLE_GROWTHBOOK: 'false'"}, analysis.ClaudeStartModeOther, ""},
		{"nonessential traffic", "          prompt: p\n", [3]string{"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: 'false'", "", ""}, analysis.ClaudeStartModeOther, ""},
		{"nearer expr", "          prompt: p\n", [3]string{"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1'", "", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: ${{ vars.T }}"}, analysis.ClaudeStartModeOther, ""},
		{"nearer empty", "          prompt: p\n", [3]string{"DISABLE_TELEMETRY: '1'", "DISABLE_TELEMETRY: ''", ""}, analysis.ClaudeStartModeOther, ""},
		{"flag auto, users", "          prompt: p\n          allowed_non_write_users: '*'\n          claude_args: --permission-mode auto\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"flag auto, users, job 0", "          prompt: p\n          allowed_non_write_users: '*'\n          claude_args: --permission-mode auto\n", [3]string{"", "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: '0'", ""}, analysis.ClaudeStartModeAuto, "--permission-mode auto"},
		{"flag auto, users expr", "          prompt: p\n          allowed_non_write_users: ${{ vars.U }}\n          claude_args: --permission-mode auto\n", [3]string{}, analysis.ClaudeStartModeUnread, ""},
		{"flag auto, scrub var", "          prompt: p\n          claude_args: --permission-mode auto\n", [3]string{"CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: '1'", "", ""}, analysis.ClaudeStartModeOther, ""},
		{"flag plan, users", "          prompt: p\n          allowed_non_write_users: '*'\n          claude_args: --permission-mode plan\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"settings auto, users", "          prompt: p\n          allowed_non_write_users: '*'\n          settings: '{\"permissions\":{\"defaultMode\":\"auto\"}}'\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"no mode, users expr", "          prompt: p\n          allowed_non_write_users: ${{ vars.U }}\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
		{"flag default, users expr", "          prompt: p\n          allowed_non_write_users: ${{ vars.U }}\n          claude_args: --permission-mode default\n", [3]string{}, analysis.ClaudeStartModeOther, ""},
	} {
		got, ok := StartModeOf(agentOf(t, claudeWith(c.with)), issues, envsOf(t, c.env[0], c.env[1], c.env[2]))
		if !ok || got.Mode != c.want || got.Source != c.source {
			t.Errorf("%s: %v %s %q, want %s %q", c.name, ok, got.Mode, got.Source, c.want, c.source)
		}
	}
	base := "uses: anthropics/claude-code-base-action@v1\n        with:\n          prompt: p\n          use_vertex: 'true'\n"
	if got, ok := StartModeOf(agentOf(t, base), issues, nil); !ok || got.Mode != analysis.ClaudeStartModeOther || got.Source != "" {
		t.Errorf("base-action: %v %s %q", ok, got.Mode, got.Source)
	}
	if _, ok := StartModeOf(agentOf(t, codexWith("          prompt: p\n")), issues, nil); ok {
		t.Error("codex: a start mode")
	}
}

// TestStartModeOfEvents: the tag mode's acceptEdits wins over the
// settings, a --permission-mode of claude_args over the tag mode's.
func TestStartModeOfEvents(t *testing.T) {
	issues := ev(t, workflow.EventNameIssues, workflow.ActivityTypeOpened)
	comment := ev(t, workflow.EventNameIssueComment, workflow.ActivityTypeCreated)
	dispatch := ev(t, workflow.EventNameWorkflowDispatch, workflow.ActivityTypeUnset)
	for _, c := range []struct {
		name, with string
		evs        []analysis.EventActivity
		on         []analysis.EventActivity
	}{
		{"tag mode alone", "          use_bedrock: 'true'\n", []analysis.EventActivity{issues}, nil},
		{"tag mode, settings auto", "          settings: '{\"permissions\":{\"defaultMode\":\"auto\"}}'\n", []analysis.EventActivity{comment}, nil},
		{"tag mode, a flag of auto", "          claude_args: --permission-mode auto\n", []analysis.EventActivity{comment}, []analysis.EventActivity{comment}},
		{"track_progress", "          prompt: p\n          track_progress: 'true'\n          use_bedrock: 'true'\n", []analysis.EventActivity{issues, dispatch}, []analysis.EventActivity{dispatch}},
		{"tag mode, a flag of auto, users", "          allowed_non_write_users: '*'\n          claude_args: --permission-mode auto\n", []analysis.EventActivity{comment}, []analysis.EventActivity{comment}},
		{"track_progress with a flag", "          prompt: p\n          track_progress: 'true'\n          claude_args: --permission-mode auto\n", []analysis.EventActivity{issues, dispatch}, []analysis.EventActivity{issues, dispatch}},
	} {
		m, ok := StartModeOf(agentOf(t, claudeWith(c.with)), c.evs, nil)
		if ok != (len(c.on) > 0) || len(m.On) != len(c.on) {
			t.Errorf("%s: %v %v, want %v", c.name, ok, m.On, c.on)
			continue
		}
		for i := range c.on {
			if m.On[i] != c.on[i] {
				t.Errorf("%s: %v, want %v", c.name, m.On, c.on)
			}
		}
	}
}

// TestStartModeOfPlacesTheSource: the source is where it is written.
func TestStartModeOfPlacesTheSource(t *testing.T) {
	issues := []analysis.EventActivity{ev(t, workflow.EventNameIssues, workflow.ActivityTypeOpened)}
	s := agentOf(t, claudeWith("          prompt: p\n          claude_args: --permission-mode auto\n"))
	m, _ := StartModeOf(s, issues, nil)
	if m.At.Base.Primary() == s.Step.Uses.Value.Base.Primary() {
		t.Error("the flag: at the uses")
	}
}
