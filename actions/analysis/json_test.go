package analysis

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestJSON: the values the args of findings hold are written as the
// schema of findings names them (findings-v0.json, $defs/sink-kind and
// $defs/approval), and a value with no name there is an error.
func TestJSON(t *testing.T) {
	for _, c := range []struct {
		v    any
		want string
	}{
		{SinkRun, `"run"`},
		{SinkScript, `"github-script"`},
		{ApprovalLabel, `"label"`},
		{ApprovalEnvironment, `"environment"`},
		{ImageSiteKindContainer, `"container"`},
		{ImageSiteKindService, `"service"`},
		{ImageSiteKindStep, `"step"`},
		{ImageSiteKindAction, `"action"`},
		{DownloadInputRunID, `"run-id"`},
		{DownloadInputRunIDSnake, `"run_id"`},
		{DownloadInputRepo, `"repo"`},
		{DownloadInputAllowForks, `"allow_forks"`},
		{DownloadInputUses, `"uses"`},
		{WriteAllJob, `"job"`},
		{WriteAllWorkflow, `"workflow"`},
		{AgentActionClaudeCode, `"claude-code-action"`},
		{AgentActionClaudeCodeBase, `"claude-code-base-action"`},
		{AgentActionCodex, `"codex-action"`},
		{AgentActionGeminiCLI, `"run-gemini-cli"`},
		{AgentActionAIInference, `"ai-inference"`},
		{AgentInputAllowedNonWriteUsers, `"allowed_non_write_users"`},
		{AgentInputAllowedBots, `"allowed_bots"`},
		{AgentInputAllowUsers, `"allow-users"`},
		{AgentInputClaudeArgs, `"claude_args"`},
		{AgentInputSettings, `"settings"`},
		{AgentInputSafetyStrategy, `"safety-strategy"`},
		{AgentInputSandbox, `"sandbox"`},
		{AgentInputPermissionProfile, `"permission-profile"`},
		{AgentInputCodexArgs, `"codex-args"`},
		{AgentInputPrompt, `"prompt"`},
		{AgentInputSystemPrompt, `"system-prompt"`},
		{AgentInputInput, `"input"`},
		{AgentInputCopilotAllowTools, `"copilot-allow-tools"`},
		{AgentInputTrackProgress, `"track_progress"`},
		{AgentInputUseCommitSigning, `"use_commit_signing"`},
		{AgentInputSSHSigningKey, `"ssh_signing_key"`},
	} {
		if b, err := json.Marshal(c.v); err != nil || string(b) != c.want {
			t.Errorf("%v: got %s, %v; want %s", c.v, b, err, c.want)
		}
	}
	if _, err := json.Marshal(ApprovalNone); err == nil {
		t.Error("ApprovalNone was written")
	}
	if _, err := json.Marshal(ImageSiteKindUnset); err == nil {
		t.Error("ImageSiteKindUnset was written")
	}
	if _, err := json.Marshal(AgentActionUnset); err == nil {
		t.Error("AgentActionUnset was written")
	}
	if _, err := json.Marshal(AgentInputUnset); err == nil {
		t.Error("AgentInputUnset was written")
	}
	if _, err := json.Marshal(WriteAllNo); err == nil {
		t.Error("WriteAllNo was written")
	}
}

// TestAgentCapabilityNames: the names of the capabilities and of the kinds
// an agent's permissions leave undecided, which the IR and the registry
// show.
func TestAgentCapabilityNames(t *testing.T) {
	for _, c := range []struct {
		got  fmt.Stringer
		want string
	}{
		{AgentCapabilityRunsAnyCode, "runs-any-code"},
		{AgentCapabilityEditsWorkspace, "edits-workspace"},
		{AgentCapabilityWritesChosenTarget, "writes-chosen-target"},
		{AgentCapabilitySendsChosenHost, "sends-chosen-host"},
		{InconclusiveAgentCommand, "unknown-command"},
		{InconclusiveAgentMCP, "custom-mcp"},
	} {
		if c.got.String() != c.want {
			t.Errorf("%v: want %s", c.got, c.want)
		}
	}
}
