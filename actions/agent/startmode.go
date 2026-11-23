package agent

import (
	"bytes"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// StartMode is the permission mode Claude Code starts in on the runs of a
// step of claude-code-action or its base-action: the first of the last
// --permission-mode (or --dangerously-skip-permissions) of claude_args,
// the defaultMode of its --settings, that of the settings input, and the
// built-in default, which is default for claude -p and the Agent SDK from
// Claude Code v2.1.302, the CLI the actions install
// (https://code.claude.com/docs/en/permission-modes, which mode a session
// starts in). The subprocess env scrub (ScrubOf) keeps any of them in the
// default mode.
type StartMode struct {
	Mode   analysis.ClaudeStartMode
	Source string                   // what decides an auto or a plan mode, as written
	At     TextAt                   // the input that decides it, or the uses
	On     []analysis.EventActivity // the events of the runs it starts in the mode
	set    string                   // the mode the inputs set, before the subprocess env scrub; empty for the built-in default
}

// maskExprs is v with each ${{ }} that has no quote in it, which a JSON
// string may hold as it is, made x; the ${{ }} are found by their syntax
// (expr.Scan), so a } inside a string literal of the ${{ }} does not end
// it.
func maskExprs(v string) string {
	segs, _ := expr.Scan(v)
	var b strings.Builder
	for _, g := range segs {
		t := v[g.Span.Start:g.Span.End]
		if g.Expr && !strings.Contains(t, `"`) {
			t = "x"
		}
		b.WriteString(t)
	}
	return b.String()
}

// modeSettings is what a settings text says of the mode.
type modeSettings struct {
	defaultMode string
	disabled    bool // disableAutoMode, at the top or under permissions, is disable
	noPlanAuto  bool // useAutoModeDuringPlan is false
}

// readModeSettings reads the settings text v; false when v is not JSON (a
// file's path) or a ${{ }} may set what it says of the mode. A ${{ }}
// inside a string of the JSON, as in the command of a hook, is read as
// that string.
func readModeSettings(v string) (modeSettings, bool) {
	v = strings.TrimSpace(v)
	masked := maskExprs(v)
	if strings.Contains(masked, "${{") {
		return modeSettings{}, false // a ${{ }} out of a string may write keys
	}
	o, ok := jsonObject([]byte(masked))
	if !ok {
		return modeSettings{}, false
	}
	var m modeSettings
	m.defaultMode, _ = stringAt(o, "permissions", "defaultMode")
	top, _ := stringAt(o, "disableAutoMode")
	under, _ := stringAt(o, "permissions", "disableAutoMode")
	if strings.Contains(v, "${{") && (m.defaultMode == "x" || top == "x" || under == "x") {
		return modeSettings{}, false // the mode is a ${{ }}
	}
	m.disabled = top == "disable" || under == "disable"
	if raw, ok := valueAt(o, "useAutoModeDuringPlan"); ok && string(bytes.TrimSpace(raw)) == "false" {
		m.noPlanAuto = true
	}
	return m, true
}

// StartModeOf is the mode the agent of s starts in on the events of evs:
// in claude-code-action's agent mode, and in its tag mode when a
// --permission-mode of claude_args wins over the tag mode's acceptEdits
// (tag/index.ts of claude-code-action). false when s is no
// step of claude-code-action or its base-action, or starts no agent on evs
// in such a mode.
func StartModeOf(s Step, evs []analysis.EventActivity, env []workflow.Field[workflow.Map[workflow.String]]) (StartMode, bool) {
	if s.Action != analysis.AgentActionClaudeCode && s.Action != analysis.AgentActionClaudeCodeBase {
		return StartMode{}, false
	}
	m := StartMode{At: TextAt{Base: s.Step.Uses.Value.Base}}
	if s.Step.With.Status == workflow.Dynamic {
		m.Mode, m.On = analysis.ClaudeStartModeUnread, evs
		return m, true
	}
	flagSet := m.read(s.Step)
	m.scrub(ScrubOf(s, env))
	agentMode := true
	if s.Action == analysis.AgentActionClaudeCode {
		agentMode, _ = claudeModes(s.Step, evs)
	}
	for _, e := range evs {
		tag := s.Action == analysis.AgentActionClaudeCode && claudeTagOn(s.Step, e)
		if tag && flagSet || !tag && agentMode {
			m.On = append(m.On, e)
		}
	}
	if len(m.On) == 0 {
		return StartMode{}, false
	}
	return m, true
}

// read sets m's mode, its source and where it is, and is whether a flag of
// claude_args sets it, which wins over the tag mode's.
func (m *StartMode) read(s workflow.Step) (flagSet bool) {
	var flagMode string // the last --permission-mode, or bypassPermissions for --dangerously-skip-permissions
	var sets []modeSettings
	userSource := true
	unread, sourcesUnread := false, false // a settings text, or --setting-sources, that is not read
	var argsAt TextAt
	switch args := inputOf(s, analysis.AgentInputClaudeArgs); {
	case args.whole:
		m.Mode = analysis.ClaudeStartModeUnread
		return true // it may set the mode
	case args.present:
		argsAt = TextAt{Base: args.at}
		r, undecided := argsRecord(args)
		if undecided {
			m.Mode = analysis.ClaudeStartModeUnread // a ${{ }} where a flag may be
			return true
		}
		if v, ok := lastValue(r, "permission-mode"); ok {
			if strings.Contains(v, "${{") {
				m.Mode = analysis.ClaudeStartModeUnread
				return true
			}
			flagMode = v
		}
		if slices.ContainsFunc(r, func(f flag) bool { return f.key == "dangerously-skip-permissions" }) {
			flagMode = "bypassPermissions"
		}
		if v, ok := lastValue(r, "settings"); ok {
			ms, ok := readModeSettings(v)
			unread = unread || !ok // a file, or a ${{ }}
			sets = append(sets, ms)
		}
		// the action passes on a value that is not empty, else every source
		if v, ok := lastValue(r, "setting-sources"); ok && strings.TrimSpace(v) != "" {
			sourcesUnread = strings.Contains(v, "${{")
			userSource = slices.Contains(strings.Split(v, ","), "user")
		}
	}
	// the action skips a settings input that is empty or blank
	// (setup-claude-code-settings.ts L34)
	set := inputOf(s, analysis.AgentInputSettings)
	set.present = set.present && (set.whole || strings.TrimSpace(set.value.Text()) != "")
	switch {
	case set.present && sourcesUnread:
		unread = true // whether the CLI reads it is not known
	case set.present && userSource:
		ms, ok := readModeSettings(set.value.Text())
		unread = unread || set.whole || !ok
		sets = append(sets, ms)
	}
	if unread && flagMode == "" {
		m.Mode = analysis.ClaudeStartModeUnread
		return false
	}
	// a flag decides the mode over a settings text that is not read; a
	// disableAutoMode in it is auto-unavailable's
	disabled, noPlanAuto := false, false
	for _, ms := range sets {
		disabled, noPlanAuto = disabled || ms.disabled, noPlanAuto || ms.noPlanAuto
	}
	mode, source, at := flagMode, "--permission-mode "+flagMode, argsAt
	defer func() { m.set = mode }()
	if mode == "" {
		for i, ms := range sets {
			if ms.defaultMode != "" {
				mode, source = ms.defaultMode, `"defaultMode": "`+ms.defaultMode+`"`
				if i == len(sets)-1 && set.present && userSource && !sourcesUnread {
					at = TextAt{Base: set.at}
				}
				break
			}
		}
	}
	switch {
	case disabled:
		m.Mode = analysis.ClaudeStartModeOther // auto mode is off: the session starts in default
	case mode == "auto":
		m.Mode, m.Source, m.At = analysis.ClaudeStartModeAuto, source, at
	case mode == "plan" && !noPlanAuto:
		m.Mode, m.Source, m.At = analysis.ClaudeStartModePlan, source, at
	default:
		m.Mode = analysis.ClaudeStartModeOther // the built-in default is default
	}
	return flagMode != ""
}

// scrub keeps an auto or a plan mode, or one that is not read, in the
// default mode under the subprocess env scrub, and leaves an auto or a
// plan mode undecided when the scrub is. Any other mode is the default
// mode under the scrub too, so the scrub changes nothing of it.
func (m *StartMode) scrub(sc analysis.SubprocessScrub, _ ScrubSource) {
	switch {
	case m.Mode != analysis.ClaudeStartModeAuto && m.Mode != analysis.ClaudeStartModePlan && m.Mode != analysis.ClaudeStartModeUnread:
	case sc == analysis.SubprocessScrubOn:
		m.Mode, m.Source = analysis.ClaudeStartModeOther, ""
	case sc == analysis.SubprocessScrubUndecided:
		m.Mode, m.Source = analysis.ClaudeStartModeUnread, ""
	}
}

// argsRecord is the record of claude_args, and whether a ${{ }} is in a
// flag's name or a word of no flag, where it may become flags.
func argsRecord(in input) ([]flag, bool) {
	exprs := exprSpans(in.value)
	stripped, of := stripCommentsAt(in.value.Text())
	ws := scan(stripped, of, exprs)
	r := record(ws)
	used := make([]bool, len(ws))
	for _, f := range r {
		for _, i := range f.words {
			used[i] = true
		}
	}
	for i, w := range ws {
		if len(w.at) > 0 && overlaps(w.at[0], w.at[len(w.at)-1]+1, exprs) && (!used[i] || strings.HasPrefix(w.text, "--")) {
			return r, true
		}
	}
	return r, false
}

// ScrubDecides is whether a ${{ }} that decides the subprocess env scrub
// of s (ScrubOf) leaves open what its agent may do on evs under env: the
// inputs set a mode the scrub keeps in the default mode (auto, plan,
// acceptEdits, bypassPermissions), or the step may run in claude-code-action's
// tag mode, whose acceptEdits the scrub takes away.
func ScrubDecides(s Step, evs []analysis.EventActivity, env []workflow.Field[workflow.Map[workflow.String]]) bool {
	if sc, _ := ScrubOf(s, env); sc != analysis.SubprocessScrubUndecided || s.Step.With.Status == workflow.Dynamic {
		return false
	}
	var m StartMode
	flagSet := m.read(s.Step)
	switch m.set {
	case "auto", "plan", "acceptEdits", "bypassPermissions":
		return true
	}
	if s.Action != analysis.AgentActionClaudeCode || flagSet {
		return false
	}
	_, tag := claudeModes(s.Step, evs)
	return tag
}

// AutoMode is whether the agent of s, a step of claude-code-action or its
// base-action that runs on evs under env (the env of its workflow, job and
// step), starts in auto mode (StartModeOf): on for auto; undecided when a
// ${{ }} or a settings file may set it, or a ${{ }} decides the subprocess
// env scrub; off for another mode, plan mode, which edits nothing, the tag
// mode alone, and any other action.
func AutoMode(s Step, evs []analysis.EventActivity, env []workflow.Field[workflow.Map[workflow.String]]) analysis.AgentAutoMode {
	m, ok := StartModeOf(s, evs, env)
	switch {
	case !ok:
		return analysis.AgentAutoModeOff
	case m.Mode == analysis.ClaudeStartModeAuto:
		return analysis.AgentAutoModeOn
	case m.Mode == analysis.ClaudeStartModeUnread:
		return analysis.AgentAutoModeUndecided
	}
	return analysis.AgentAutoModeOff
}
