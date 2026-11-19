package agent

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// ToolPermission is an entry of what a step of an agent action allows its
// agent: an element of an input's list of tools, or one the action allows
// on its own (claude-code-action's tag mode, run-gemini-cli without
// tools.core).
type ToolPermission struct {
	Input analysis.AgentInput // the input it is in; unset for the action's own
	Text  string              // as written, or as the action writes it
	At    TextAt
}

// TextAt is where a ToolPermission is: a span of the value of an input,
// or the node Base (an input's value as a whole, or the uses for the
// action's own).
type TextAt struct {
	Base    workflow.Base
	Value   workflow.String
	Span    expr.Span
	Spanned bool
}

// UndecidedPermission is a permission, or an input of them, whose
// capabilities the analysis does not decide.
type UndecidedPermission struct {
	Kind       analysis.InconclusiveAgentKind
	Permission ToolPermission
}

// gitPushWrapper is the script claude-code-action's tag mode allows the
// agent to push with: to origin, a ref it chooses (as read on 2026-10-11).
const gitPushWrapper = "${GITHUB_ACTION_PATH}/scripts/git-push.sh"

// acceptEdits is the permission mode that lets Claude edit the files of the
// workspace, as a permission.
const acceptEdits = "--permission-mode acceptEdits"

// lists are what a step allows and denies its agent.
type lists struct {
	action    analysis.AgentAction
	allow     []ToolPermission
	deny      []ToolPermission
	undecided []UndecidedPermission
	servers   []string // the MCP servers of an inline --mcp-config
	githubMCP bool     // claude-code-action runs github-mcp-server
	writesGit bool     // the agent's edits may write .git: gemini-cli's and the Copilot CLI's
	scrub     analysis.SubprocessScrub
	scrubSrc  ScrubSource
}

// acceptEdits allows p, a permission mode of acceptEdits, but under the
// subprocess env scrub, which keeps the CLI in the default mode, where
// acceptEdits allows no edit (observed with claude-code-action 925afb53);
// an undecided scrub leaves it undecided, once, at what decides the scrub.
func (l *lists) acceptEdits(p ToolPermission) {
	switch l.scrub {
	case analysis.SubprocessScrubOn:
	case analysis.SubprocessScrubUndecided:
		q := ToolPermission{Input: l.scrubSrc.Input, Text: l.scrubSrc.Text, At: TextAt{Base: l.scrubSrc.At}}
		// one source of a scrub for a step: its input or its variable
		if !slices.ContainsFunc(l.undecided, func(u UndecidedPermission) bool { return u.Permission.Input == q.Input && u.Permission.Text == q.Text }) {
			l.undecide(analysis.InconclusiveAgentSetting, q)
		}
	default:
		l.allow = append(l.allow, p)
	}
}

func (l *lists) undecide(k analysis.InconclusiveAgentKind, p ToolPermission) {
	l.undecided = append(l.undecided, UndecidedPermission{Kind: k, Permission: p})
}

// whole is the permission of an input's value as a whole.
func whole(in input) ToolPermission {
	return ToolPermission{Input: in.name, Text: in.text, At: TextAt{Base: in.at}}
}

// exprSpans are the spans of the ${{ }} of v.
func exprSpans(v workflow.String) []expr.Span {
	var out []expr.Span
	for _, p := range v.Parts {
		if p.Expr {
			out = append(out, p.Span)
		}
	}
	return out
}

// overlaps is whether a span of exprs is in from..to.
func overlaps(from, to int, exprs []expr.Span) bool {
	return slices.ContainsFunc(exprs, func(e expr.Span) bool { return from < e.End && e.Start < to })
}

// add puts the elements es of the input in's value v in to: an element
// with a ${{ }} is undecided.
func (l *lists) add(to *[]ToolPermission, in analysis.AgentInput, v workflow.String, es []element) {
	exprs := exprSpans(v)
	for _, e := range es {
		p := ToolPermission{Input: in, Text: e.text, At: TextAt{Base: v.Base, Value: v, Span: e.span, Spanned: true}}
		if overlaps(e.span.Start, e.span.End, exprs) {
			l.undecide(analysis.InconclusiveAgentSetting, p)
			continue
		}
		*to = append(*to, p)
	}
}

// addStrings puts the strings xs of a JSON value at at in to: one with a
// ${{ }} is undecided.
func (l *lists) addStrings(to *[]ToolPermission, in analysis.AgentInput, xs []string, at TextAt) {
	for _, x := range xs {
		p := ToolPermission{Input: in, Text: x, At: at}
		if strings.Contains(x, "${{") {
			l.undecide(analysis.InconclusiveAgentSetting, p)
			continue
		}
		*to = append(*to, p)
	}
}

var (
	allowFlags = []string{"allowedTools", "allowed-tools"}
	denyFlags  = []string{"disallowedTools", "disallowed-tools"}
)

// claudeLists are the permissions of a step of claude-code-action or its
// base-action that runs on evs: the lists of claude_args
// and of the settings, and on a step claude-code-action may run in its tag
// mode, the tools the mode allows and its acceptEdits; acceptEdits as sc,
// the subprocess env scrub of src, lets it (lists.acceptEdits). A step
// that runs in neither mode starts no agent.
func claudeLists(s workflow.Step, a analysis.AgentAction, evs []analysis.EventActivity, sc analysis.SubprocessScrub, src ScrubSource) lists {
	l := lists{action: a, scrub: sc, scrubSrc: src}
	agentMode, tagMode := true, false
	if a == analysis.AgentActionClaudeCode {
		agentMode, tagMode = claudeModes(s, evs)
	}
	if !agentMode && !tagMode {
		return l
	}
	modeSet := false // a --permission-mode wins over defaultMode and the tag mode's
	switch args := inputOf(s, analysis.AgentInputClaudeArgs); {
	case args.whole:
		l.undecide(analysis.InconclusiveAgentSetting, whole(args))
	case args.present:
		modeSet = l.claudeArgs(args)
	}
	switch set := inputOf(s, analysis.AgentInputSettings); {
	case set.whole:
		l.undecide(analysis.InconclusiveAgentSetting, whole(set))
	case set.present:
		l.claudeSettings(strings.TrimSpace(set.value.Text()), whole(set), modeSet)
	}
	if tagMode {
		l.tagDefaults(s, modeSet)
	}
	if a == analysis.AgentActionClaudeCode {
		for _, p := range l.allow {
			if p.Input != analysis.AgentInputClaudeArgs {
				continue // the action runs its servers by claude_args alone
			}
			// the tag mode passes on only those that begin mcp__github_
			l.githubMCP = l.githubMCP || agentMode && p.Text == "mcp__github" || strings.HasPrefix(p.Text, "mcp__github__")
		}
	}
	return l
}

// claudeArgs reads the lists of claude_args, its inline --mcp-config,
// --settings and --permission-mode, and is whether it sets the mode. A
// ${{ }} in a flag's name or in a word of no flag leaves the input
// undecided, as it may become flags; one in an element of a list leaves
// that element undecided; one in the value of another flag is skipped.
func (l *lists) claudeArgs(in input) (modeSet bool) {
	v := in.value
	exprs := exprSpans(v)
	stripped, of := stripCommentsAt(v.Text())
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
			l.undecide(analysis.InconclusiveAgentSetting, whole(in))
			break
		}
	}
	for _, f := range r {
		key, joined, isJoined := strings.Cut(f.key, "=")
		to := &l.allow
		switch {
		case slices.Contains(allowFlags, key):
		case slices.Contains(denyFlags, key):
			to = &l.deny
		case key == "mcp-config":
			for _, i := range f.words[1:] {
				if w := ws[i]; len(w.at) > 0 && overlaps(w.at[0], w.at[len(w.at)-1]+1, exprs) {
					l.undecide(analysis.InconclusiveAgentSetting, whole(in)) // its servers are not known
				} else {
					l.servers = append(l.servers, mcpServers(w.text)...)
				}
			}
			continue
		default:
			continue
		}
		if isJoined {
			w := ws[f.words[0]]
			l.add(to, in.name, v, w.elements(len(w.text)-len(joined), true, exprs))
			continue
		}
		for _, i := range f.words[1:] {
			l.add(to, in.name, v, ws[i].elements(0, true, exprs))
		}
	}
	if m, ok := lastValue(r, "permission-mode"); ok {
		if strings.Contains(m, "${{") {
			l.undecide(analysis.InconclusiveAgentSetting, whole(in)) // the mode is not known
		} else {
			modeSet = true
			if m == "acceptEdits" {
				l.acceptEdits(ToolPermission{Input: in.name, Text: acceptEdits, At: TextAt{Base: in.at}})
			}
		}
	}
	if set, ok := lastValue(r, "settings"); ok {
		l.claudeSettings(set, whole(in), modeSet)
	}
	return modeSet
}

// claudeSettings reads permissions.allow, deny and defaultMode of the
// settings text, a JSON object whose keys are matched exactly as
// JSON.parse does; a file's path leaves them undecided.
func (l *lists) claudeSettings(text string, p ToolPermission, modeSet bool) {
	o, ok := jsonObject([]byte(text))
	if !ok {
		l.undecide(analysis.InconclusiveAgentSetting, p)
		return
	}
	allow, _ := stringsAt(o, "permissions", "allow")
	deny, _ := stringsAt(o, "permissions", "deny")
	l.addStrings(&l.allow, p.Input, allow, p.At)
	l.addStrings(&l.deny, p.Input, deny, p.At)
	if mode, _ := stringAt(o, "permissions", "defaultMode"); mode == "acceptEdits" && !modeSet {
		l.acceptEdits(ToolPermission{Input: p.Input, Text: acceptEdits, At: p.At})
	}
}

// tagDefaults are what claude-code-action's tag mode allows (its
// tag/index.ts): git through its wrapper of push, unless it
// commits through the API (use_commit_signing without ssh_signing_key),
// and acceptEdits, which a --permission-mode of claude_args replaces. Its
// tools to read and of its own MCP servers give no capability.
func (l *lists) tagDefaults(s workflow.Step, modeSet bool) {
	at := TextAt{Base: s.Uses.Value.Base}
	sign, key := inputOf(s, analysis.AgentInputUseCommitSigning), inputOf(s, analysis.AgentInputSSHSigningKey)
	v, signLit := sign.raw()
	k, keyLit := key.raw()
	api := signLit && v == "true" && (!key.present || keyLit && k == "")
	if !api {
		for _, t := range []string{"Bash(git add:*)", "Bash(git commit:*)", "Bash(" + gitPushWrapper + ":*)", "Bash(git rm:*)"} {
			l.allow = append(l.allow, ToolPermission{Text: t, At: at})
		}
	}
	if !modeSet {
		l.acceptEdits(ToolPermission{Text: acceptEdits, At: at})
	}
}

// claudeModes are the modes claude-code-action may run s in on evs
// (its detector.ts): tag with track_progress on an event
// of an issue or a pull request, or without a prompt on an event of an
// issue, a comment or a review, which a trigger in the payload starts;
// agent with a prompt. A ${{ }} may be either.
func claudeModes(s workflow.Step, evs []analysis.EventActivity) (agentMode, tagMode bool) {
	prompt, track := inputOf(s, analysis.AgentInputPrompt), inputOf(s, analysis.AgentInputTrackProgress)
	p, _ := prompt.raw()
	t, _ := track.raw()
	agentMode = prompt.dynamic || p != ""
	noPrompt := !prompt.present || prompt.whole || !prompt.dynamic && p == "" || prompt.dynamic && onlyExprs(prompt.value)
	tracks := track.dynamic || t == "true"
	for _, e := range evs {
		switch e.Name() {
		case workflow.EventNameIssues, workflow.EventNameIssueComment, workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment:
			tagMode = tagMode || noPrompt || tracks
		case workflow.EventNamePullRequest, workflow.EventNamePullRequestTarget:
			tagMode = tagMode || tracks
		}
	}
	return agentMode, tagMode
}

// claudeTagOn is whether claude-code-action surely runs s in its tag mode
// on e (its detector.ts): with track_progress true on an
// event of an issue or a pull request, or without a prompt on an event of
// an issue, a comment or a review.
func claudeTagOn(s workflow.Step, e analysis.EventActivity) bool {
	prompt, track := inputOf(s, analysis.AgentInputPrompt), inputOf(s, analysis.AgentInputTrackProgress)
	p, _ := prompt.raw()
	t, _ := track.raw()
	noPrompt := !prompt.present || !prompt.dynamic && p == ""
	tracks := !track.dynamic && t == "true"
	switch e.Name() {
	case workflow.EventNameIssues, workflow.EventNameIssueComment, workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment:
		return noPrompt || tracks
	case workflow.EventNamePullRequest, workflow.EventNamePullRequestTarget:
		return tracks
	}
	return false
}

// onlyExprs is whether v is ${{ }} and blanks: it may be empty.
func onlyExprs(v workflow.String) bool {
	t := v.Text()
	for _, p := range v.Parts {
		if !p.Expr && strings.TrimSpace(t[p.Span.Start:p.Span.End]) != "" {
			return false
		}
	}
	return true
}

// geminiLists are the permissions of a step of run-gemini-cli:
// tools.core of its settings, which gemini-cli v0.63.0 reads (not a
// coreTools at the top), less the bare names of tools.exclude; every tool
// without tools.core, as it runs with --yolo.
func geminiLists(s workflow.Step) lists {
	l := lists{action: analysis.AgentActionGeminiCLI, writesGit: true}
	in := inputOf(s, analysis.AgentInputSettings)
	at, name := TextAt{Base: s.Uses.Value.Base}, analysis.AgentInputUnset
	switch {
	case in.whole:
		l.undecide(analysis.InconclusiveAgentSetting, whole(in))
		return l
	case in.present:
		at, name = TextAt{Base: in.at}, in.name
		o, ok := jsonObject([]byte(in.value.Text()))
		if !ok {
			l.undecide(analysis.InconclusiveAgentSetting, whole(in))
			return l
		}
		exclude, _ := stringsAt(o, "tools", "exclude")
		for _, x := range exclude {
			if !strings.Contains(x, "(") { // a command in it stops nothing
				l.deny = append(l.deny, ToolPermission{Input: name, Text: x, At: at})
			}
		}
		if core, found := stringsAt(o, "tools", "core"); found {
			l.addStrings(&l.allow, name, core, at)
			return l
		}
	}
	for _, t := range []string{"run_shell_command", "write_file", "web_fetch"} {
		l.allow = append(l.allow, ToolPermission{Input: name, Text: t, At: at})
	}
	return l
}

// copilotLists are the permissions of a step of ai-inference: the elements
// of copilot-allow-tools, which it splits at commas. Without
// them the Copilot CLI only reads.
func copilotLists(s workflow.Step) lists {
	l := lists{action: analysis.AgentActionAIInference, writesGit: true}
	switch in := inputOf(s, analysis.AgentInputCopilotAllowTools); {
	case in.whole:
		l.undecide(analysis.InconclusiveAgentSetting, whole(in))
	case in.present:
		l.add(&l.allow, in.name, in.value, plainWord(in.value.Text()).elements(0, false, nil))
	}
	return l
}

// jsonObject is raw as a JSON object, its keys as JSON.parse keeps them
// (the last of a key written twice).
func jsonObject(raw []byte) (map[string]json.RawMessage, bool) {
	var o map[string]json.RawMessage
	if json.Unmarshal(raw, &o) != nil || o == nil {
		return nil, false
	}
	return o, true
}

// stringsAt are the strings of the array at path of o; found is whether
// there is something at path.
func stringsAt(o map[string]json.RawMessage, path ...string) (out []string, found bool) {
	raw, ok := valueAt(o, path...)
	if !ok {
		return nil, false
	}
	var xs []json.RawMessage
	if json.Unmarshal(raw, &xs) != nil {
		return nil, true
	}
	for _, x := range xs {
		var s string
		if json.Unmarshal(x, &s) == nil {
			out = append(out, s)
		}
	}
	return out, true
}

// stringAt is the string at path of o.
func stringAt(o map[string]json.RawMessage, path ...string) (string, bool) {
	raw, ok := valueAt(o, path...)
	var s string
	if !ok || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func valueAt(o map[string]json.RawMessage, path ...string) (json.RawMessage, bool) {
	for i, k := range path {
		raw, ok := o[k]
		if !ok {
			return nil, false
		}
		if i == len(path)-1 {
			return raw, true
		}
		if o, ok = jsonObject(raw); !ok {
			return nil, false
		}
	}
	return nil, false
}

// mcpServers are the servers of an inline --mcp-config: the keys of its
// mcpServers; none for a file's path.
func mcpServers(text string) []string {
	o, ok := jsonObject([]byte(text))
	if !ok {
		return nil
	}
	s, ok := jsonObject(o["mcpServers"])
	if !ok {
		return nil
	}
	var out []string
	for k := range s {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
