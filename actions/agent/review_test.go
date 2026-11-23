package agent

import (
	"slices"
	"testing"
)

// claudeWith is a step of claude-code-action whose with is the YAML with,
// written at the indent of a with's entries.
func claudeWith(with string) string {
	return "uses: anthropics/claude-code-action@v1\n        with:\n" + with
}

func codexWith(with string) string {
	return "uses: openai/codex-action@v1\n        with:\n" + with
}

// TestOfArgsAsTheActionsRead: readings each checked against the action's
// source:
// --settings in claude_args, shell-quote's comment, the record of
// claude_args whose keys keep their first place, the exact keys of the
// settings' JSON, a token not trimmed, and codex's inputs not trimmed and
// split by string-argv.
func TestOfArgsAsTheActionsRead(t *testing.T) {
	for _, c := range []struct {
		name, step string
		gates      []string
		set, inc   []string
	}{
		{"a blank token is a token", claudeWith(`          allowed_non_write_users: "*"
          github_token: " "
`), []string{"any-user allowed_non_write_users"}, nil, nil},
		{"settings flag", claudeWith(`          claude_args: |
            --settings '{"permissions": {"defaultMode": "bypassPermissions"}}'
`), nil, []string{"commands claude_args bypassPermissions"}, nil},
		{"settings flag equals", claudeWith(`          claude_args: --settings='{"permissions":{"defaultMode":"bypassPermissions"}}'
`), nil, []string{"commands claude_args bypassPermissions"}, nil},
		{"settings flag file", claudeWith(`          claude_args: --settings .claude/ci.json
`), nil, nil, []string{"setting-expr claude_args"}},
		{"comment ends the args", claudeWith(`          claude_args: |
            --permission-mode bypassPermissions # keep
            --permission-mode default
`), nil, []string{"commands claude_args bypassPermissions"}, nil},
		{"comment hides a flag", claudeWith(`          claude_args: |
            --model x # pick
            --dangerously-skip-permissions
`), nil, nil, nil},
		{"mode equals after", claudeWith(`          claude_args: --permission-mode bypassPermissions --permission-mode=default
`), nil, nil, nil},
		{"mode equals before: the mode decides", claudeWith(`          claude_args: --permission-mode=default --permission-mode bypassPermissions
`), nil, nil, []string{"setting-expr claude_args"}},
		{"mode equals both bypass", claudeWith(`          claude_args: --permission-mode=bypassPermissions --permission-mode bypassPermissions
`), nil, []string{"commands claude_args bypassPermissions"}, nil},
		{"settings keys are exact", claudeWith(`          settings: '{"Permissions": {"DefaultMode": "bypassPermissions"}}'
`), nil, nil, nil},
		{"settings key of another case", claudeWith(`          settings: '{"permissions": {"defaultMode": "bypassPermissions", "DEFAULTMODE": "default"}}'
`), nil, []string{"commands settings bypassPermissions"}, nil},
		{"codex strategy is not trimmed", codexWith(`          safety-strategy: " unsafe"
`), nil, nil, nil},
		{"codex args are not trimmed", codexWith(`          codex-args: ' ["--yolo"]'
`), nil, nil, nil},
		{"codex args quoted", codexWith(`          codex-args: '"a\" --yolo"'
`), nil, []string{"commands codex-args --yolo"}, nil},
		{"codex args backslash", codexWith(`          codex-args: '\--yolo'
`), nil, nil, nil},
		{"codex args quote inside", codexWith(`          codex-args: --y'o'lo
`), nil, nil, nil},
	} {
		s, _ := Of(stepOf(t, c.step))
		if !slices.Equal(gates(s), c.gates) || !slices.Equal(settings(s), c.set) || !slices.Equal(inconclusive(s), c.inc) {
			t.Errorf("%s: gates %q, settings %q, inconclusive %q", c.name, gates(s), settings(s), inconclusive(s))
		}
	}
}

// TestWordsComment: an unquoted # ends what shell-quote's parse gives as
// words: the rest is a comment, which claude-code-action drops.
func TestWordsComment(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"a#b --c", []string{"a"}},
		{"--p bypass # keep\n--p default", []string{"--p", "bypass"}},
		{"'#' --d", []string{"#", "--d"}},
	} {
		if got := words(c.in); !slices.Equal(got, c.want) {
			t.Errorf("%q: %q, want %q", c.in, got, c.want)
		}
	}
}

// TestArgv: string-argv 0.3.2's parseArgsStringToArgv, which codex-action
// splits codex-args with: a word wholly in quotes loses
// them, quotes inside a word stay, and a backslash is a letter.
func TestArgv(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"--a 'b c'", []string{"--a", "b c"}},
		{`"a\" --yolo"`, []string{`a\`, "--yolo"}},
		{`\--yolo`, []string{`\--yolo`}},
		{"--y'o'lo", []string{"--y'o'lo"}},
		{`--x="a b"`, []string{`--x="a b"`}},
		{`["--yolo"]`, []string{`["--yolo"]`}},
		{"'unclosed --yolo", []string{"unclosed", "--yolo"}},
		{"''", []string{""}},
		{"", nil},
	} {
		if got := argv(c.in); !slices.Equal(got, c.want) {
			t.Errorf("%q: %q, want %q", c.in, got, c.want)
		}
	}
}

// TestOfSettingsTheActionIgnores: settings the action or the CLI does not
// use: codex takes the read-only strategy
// over a profile, and a profile over the sandbox;
// claude's --permission-mode overrides the defaultMode of settings
// (Claude Code's CLI reference).
func TestOfSettingsTheActionIgnores(t *testing.T) {
	for _, c := range []struct {
		name, step string
		set        []string
	}{
		{"read-only over the sandbox", codexWith(`          safety-strategy: read-only
          sandbox: danger-full-access
`), nil},
		{"read-only over the profile", codexWith(`          safety-strategy: read-only
          permission-profile: ":danger-full-access"
`), nil},
		{"a profile over the sandbox", codexWith(`          permission-profile: ":workspace"
          sandbox: danger-full-access
`), nil},
		{"the profile is used", codexWith(`          permission-profile: ":danger-full-access"
          sandbox: workspace-write
`), []string{"commands permission-profile :danger-full-access"}},
		{"a mode over settings", "uses: anthropics/claude-code-action/base-action@v1\n        with:\n" + `          claude_args: --permission-mode acceptEdits
          settings: '{"permissions":{"defaultMode":"bypassPermissions"}}'
`, nil},
		{"a mode over --settings", "uses: anthropics/claude-code-action/base-action@v1\n        with:\n" + `          claude_args: --permission-mode acceptEdits --settings='{"permissions":{"defaultMode":"bypassPermissions"}}'
`, nil},
		{"settings without a mode", "uses: anthropics/claude-code-action/base-action@v1\n        with:\n" + `          settings: '{"permissions":{"defaultMode":"bypassPermissions"}}'
`, []string{"commands settings bypassPermissions"}},
	} {
		s, _ := Of(stepOf(t, c.step))
		if !slices.Equal(settings(s), c.set) {
			t.Errorf("%s: settings %q", c.name, settings(s))
		}
	}
}
