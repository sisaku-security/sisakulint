package core

import "testing"

func TestApplyGitHubScriptReplacements_StripsStringLiteralQuotes(t *testing.T) {
	replacements := map[string]string{
		"${{ github.event.issue.body }}":   "process.env.ISSUE_BODY",
		"${{ github.event.comment.body }}": "process.env.COMMENT_BODY",
	}

	tests := []struct {
		name   string
		script string
		want   string
	}{
		{
			name:   "single quoted exact expression",
			script: `fetch('${{ github.event.issue.body }}')`,
			want:   `fetch(process.env.ISSUE_BODY)`,
		},
		{
			name:   "double quoted exact expression",
			script: `axios.get("${{ github.event.comment.body }}")`,
			want:   `axios.get(process.env.COMMENT_BODY)`,
		},
		{
			name:   "embedded expression preserves surrounding text",
			script: `console.log('Comment: ${{ github.event.comment.body }}')`,
			want:   `console.log('Comment: ' + process.env.COMMENT_BODY)`,
		},
		{
			name:   "multiple expressions in one string literal",
			script: `console.log('${{ github.event.issue.body }} / ${{ github.event.comment.body }}')`,
			want:   `console.log(process.env.ISSUE_BODY + ' / ' + process.env.COMMENT_BODY)`,
		},
		{
			name:   "unquoted expression remains a direct replacement",
			script: `console.log(${{ github.event.comment.body }})`,
			want:   `console.log(process.env.COMMENT_BODY)`,
		},
		{
			name: "single quote in line comment does not hide later string literal",
			script: `// user's supplied URL
fetch('${{ github.event.issue.body }}')`,
			want: `// user's supplied URL
fetch(process.env.ISSUE_BODY)`,
		},
		{
			name:   "object literal key becomes computed property key",
			script: `const headers = { '${{ github.event.issue.body }}': 'x' }`,
			want:   `const headers = { [process.env.ISSUE_BODY]: 'x' }`,
		},
		{
			name:   "embedded object literal key becomes computed property key",
			script: `const headers = { 'prefix-${{ github.event.issue.body }}': 'x' }`,
			want:   `const headers = { ['prefix-' + process.env.ISSUE_BODY]: 'x' }`,
		},
		{
			name:   "object literal method name becomes computed method name",
			script: `const handlers = { '${{ github.event.issue.body }}'() {} }`,
			want:   `const handlers = { [process.env.ISSUE_BODY]() {} }`,
		},
		{
			name:   "embedded object literal method name becomes computed method name",
			script: `const handlers = { 'prefix-${{ github.event.issue.body }}'() {} }`,
			want:   `const handlers = { ['prefix-' + process.env.ISSUE_BODY]() {} }`,
		},
		{
			name:   "class method name becomes computed method name",
			script: `class Handler { '${{ github.event.issue.body }}'() {} }`,
			want:   `class Handler { [process.env.ISSUE_BODY]() {} }`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyGitHubScriptReplacements(tt.script, replacements)
			if got != tt.want {
				t.Fatalf("applyGitHubScriptReplacements() = %q, want %q", got, tt.want)
			}
		})
	}
}
