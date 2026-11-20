// Package ident is how the names of the schemas are checked and written in
// Go, by actions/lint and by the generators that read the schemas.
package ident

import (
	"regexp"
	"strings"
)

var kebab = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// IsKebab is whether s is kebab-case: lower-case letters and digits in
// parts joined by -, starting with a letter.
func IsKebab(s string) bool { return kebab.MatchString(s) }

var snake = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// IsSnake is whether s is snake_case: lower-case letters and digits in
// parts joined by _, starting with a letter, as the keys of the JSON are.
func IsSnake(s string) bool { return snake.MatchString(s) }

// initialisms are the parts Go writes in capitals.
var initialisms = map[string]string{"ai": "AI", "api": "API", "pr": "PR", "id": "ID", "sha": "SHA", "url": "URL", "github": "GitHub", "ghsa": "GHSA", "json": "JSON"}

// GoName is the Go name of s, whose parts are joined by ., - or _:
// fork-pr-author is ForkPRAuthor, test.repo-flag is TestRepoFlag, sha is
// SHA.
func GoName(s string) string {
	var b strings.Builder
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r == '_' }) {
		if w, ok := initialisms[part]; ok {
			b.WriteString(w)
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}
