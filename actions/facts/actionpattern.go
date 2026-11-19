package facts

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ActionPattern is a pattern of repo.action-list ($defs/action-pattern):
// one uses that the repository allows, written as the uses is written
// (owner/repo@ref, owner/repo/path@ref, docker://image), where * stands
// for any characters, / and @ among them. A pattern that starts with !
// blocks. A pattern without ! compares the owner and the name of the
// repository before its first * without case, as GitHub compares them, and
// the rest as written; a pattern with ! compares the whole uses without
// case, so that a * before the name does not let a uses past the block. The text is kept as written: a Condition compares the answer
// with the value as JSON, so a pattern written back in another form would
// not be the answer. The zero ActionPattern is none.
type ActionPattern struct {
	s  string
	re *regexp.Regexp // the pattern without its !, as a regular expression of the whole uses
}

var actionPatternText = regexp.MustCompile(`^!?[^\s,!][^\s,]*$`)

// ParseActionPattern reads a pattern: no white space, no comma, and not
// empty, not ! alone and not !! at the start.
func ParseActionPattern(s string) (ActionPattern, error) {
	if !actionPatternText.MatchString(s) {
		return ActionPattern{}, fmt.Errorf("%q is not a pattern of repo.action-list: a pattern has the form of a value of uses, may have * for any characters and a ! at the start to block, and has no white space and no comma (write each pattern of a comma-separated list of the settings of GitHub as a separate pattern)", s)
	}
	body, flags := foldRepositoryPattern(s), `(?s)`
	if strings.HasPrefix(s, "!") {
		body, flags = s[1:], `(?is)`
	}
	return ActionPattern{s, wholeUses(flags, body)}, nil
}

// wholeUses is the regular expression of a pattern of uses, body without
// its !, that matches the whole of a uses, each * matching any characters,
// with the flags (?s) or (?is).
func wholeUses(flags, body string) *regexp.Regexp {
	parts := strings.Split(body, "*")
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	return regexp.MustCompile(flags + `^` + strings.Join(parts, ".*") + `$`)
}

// MustActionPattern is ParseActionPattern that panics on an error.
func MustActionPattern(s string) ActionPattern {
	p, err := ParseActionPattern(s)
	if err != nil {
		panic(err)
	}
	return p
}

func (p ActionPattern) String() string { return p.s }

// blocks is whether p starts with !.
func (p ActionPattern) blocks() bool { return strings.HasPrefix(p.s, "!") }

// matches is whether p, without its !, matches the whole of uses, *
// matching any characters: a pattern without ! with the owner and the name
// of the repository in any case, a pattern with ! in any case throughout.
func (p ActionPattern) matches(uses string) bool {
	if p.blocks() {
		return p.re != nil && p.re.MatchString(uses)
	}
	return p.re != nil && p.re.MatchString(foldRepository(uses))
}

// foldRepositoryPattern is the pattern s with owner/repo in lower case,
// as foldRepository writes a uses, up to the first *: a * may stand for
// the end of owner/repo and for a part of the path, so the letters after
// it are compared as written.
func foldRepositoryPattern(s string) string {
	end := len(s)
	if i := strings.IndexByte(s, '*'); i >= 0 {
		end = i
	}
	return foldRepository(s[:end]) + s[end:]
}

// foldRepository is s with owner/repo, the text before the second / or
// before the @ when it comes first, in lower case; a uses of a Docker image
// (docker://) is as written.
func foldRepository(s string) string {
	if strings.HasPrefix(s, "docker://") {
		return s
	}
	end := len(s)
	if i := strings.IndexByte(s, '@'); i >= 0 {
		end = i
	}
	if i := strings.IndexByte(s, '/'); i >= 0 && i < end {
		if j := strings.IndexByte(s[i+1:], '/'); j >= 0 && i+1+j < end {
			end = i + 1 + j
		}
	}
	return strings.ToLower(s[:end]) + s[end:]
}

// ActionListAllows is whether list allows uses: some pattern without !
// matches uses, and no pattern with ! does, whatever their order. An empty
// list allows nothing. uses is as GitHub reads it: owner/repo[/path]@ref,
// or docker:// and the image as written.
func ActionListAllows(list []ActionPattern, uses string) bool {
	allowed := false
	for _, p := range list {
		if !p.matches(uses) {
			continue
		}
		if p.blocks() {
			return false
		}
		allowed = true
	}
	return allowed
}

func (p ActionPattern) MarshalJSON() ([]byte, error) {
	if p.s == "" {
		return nil, errors.New("the zero ActionPattern is no pattern")
	}
	return json.Marshal(p.s)
}

func (p *ActionPattern) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseActionPattern(s)
	if err != nil {
		return err
	}
	*p = v
	return nil
}
