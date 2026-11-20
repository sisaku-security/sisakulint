package lint

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// SourceFile is a file of a public repository on GitHub at one commit,
// whose steps an example reproduces when no advisory reports the form: what
// an example of a case found in a repository cites (# source: <URL>). Only
// ParseSourceFile makes one.
type SourceFile struct {
	repo facts.Repo
	sha  facts.SHA
	path string // the path of the file in the repository, with no leading /
	url  Citation
}

func (s SourceFile) Repo() facts.Repo { return s.repo }
func (s SourceFile) SHA() facts.SHA   { return s.sha }
func (s SourceFile) Path() string     { return s.path }
func (s SourceFile) URL() Citation    { return s.url }

// Key is what tells two source files apart: the repository and the path,
// as owner/repository:path. Two commits of one file have one key.
func (s SourceFile) Key() string { return s.repo.String() + ":" + s.path }

// MarshalJSON writes the URL.
func (s SourceFile) MarshalJSON() ([]byte, error) { return json.Marshal(s.url.s) }

// ParseSourceFile reads https://github.com/<owner>/<repository>/blob/<a
// commit, 40 or 64 hexadecimal digits>/<path>, and at most one fragment of
// lines: #L<n> or #L<n>-L<m>, with n ≤ m. A branch or a tag in place of the
// commit is an error, as the file it names moves. There is no query.
func ParseSourceFile(s string) (SourceFile, error) {
	bad := func(why string) (SourceFile, error) {
		return SourceFile{}, fmt.Errorf("%q is not https://github.com/<owner>/<repository>/blob/<commit>/<path>: %s", s, why)
	}
	c, err := ParseCitation(s)
	if err != nil {
		return SourceFile{}, err
	}
	u, err := url.Parse(s)
	if err != nil || u.Host != "github.com" || u.RawQuery != "" || strings.Contains(s, "?") {
		return bad("the host is not github.com, or it has a query")
	}
	if u.Fragment != "" && !linesFragment(u.Fragment) {
		return bad("the fragment is not #L<n> or #L<n>-L<m>")
	}
	parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 5)
	if len(parts) != 5 || parts[2] != "blob" || parts[4] == "" || strings.HasSuffix(parts[4], "/") {
		return bad("no blob and path")
	}
	repo, err := facts.ParseRepo(parts[0] + "/" + parts[1])
	if err != nil {
		return bad(err.Error())
	}
	sha, err := facts.ParseSHA(parts[3])
	if err != nil {
		return bad("the commit is not 40 or 64 hexadecimal digits (a branch or a tag moves)")
	}
	return SourceFile{repo, sha, parts[4], c}, nil
}

// MustSourceFile is ParseSourceFile that panics on an error.
func MustSourceFile(s string) SourceFile { return must(ParseSourceFile(s)) }

// linesFragment is whether f is L<n> or L<n>-L<m>, with 0 < n ≤ m.
func linesFragment(f string) bool {
	line := func(s string) (int, bool) {
		d, ok := strings.CutPrefix(s, "L")
		if !ok || d == "" || d[0] == '0' || strings.ContainsFunc(d, func(r rune) bool { return r < '0' || r > '9' }) {
			return 0, false
		}
		n, err := strconv.Atoi(d)
		return n, err == nil
	}
	a, b, two := strings.Cut(f, "-")
	n, ok := line(a)
	if !ok {
		return false
	}
	if !two {
		return true
	}
	m, ok := line(b)
	return ok && n <= m
}
