package artifact

import (
	"path"
	"slices"
	"strings"
)

// pattern is a line of an upload's path: its parts from the workspace,
// whether it leaves out what it matches (!), and whether it ends in /,
// which @actions/glob matches with a directory only ("Trailing slash
// indicates the pattern should only match directories, not regular files",
// https://github.com/actions/toolkit/blob/7e25f67e8fd17369aa21e6e816ac99654106e0dc/packages/glob/src/internal-pattern.ts).
type pattern struct {
	exclude bool
	dirOnly bool
	segs    []string
}

// parsePattern reads a line of path as @actions/glob does: white space
// around it and an empty line or a comment (#) are nothing; ! excludes. ok
// is false for a line that is not a path of the workspace: absolute, or
// from the home. fails is whether @actions/glob refuses it, which fails the
// upload: a part .. anywhere, or . but first (fixupPattern of @actions/glob).
func parsePattern(line string) (p pattern, skip, ok, fails bool) {
	l := strings.TrimSpace(line)
	if l == "" || strings.HasPrefix(l, "#") {
		return pattern{}, true, true, false
	}
	if strings.HasPrefix(l, "!") {
		p.exclude, l = true, strings.TrimSpace(l[1:])
	}
	for i, seg := range strings.Split(l, "/") {
		if seg == ".." || seg == "." && i > 0 {
			return pattern{}, false, true, true
		}
	}
	if strings.HasPrefix(l, "/") || strings.HasPrefix(l, "~") {
		return pattern{}, false, false, false
	}
	p.dirOnly = strings.HasSuffix(l, "/")
	p.segs = parts(l)
	return p, false, true, false
}

func hasMeta(seg string) bool { return strings.ContainsAny(seg, "*?[") }

// match is whether the pattern segs matches the path file, both in parts:
// ** is any parts, any other part is path.Match (minimatch with dot).
func match(segs, file []string) bool {
	if len(segs) == 0 {
		return len(file) == 0
	}
	if segs[0] == "**" {
		for i := 0; i <= len(file); i++ {
			if match(segs[1:], file[i:]) {
				return true
			}
		}
		return false
	}
	if len(file) == 0 {
		return false
	}
	ok, err := path.Match(segs[0], file[0])
	return err == nil && ok && match(segs[1:], file[1:])
}

// matches is whether p takes file: it matches file or a directory above
// it, which takes what is under it; a pattern of a directory only does
// not match file itself. A file above the workspace is taken only by a
// pattern that goes up to it.
func matches(p pattern, file []string) (bool, int) {
	if len(file) > 0 && file[0] == ".." && (len(p.segs) == 0 || p.segs[0] != "..") {
		return false, 0
	}
	last := len(file)
	if p.dirOnly {
		last-- // file itself is no directory
	}
	for k := 0; k <= last; k++ {
		if match(p.segs, file[:k]) {
			return true, k
		}
	}
	return false, 0
}

// root is the parts of p before its first part with a glob character: the
// root of the search.
func (p pattern) root() []string {
	for i, s := range p.segs {
		if hasMeta(s) {
			return p.segs[:i]
		}
	}
	return p.segs
}

// leftOut is whether, without hidden files, the search leaves file out:
// the search starts at root, the highest root of the lines that take (a
// root under another is not searched again, getSearchPaths), and leaves
// out an item whose name starts with a dot, root included.
func leftOut(root, file []string) bool {
	if n := len(root); n > 0 && strings.HasPrefix(root[n-1], ".") {
		return true
	}
	for _, s := range file[min(len(root), len(file)):] {
		if strings.HasPrefix(s, ".") {
			return true
		}
	}
	return false
}

// under is whether the parts a are b or under it.
func under(a, b []string) bool { return len(a) >= len(b) && slices.Equal(a[:len(b)], b) }

// globLines are the lines of path read once, for takes: the patterns,
// the roots of those that take, and whether a line @actions/glob refuses
// fails the upload.
type globLines struct {
	ps    []pattern
	roots [][]string
	fails bool
}

// parseLines reads the lines of path for takes.
func parseLines(lines []string) globLines {
	var g globLines
	for _, l := range lines {
		p, skip, ok, fails := parsePattern(l)
		switch {
		case fails:
			return globLines{fails: true}
		case skip || !ok:
			continue
		}
		g.ps = append(g.ps, p)
		if !p.exclude {
			g.roots = append(g.roots, p.root())
		}
	}
	return g
}

// takes is whether the lines g take file, hidden files taken or not. The
// lines are folded in order, as @actions/glob does: a line that takes it
// takes it, a line of ! that matches it leaves it out, and a later line
// wins. A line @actions/glob refuses fails the upload, which then takes
// nothing.
func (g globLines) takes(file []string, hidden bool) bool {
	if g.fails {
		return false
	}
	in := false
	temp := len(file) > 0 && file[0] == runnerTempRoot
	for _, p := range g.ps {
		if r := p.root(); temp != (len(r) > 0 && r[0] == runnerTempRoot) {
			continue // a file of RUNNER_TEMP is taken only by a line under ${{ runner.temp }}, and only such a file
		}
		if m, _ := matches(p, file); !m {
			continue
		}
		if p.exclude {
			in = false
			continue
		}
		root := p.root()
		for _, r := range g.roots {
			if under(root, r) && len(r) < len(root) {
				root = r
			}
		}
		if hidden || !leftOut(root, file) {
			in = true
		}
	}
	return in
}
