package repofile

import (
	"path"
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/facts"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/scalar"
)

// dependabotFiles are the names Dependabot reads its configuration from,
// in the order its engine tries them (common/lib/dependabot/config/file_fetcher.rb of
// https://github.com/dependabot/dependabot-core/tree/fda701f49c7d6ba5807e98a06549fdb935e3bd2e).
var dependabotFiles = []string{".github/dependabot.yml", ".github/dependabot.yaml"}

// workflowsDir is where the directory / of github-actions reads workflows.
const workflowsDir = ".github/workflows"

// dependabotVersionUpdates answers q from the configuration of Dependabot.
func (r resolver) dependabotVersionUpdates(q facts.DependabotVersionUpdates) facts.RawAnswer {
	var text []byte
	name := ""
	for _, n := range dependabotFiles {
		b, ok, err := r.readFile(n)
		if err != nil {
			return unknown("reading " + n + ": " + err.Error())
		}
		if !ok {
			continue
		}
		if name != "" {
			return unknown("both " + name + " and " + n + " are there: which one Dependabot reads is not known")
		}
		name, text = n, b
	}
	if name == "" {
		return found(false)
	}
	t := cst.ParseMode(text, cst.ModeGitHub)
	if len(t.Errors()) != 0 {
		return unknown(name + " is not YAML that can be read")
	}
	top, ok := documentMapping(t)
	if !ok {
		return unknown(name + " is not a mapping")
	}
	updates, present := entryValue(top, "updates")
	if !present {
		return found(false)
	}
	seq, ok := updates.Sequence()
	if !ok {
		return unknown(name + ": updates is not a sequence")
	}
	why := ""
	for item := range seq.Items() {
		entry, ok := item.Mapping()
		if !ok {
			return unknown(name + ": an entry of updates is not a mapping")
		}
		if eco, _ := scalarText(entry, "package-ecosystem"); eco != q.PackageEcosystem.String() {
			continue
		}
		reads, reason := entryReads(entry, q.InputPath.String())
		switch {
		case reads && reason == "":
			return found(true)
		case reason != "":
			why = reason
		}
	}
	if why != "" {
		return unknown(name + ": " + why)
	}
	return found(false)
}

// entryReads is whether entry, of the ecosystem asked about, reads the
// file p: reason is why that is not known, when it is not.
func entryReads(entry cst.Mapping, p string) (reads bool, reason string) {
	var dirs, globs []string
	if d, ok := scalarText(entry, "directory"); ok {
		dirs = append(dirs, d) // a glob is not one in directory (dependabot-options-reference.md)
	}
	if v, present := entryValue(entry, "directories"); present {
		seq, ok := v.Sequence()
		if !ok {
			return false, "directories is not a sequence"
		}
		for item := range seq.Items() {
			s, ok := scalar.Decode(item)
			if !ok {
				return false, "a value of directories is not a string"
			}
			if strings.ContainsAny(s.String(), "*?[{") {
				globs = append(globs, s.String())
			} else {
				dirs = append(dirs, s.String())
			}
		}
	}
	reads = slices.ContainsFunc(dirs, func(d string) bool { return directoryReads(d, p) })
	if !reads {
		if len(globs) > 0 { // whether a glob of directories works for github-actions is not known
			return false, "a glob in directories, which is not known to work for github-actions"
		}
		return false, ""
	}
	if limit, ok := scalarText(entry, "open-pull-requests-limit"); ok && strings.TrimSpace(limit) == "0" {
		return false, ""
	}
	for _, k := range []string{"target-branch", "exclude-paths", "allow"} {
		if _, present := entryValue(entry, k); present {
			return false, "the entry has " + k + ", which the rule does not read"
		}
	}
	if ignoresByPattern(entry) {
		return false, "the entry ignores a dependency-name with *, which may be every action"
	}
	return true, ""
}

// directoryReads is whether the directory d of an entry of github-actions
// reads the file p (github_actions/lib/dependabot/github_actions/file_fetcher.rb
// of dependabot-core fda701f4).
func directoryReads(d, p string) bool {
	d = strings.Trim(d, "/")
	dir, base := path.Split(p)
	dir = strings.TrimSuffix(dir, "/")
	yaml := strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")
	if d == "" {
		return (dir == workflowsDir && yaml) || p == "action.yml" || p == "action.yaml"
	}
	return dir == d && yaml
}

// ignoresByPattern is whether the ignore of entry has a dependency-name
// with *.
func ignoresByPattern(entry cst.Mapping) bool {
	v, present := entryValue(entry, "ignore")
	if !present {
		return false
	}
	seq, ok := v.Sequence()
	if !ok {
		return false
	}
	for item := range seq.Items() {
		m, ok := item.Mapping()
		if !ok {
			continue
		}
		if n, _ := scalarText(m, "dependency-name"); strings.Contains(n, "*") {
			return true
		}
	}
	return false
}

// documentMapping is the mapping at the top of the first document of t.
func documentMapping(t *cst.Tree) (cst.Mapping, bool) {
	for e := range t.Root().Children() {
		d, ok := e.Node()
		if !ok || d.Kind() != cst.NodeDocument {
			continue
		}
		for c := range d.Children() {
			if n, ok := c.Node(); ok && n.Kind() != cst.NodeDirective {
				return n.Mapping()
			}
		}
	}
	return cst.Mapping{}, false
}

// entryValue is the value of the key k of m.
func entryValue(m cst.Mapping, k string) (cst.Node, bool) {
	for e := range m.Entries() {
		if s, ok := scalar.Decode(e.Key); ok && s.String() == k {
			return e.Value, true
		}
	}
	return cst.Node{}, false
}

// scalarText is the text of the scalar value of the key k of m.
func scalarText(m cst.Mapping, k string) (string, bool) {
	v, present := entryValue(m, k)
	if !present {
		return "", false
	}
	s, ok := scalar.Decode(v)
	if !ok {
		return "", false
	}
	return s.String(), true
}
