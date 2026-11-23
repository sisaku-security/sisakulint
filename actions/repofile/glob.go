package repofile

import (
	"path"
	"strings"
)

// globMatch is whether the path p, / separated, matches pattern, a glob of
// *, ? and ** (any number of whole parts). ok is false for a pattern with
// another character of globs of minimatch ([, {, !, the extglobs with
// ( and the escape \\), which is not read.
func globMatch(pattern, p string) (match, ok bool) {
	if strings.ContainsAny(pattern, "[{!()\\") {
		return false, false
	}
	return matchParts(strings.Split(pattern, "/"), strings.Split(p, "/")), true
}

func matchParts(pat, parts []string) bool {
	if len(pat) == 0 {
		return len(parts) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(parts); i++ {
			if matchParts(pat[1:], parts[i:]) {
				return true
			}
		}
		return false
	}
	if len(parts) == 0 {
		return false
	}
	if ok, err := path.Match(pat[0], parts[0]); err != nil || !ok {
		return false
	}
	return matchParts(pat[1:], parts[1:])
}
