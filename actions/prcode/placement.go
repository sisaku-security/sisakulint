package prcode

import (
	"path"
	"strings"
)

// placementBase is the directory a Placement is under.
type placementBase uint8

const (
	baseWorkspace  placementBase = iota // github.workspace
	baseRunnerTemp                      // runner.temp, a directory out of the workspace
)

// relDir is a directory under a base: a cleaned relative path that does
// not leave the base (. is the base itself), or any directory under it
// when the path is not known.
type relDir struct {
	path  string
	known bool
}

// relDirOf is the directory p under a base: p cleaned, or any directory
// when p is absolute or leaves the base by ..
func relDirOf(p string) relDir {
	c := path.Clean(p)
	if path.IsAbs(c) || c == ".." || strings.HasPrefix(c, "../") {
		return anyDir()
	}
	return relDir{path: c, known: true}
}

// anyDir is any directory under a base.
func anyDir() relDir { return relDir{} }

// holds is whether the relative path p may be in d: always when d is not
// known or is the base itself.
func (d relDir) holds(p string) bool {
	if !d.known {
		return true
	}
	return under(p, d.path)
}

func (d relDir) String() string {
	if !d.known {
		return "*"
	}
	return d.path
}

// Placement is where a step puts files: a directory under the workspace
// or under runner.temp.
type Placement struct {
	base placementBase
	dir  relDir
}

func workspacePlacement(d relDir) Placement  { return Placement{base: baseWorkspace, dir: d} }
func runnerTempPlacement(d relDir) Placement { return Placement{base: baseRunnerTemp, dir: d} }

// InWorkspace is whether p is under the workspace.
func (p Placement) InWorkspace() bool { return p.base == baseWorkspace }

// Dir is the directory of p under its base, and whether it is known.
func (p Placement) Dir() (rel string, known bool) { return p.dir.path, p.dir.known }

func (p Placement) String() string {
	if p.base == baseRunnerTemp {
		return "runner.temp:" + p.dir.String()
	}
	return "workspace:" + p.dir.String()
}
