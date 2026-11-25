package labeler

import (
	"io/fs"

	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/facts"
)

// Table are the steps of the workflows of a repository that run
// actions/labeler on the pull request of an attacker with a token other
// than the GITHUB_TOKEN.
type Table struct {
	steps []Step
}

// Read is the table of the workflows and composite actions of files, the
// whole repository of root, each read on the chains of calls that run it
// (chainsOf); a configuration under a path excluded is not read. A nil root (the
// inputs are not the whole repository) has no steps.
func Read(files []calls.File, root fs.FS, excluded func(facts.InputPath) bool) *Table {
	return ReadIn(attacker.Outsider, facts.Repo{}, files, root, excluded)
}

// ReadIn is Read, with the ifs read in the attacker run table at, for
// the files of repo: a uses: owner/repo/path@ref of another repository
// runs that repository's file, not the input at path (calls.New). The
// zero Repo is a repository not known.
func ReadIn(at attacker.Table, repo facts.Repo, files []calls.File, root fs.FS, excluded func(facts.InputPath) bool) *Table {
	t := &Table{}
	if root == nil {
		return t
	}
	g := calls.New(files, true, false, repo)
	for _, f := range files {
		for _, c := range chainsOf(g, f.Node(), map[calls.Node]bool{}) {
			var steps []Step
			switch {
			case f.Workflow != nil:
				steps = workflowSteps(at, f.Name, f.Workflow, c, root, excluded)
			case f.Action != nil:
				steps = actionSteps(at, f.Name, f.Action, c, root, excluded)
			}
			for _, s := range steps {
				s.Tree = f.Tree
				t.steps = append(t.steps, s)
			}
		}
	}
	return t
}

// Steps are the steps of t, in the order of the files and of the steps.
// One step of actions/labeler may give two Steps: one that surely runs,
// and one that may not run (MayNotRun), whose labels are more.
func (t *Table) Steps() []Step {
	if t == nil {
		return nil
	}
	return t.steps
}
