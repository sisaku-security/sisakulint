// Package callerstest makes the inputs of a test of callers and called
// workflows and actions: what lint reads of each file, as calls.File.
package callerstest

import (
	"path"
	"testing"

	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// File is the file name with the text src, read as lint reads it: an
// action.yml or action.yaml as action metadata, the rest as a workflow.
func File(t testing.TB, name, src string) calls.File {
	t.Helper()
	tree := cst.ParseMode([]byte(src), cst.ModeGitHub)
	f := calls.File{Name: facts.MustCleanInputPath(name), Tree: tree}
	if b := path.Base(name); b == "action.yml" || b == "action.yaml" {
		f.Action, _ = workflow.ParseActionMetadata(tree)
	} else {
		f.Workflow, _ = workflow.Parse(tree)
	}
	return f
}

// Graph is the graph of the files given as name and text, in pairs.
func Graph(t testing.TB, complete, missing bool, files ...[2]string) *calls.Graph {
	t.Helper()
	var fs []calls.File
	for _, f := range files {
		fs = append(fs, File(t, f[0], f[1]))
	}
	return calls.New(fs, complete, missing, facts.Repo{})
}
