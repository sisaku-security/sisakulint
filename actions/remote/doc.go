// Package remote reads a repository of GitHub without a clone: the tree of
// one commit as an fs.FS (Tree), whose files it reads one blob at a time
// through the git API, and a pull request (its head, its base and the
// paths it changes). It holds a token through actions/internal/githubapi
// and gives none to a rule.
//
// A run reads the blob of a file, not an archive: GitHub runs a workflow
// as the commit has it, and an archive applies the .gitattributes of the
// commit (export-ignore leaves a file out, export-subst rewrites one).
//
// Where things are:
//
//	tree.go  Limits, OpenTree, ResolveCommit, ListTree, Tree (the fs.FS),
//	         and the errors of reading
//	pull.go  ReadPullRequest, ChangedPaths (the difference of two trees),
//	         ChangedInputs (the changed inputs of a run) and BaseChanges
package remote
