// Package composite reads the actions a step runs, and the steps of those
// that are composite actions, to a depth of four (the action of the step
// is at depth 1), as the rules read them through actions/ir.
//
// An action of the repository (./ of a step of a workflow, and $/, the
// repository of the workflow) is an input of the run, which Local looks
// up. An action of another repository is the fact action.definition: the
// file the runner reads from the archive it downloads. The runner reads ./
// in a composite action from the workspace of the job, not from the
// action's repository, so Reader does not follow ./ in a composite action.
// Each action (an input, or a repository, a path and a commit) is read
// once for a step; Reader parses the file of an answer once for all the
// steps it reads, so that the places in it are the same.
//
// A uses of another repository that action.definition does not answer is
// Unanswered: whether someone asked could not answer it (an unknown of
// --online, or of a file of facts that records one) or no one answered at
// all (a run without --online or --facts).
//
// ExpandCall reads, the same way, the reusable workflows of other
// repositories a job calls, to a depth of three (the workflow the job calls
// is at depth 1): the fact workflow.definition, the file at the commit
// (GitHub runs a reusable workflow of another repository from the commit,
// not from its archive). In a workflow read, ./ and $/ name a workflow of
// the same commit of its repository. Each workflow it reads (Called) has
// the job that calls it and the workflow that job is in, and is read once
// for each job that calls it: two jobs give it different with and secrets.
package composite
