// Package job is the analysis of one job of a workflow: the attacker's
// privileged events it can run on, what approves its run, whether its
// GITHUB_TOKEN may write, the secrets it reads (for a job that calls a
// reusable workflow, through the call graph, AnalyzeIn), and the labels of its
// runs-on. It
// asks no fact: what the repository's settings decide is left to the rules
// (repo.default-token-write, repo.environment-protected, repo.public). It
// also tells where the reusable workflow a job calls is.
//
// Where things are:
//
//	events.go    the attacker's privileged events
//	approval.go  what approves a run: a label, or an environment
//	writes.go    whether the GITHUB_TOKEN may write, by the permissions
//	             written, where write-all holds, whether it may read
//	             actions and write pull-requests, and whether the
//	             cache-mode saves (CacheWriteOf)
//	called.go    whether a workflow runs only when called, and where the
//	             reusable workflow a job calls is
//	dispatchinput.go whether a value refers to an input of
//	             workflow_dispatch (DispatchInputs)
//	eventname.go the events of a workflow by name, an if read of
//	             github.event_name alone, and whether a job saves to the
//	             cache on an event
//	secrets.go   the secrets a job reads
//	calledsecrets.go what a job that calls a reusable workflow reads through
//	             the call graph (calledReader), and the reads of the
//	             secrets context without a name in the called workflows
//	secretuse.go the reads of the secrets context that name no secret, and
//	             the values taken out of a secret by fromJSON
//	runners.go   the labels of runs-on, with the other labels of the same
//	             runs-on (RunnerLabel.With), the values of the matrix a value
//	             takes (MatrixValues), and the labels a whole ${{ }} that
//	             reads only the matrix gives for each combination of its values
//	hosted.go    whether a job runs on a runner GitHub hosts (Hosted,
//	             HostedSudo), and the names of its services and labels
//	needs.go     every job a job depends on through needs (Ancestors), and
//	             the jobs by name (ByName); the jobs whose ifs a run of a job
//	             goes through are attacker.NeedJobs
//	skipped.go   whether GitHub skips a job in every run (AlwaysSkipped);
//	             calledReader does not read the jobs of a called workflow
//	             that GitHub skips
//	job.go       Analyze and AnalyzeIn: each job with all of the above
package job
