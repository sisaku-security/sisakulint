// Package attacker reads an if as it is in a run an attacker triggers: for each
// event and activity type, the table of runs (table.go) gives what the
// context holds there, and an if that is false in each run of an event
// keeps the attacker's event out.
//
// Where things are:
//
//	value.go   the values of an attacker run that are not known: a name of
//	           the attacker's own, a name they choose, a value of the
//	           repository, one of a set
//	table.go   the runs of each event and what the context holds in them
//	           (rows), and Table, the table as a run reads it: Outsider,
//	           or TableOf the barriers an attacker the run adds gets past
//	status.go  the status functions an if calls (StatusFunctions,
//	           HasStatusFunction), and the expression GitHub evaluates for
//	           an if (IfTree)
//	placed.go  an if with the place it stands in (PlacedIf: a step's, or a
//	           job's with the jobs it depends on directly), and the jobs
//	           whose ifs a run of a job goes through (NeedJobs, JobIfs)
//	eval.go    the truth of a PlacedIf in a run (Truth), with
//	           github.event_name alone (EventNameOnly), and which events it
//	           keeps
//	jobstate.go the truth of a PlacedIf in a job of a known state
//	           (JobState: after a failure, in a cancelled run, with no
//	           failure; job.status), and of a job's if when every job it
//	           depends on through needs, directly or through other jobs,
//	           succeeded or one failed, over the attacker's runs (RunTruth,
//	           CodeTruth, ActorTruth); a job's if with the result of the
//	           jobs it depends on directly, which may surely run or fail
//	           (Need, JobCodeTruth, JobActorTruth)
//	narrow.go  whether an if lets a reference be only the strings it
//	           compares the reference with (Narrowing)
//	bypass.go  the comparisons of an if that a run of Dependabot, or a
//	           part of a string, lets through, and those with the name of
//	           another bot (OtherBots)
//	label.go   the truth of a PlacedIf in the run a label starts
//	           (LabelTruth), and the
//	           comparisons of the label's name that a part of a string
//	           lets through
//	gate.go    whether the value of an agent action's gate lets in the
//	           attacker who triggers the run as its actor, and the name of
//	           another the attacker comments on
package attacker
