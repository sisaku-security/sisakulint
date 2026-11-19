// Package analysis has the enumerations, and the few values of their own
// type (EventActivity, LabelName, Transform), that the shared analyses
// (actions/taint, actions/prcode, actions/job, actions/agent and the
// others under actions/ that read the model) give and the IR (actions/ir)
// and the rules read: each defined here once, so that no package restates
// them.
package analysis
