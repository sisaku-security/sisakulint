// Package ir is the intermediate representation the rules read: the
// results of the shared analyses (actions/taint, actions/prcode,
// actions/shell, actions/job, actions/agent, actions/composite and the
// others under actions/ that read the model), each as summaries of places
// of an input.
//
// A summary is a value of one place, of a summary type: its key (Key: the
// input and the YAML path of the place, by the rules of the fingerprint),
// its fields, and its handles on the syntax (Handle), by which a rule
// makes where a finding is and the edits of a fix, and nothing else.
//
// What a group of rules reads is declared once, in views.json: its
// fields and the operations of handles it uses. The generator makes a
// reader for each (NReader, made by the View NView), with the accessors
// of those fields and nothing else, so that a rule cannot read a field it
// does not declare; the engine gives it through lint.WithView.
//
// The layers: yaml/cst/v1 (the tree, which fixes edit) → actions/workflow
// (the model) → actions/analysis (the enumerations) → the shared
// analyses → actions/ir → actions/rules. actions/lint imports this
// package, and this package does not import actions/lint.
//
// The summary types, and the types of the values their fields hold, are
// those of summaries.json; summary_gen.go is made from it and views.json
// by go generate (internal/irgen). Each type is made in the file of what
// it summarizes (Uses and UnreadCallee in uses.go, CheckoutSite and RunCheckoutSite in checkout.go, the first with its
// fixes in checkoutfix.go, Sink in sink.go, AgentStep in agent.go,
// CompositeCall in composite.go; the summaries of the quality rules in
// quality.go, but ExpressionMistake in expression.go and
// ConfigurationVariableRef in configvar.go, which share one walk of the
// keys that may hold a ${{ }}), of the model or the analyses, the
// first time a rule asks for it, and once for the IR; the scripts of runs
// are read once for all
// (shell.Memo). CompositeCall reads the actions the steps run through
// actions/composite, which asks the facts of the actions of other
// repositories (WithComposite); its handles in those files are in the
// value of a fact (Handle.Fact). RemoteCall, in remotecall.go, reads the
// reusable workflows of other repositories a job calls the same way
// (composite.Reader.ExpandCall). CacheRestoreSave and AgentStep read the
// steps of the composite actions of other repositories the same way;
// place.go makes the handles of a summary in the file of an input or of
// such an action. skipped.go finds the job a summary is in, and whether
// GitHub skips that job in every run (job.AlwaysSkipped), for the field
// always-skipped of the summaries. NewRemote is the IR of a remote called workflow (a
// reusable workflow of another repository, read for a chain of calls from
// a job of an input): its handles are in the value of workflow.definition,
// and it reads its events and inputs from its caller.
//
// To add a field: add it to its summary type in summaries.json and to the
// views that read it in views.json, run go generate, and set it where the
// summary is made (the file of its type). A field is for what several
// rules read, or what a fix may change; a value only one rule reads, of
// no use to compare, stays in that rule.
package ir
