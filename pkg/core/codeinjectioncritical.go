package core

// CodeInjectionCritical is a type alias for backward compatibility with existing tests
// The actual implementation is in CodeInjectionRule
type CodeInjectionCritical = CodeInjectionRule

// CodeInjectionCriticalRule creates a rule for detecting code injection in privileged workflow contexts
// Privileged contexts include: pull_request_target, workflow_run, issue_comment, issues, discussion_comment
// These triggers have write access or run with secrets, making code injection critical severity
// CodeInjectionCriticalRule creates a rule for detecting code injection in privileged workflow contexts.
// Pass a shared *WorkflowTaintMap to enable cross-job taint propagation detection, or nil to disable it.
func CodeInjectionCriticalRule(wfTaintMap *WorkflowTaintMap) *CodeInjectionRule {
	return newCodeInjectionRule("critical", true, wfTaintMap)
}
