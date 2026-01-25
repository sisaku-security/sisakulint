package core

// OutputClobberingCritical is a type alias for backward compatibility with existing tests
// The actual implementation is in OutputClobberingRule
type OutputClobberingCritical = OutputClobberingRule

// OutputClobberingCriticalRule creates a rule for detecting output clobbering in privileged workflow contexts
// Privileged contexts include: pull_request_target, workflow_run, issue_comment, issues, discussion_comment
// These triggers have write access or run with secrets, making output clobbering critical severity
func OutputClobberingCriticalRule() *OutputClobberingRule {
	return newOutputClobberingRule("critical", true)
}
