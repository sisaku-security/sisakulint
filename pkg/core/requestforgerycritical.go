package core

// RequestForgeryCriticalRule creates a critical severity request forgery rule
// that checks for SSRF vulnerabilities in workflows with privileged triggers
// (pull_request_target, workflow_run, issue_comment)
func RequestForgeryCriticalRule() *RequestForgeryRule {
	return newRequestForgeryRule("critical", true)
}
