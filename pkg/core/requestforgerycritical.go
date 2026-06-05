package core

// RequestForgeryCriticalRule creates a critical severity request forgery rule
// that checks for SSRF vulnerabilities in workflows with privileged triggers.
func RequestForgeryCriticalRule(wfTaintMap *WorkflowTaintMap) *RequestForgeryRule {
	return newRequestForgeryRule("critical", true, wfTaintMap)
}
