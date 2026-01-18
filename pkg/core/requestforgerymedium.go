package core

// RequestForgeryMediumRule creates a medium severity request forgery rule
// that checks for SSRF vulnerabilities in workflows with normal triggers
// (pull_request, push, schedule, etc.)
func RequestForgeryMediumRule() *RequestForgeryRule {
	return newRequestForgeryRule("medium", false)
}
