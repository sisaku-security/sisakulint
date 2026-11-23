// Package githubapi sends the requests of the GitHub REST API: the base
// URL, the headers, the token, the redirects and the rate limit. Two
// packages hold a token through it, actions/facts/github and
// actions/remote, and neither gives the token to a rule.
//
// The token goes to the host of the base URL only: Get and Do stop at a
// redirect to another host or scheme, and Stream, which reads an archive
// that another host serves, follows a redirect to another host of the
// same scheme without the token.
package githubapi
