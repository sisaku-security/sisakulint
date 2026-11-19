// Package reportview draws a report for people: a page, whole in one HTML
// file, that shows each finding as the path of its evidence, from the
// events an attacker acts on to where the value is used, and lets one try
// the leaves of its condition. A finding whose certainty is inconclusive is
// in the same list, marked inconclusive, with its place, its related places
// and the text of its inconclusive kind. It shows each quality finding too,
// at its place and its related places, after the findings. Toggled, it
// shows what an auditor of
// the rules reads too: the places, the kinds, the args and the
// fingerprints.
//
// It also draws an example catalog (BuildCatalog): for each rule and
// quality rule, the examples of its declarations, whether each is what its
// declaration says, whether a person approved each (ReviewStatus), and the
// page and the facts asked of each run, with the tables of actions/boundary,
// the terms, and the index of the advisories whose form an example is.
//
// The data in the page is for its own script, not a contract.
//
// Where things are:
//
//	model.go     Build: the page of a report, its findings and quality findings
//	files.go     File: the inputs the nodes of a page are in, whole
//	snippet.go   the lines of the step a place is in
//	fix.go       Fix, NoFix: the fix of a finding as the page shows it
//	locate.go    the job and the step a location is in
//	catalog.go   Catalog, BuildCatalog, ReviewStatus, CatalogArgument: the example catalog, with
//	             the arguments of each kind, which the registry's JSON does not have, and
//	             CatalogAdvisory: the index of the advisories the examples cite
//	boundary.go  CatalogBoundary: what the catalog shows of actions/boundary
//	html.go      HTML: the page of a report or of a catalog as one file, with its policy of content
//	serve.go     Serve: the page on a loopback address
//	assets/      the script and the style of the page
package reportview
