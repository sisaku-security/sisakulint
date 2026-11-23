// Package anchor resolves the aliases of a cst tree (YAML 1.2.2 3.2.2.2
// and 7.1): an alias refers to the latest node before it, in its document,
// with the same anchor.
//
// Where things are:
//
//	anchor.go  Index, Build, Resolve
//
// Tests:
//
//	anchor_test.go  redefinition, undefined and forward aliases, documents
//	suite_test.go   yaml-test-suite: every =ALI
//	fuzz_test.go    FuzzResolve, seeded with the suite and the corpus
package anchor
