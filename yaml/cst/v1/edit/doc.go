// Package edit rewrites the bytes of a cst tree and reads them back,
// keeping everything it does not replace (GOAL 1, 2). An Edit replaces a
// range of the tree's bytes; Apply applies a list of them at once, reads
// the result back the way the tree was read, and refuses the whole list
// when the result has a new syntax error or a value other than the one an
// edit promised, or a change in the logical tree that no edit explains.
// Each Apply returns the edits that undo it, the logical difference of the
// trees, and the node each old node became.
//
// Where things are:
//
//	edit.go      Edit, Result, Error, Apply: checking, ordering, the new bytes, the inverse
//	check.go     the checks after reading back: syntax errors, what each edit promises,
//	             changes that nothing explains
//	diff.go      Change, Path, the pairing of old and new nodes, Result.Follow
//	replace.go   Replace: text in a value, in the scalar's style; the plain and block rules;
//	             Rewrite: the whole scalar in another style
//	value.go     Value, Scalar, Map, Seq: what the structural operations write; sameValue
//	write.go     writing a value tree in a block or a flow collection, keys, block scalars
//	lines.go     the lines a block element takes (whose comments are whose), the layout to write in
//	structure.go Place, Insert, InsertItem, Delete, SetValue: where an element goes or what it
//	             takes in a block or a flow collection
//	comment.go   LineComment: the comment at the end of a node's line
//	editor.go    Editor, whose methods those are: what it remembers of a document, anchors
//	             that aliases outside use
//
// Tests:
//
//	apply_test.go    ranges, order, overlaps, stale edits, errors, the inverse, many edits
//	replace_test.go  Replace in each style, what it refuses, block lines, CRLF
//	rewrite_test.go  Rewrite between styles, properties and header comments kept
//	diff_test.go     the diff of raw edits and of Replace, renamed keys, Follow, Path.String
//	write_test.go    writing each kind of value, what cannot be written, reading it back
//	lines_test.go    the lines of an element, comments above it, compact entries, layouts,
//	                 pairOf as Mapping.Entries
//	insert_test.go   Insert and InsertItem at each place, block and flow, what they refuse
//	delete_test.go   Delete of entries and items, comments, compact and flow forms, refusals
//	setvalue_test.go SetValue between kinds, comments on the key's line, refusals
//	comment_test.go  LineComment: add, change, remove, with a Replace, refusals, its promise
//	scenario_test.go autofixes of a workflow, several edits of one scalar
//	scenario_structure_test.go the structural autofixes of sisakulint, chained through Follow
//	corpus_test.go   every scalar of the suite and the corpus: itself, a word replaced
//	corpus_structure_test.go every structural operation on the suite and the corpus
//	fuzz_test.go     FuzzApply: a raw edit, a Replace and a structural operation on any
//	                 input; FuzzWrite: any value tree
//	scale_test.go    making and applying edits takes time linear in their number, for each kind
//	editor_test.go   an Editor that made other edits makes the same edit as a new one
//	github_test.go   a tree read in ModeGitHub is read back in ModeGitHub by Apply
//	helpers_test.go  walking the scalars of a tree
//	bench_test.go    benchmarks; results in BENCH.md
package edit
