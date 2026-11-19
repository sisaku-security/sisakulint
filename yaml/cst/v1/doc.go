// Package cst reads YAML 1.2.2 into a lossless concrete syntax tree.
// Values, tags and aliases are read by the packages scalar and anchor;
// the package edit rewrites the bytes and reads them back.
//
// Every input byte belongs to exactly one token, and the tree contains every
// token exactly once, so the input is recovered from any node's Bytes.
//
// ParseMode with ModeGitHub accepts what GitHub accepts in a workflow file
// instead of YAML 1.2.2; each of its rules was observed on GitHub.
//
// Where things are:
//
//	kind.go    TokenKind, NodeKind
//	tree.go    Tree, Node, Token, Element: Children, Tokens, Span, Bytes; Reparse, Mode
//	view.go    typed reading: Mapping, Entry, Sequence, Anchor, Tag, Style, IsFlow
//	pos.go     line index; Position, RuneColumn, LineStart
//	error.go   Error, ErrorCode
//	parser.go  Parse, ParseMode, Mode; parser state; the token and node primitives (emit, open, close, mark, reset)
//
// The parser follows the productions of YAML 1.2.2, one function per
// production, named after it and annotated with its number. Files follow
// the chapters of the YAML 1.2.2 specification:
//
//	chars.go   chapter 5: character classes, encoding detection, checkChars
//	basic.go   chapter 6: indentation, separation, comments, directives, properties
//	flow.go    chapter 7: alias, quoted and plain scalars, flow collections, flow nodes
//	block.go   chapter 8: block scalars and collections
//	stream.go  chapter 9: documents and the stream; recovery at stream level
//	recover.go recovery inside block and flow collections; the nesting limit;
//	           the flow-pair pre-scan
//
// Tests:
//
//	validate_test.go  the tree invariants, used by every other test
//	suite_test.go     yaml-test-suite: invariants, error judgment, skeleton
//	events_test.go    the tree as yaml-test-suite events, via the typed API
//	tree_test.go      trees built by hand, empty nodes and inputs, the check of the invariants,
//	                  ContentSpan
//	view_test.go      Mapping, Sequence, their properties, flow pairs, block scalar styles
//	pos_test.go       Position, LineStart
//	flow_test.go      flow scalars and collections, escapes, errors rolled back
//	block_test.go     block scalars and collections, and their errors
//	stream_test.go    documents, the tokens of the stream, encoding errors, unparsed content
//	error_test.go     the constraint violations
//	recover_test.go   recovery, the depth limit (its time with ACTIONS_SCALE=1)
//	suite_exclude_test.go the suite cases not passed, with the reason
//	corpus_test.go    yaml/corpus: invariants; -corpus.report lists files with errors
//	github_test.go    ModeGitHub against what GitHub did (the observations above)
//	suite_github_test.go  the suite cases ModeGitHub judges differently; the
//	                  bound on what ModeGitHub changes (CST_CORPUS=full: all the corpus)
//	fuzz_test.go      FuzzParse, seeded with the suite and the corpus
//	bench_test.go     benchmarks; results in BENCH.md
//	builder_test.go   building trees by hand for the tree and view tests
//	internal/suitetest  reading the suite's data release; does not import cst
//	internal/suitewalk  the tree in suite event order, for the packages above cst
package cst
