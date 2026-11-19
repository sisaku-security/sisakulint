// Package scalar reads the values and tags of cst Scalar nodes, and maps
// positions in a value back to the input.
//
// Values follow YAML 1.2.2 chapters 7 and 8.1; tags are resolved with the
// core schema (10.3).
//
// The end of the input is no line break: a block scalar whose last line has
// none ends without a line feed ([165]). GitHub, YamlDotNet and libyaml read
// it the same way; only the yaml-test-suite's expected values differ.
//
// Where things are:
//
//	value.go   Value, its segments, Source, Position; the builder that makes them
//	flow.go    Decode; chapter 7: plain, single- and double-quoted scalars, escapes
//	block.go   chapter 8.1: literal and folded scalars, chomping
//	tag.go     Tag, Directives, Explicit (6.9), Resolve (10.3.2)
//	convert.go the core schema's rules; Bool, Int, Float
//	encode.go  Body: a value written in a style, the inverse of Decode
//
// Tests:
//
//	value_test.go          Source and Position on values built by hand
//	flow_test.go           flow scalar values, kept escapes, CRLF, empty scalars
//	block_test.go          block scalar values, chomping, CRLF, run: | positions
//	property_test.go       segment properties on the suite, the corpus, a huge run: |
//	fuzz_test.go           FuzzDecode, seeded with the suite and the corpus
//	tag_test.go            tag expansion, resolution (Example 10.9)
//	convert_test.go        Bool, Int, Float at their limits
//	encode_test.go         Body, read back in each style; FuzzEncode
//	suite_test.go          yaml-test-suite: values, tags
//	suite_exclude_test.go  suite cases not passed, with the reason
//	json_test.go           yaml-test-suite: in.json, with anchor (package scalar_test)
//	github_test.go         the values GitHub gave for quoted scalars less indented than YAML allows
//	bench_test.go          benchmarks; results in BENCH.md
package scalar
