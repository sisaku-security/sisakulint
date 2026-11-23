// Package regexpcalls keeps the linter from reading ${{ }} expressions and
// shell scripts with regular expressions. The rule of this module is that
// expressions are read with the syntax of actions/expr and scripts with the
// syntax of actions/shell, and that a regular expression only checks the
// form of one token that the syntax took out. Its tests count, file by
// file, the calls of the Go files under Dirs to the functions of regexp that
// compile a pattern (Count), and compare them with allowed.tsv, which may
// only shrink. Tests and generated files are not counted; a generator is.
// The count is a guard that can be gone around, not a proof: a call through
// a dot import of regexp, or through a function value
// (mc := regexp.MustCompile; mc(...)), is not counted.
//
// Where things are:
//
//	count.go  Dirs, Files, Count, the file allowed.tsv, Grown
package regexpcalls
