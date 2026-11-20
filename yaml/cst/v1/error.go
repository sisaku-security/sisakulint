package cst

import "fmt"

// ErrorCode classifies an Error.
type ErrorCode uint16

const (
	ErrUnexpected         ErrorCode = iota + 1 // content no production accepts; wrapped in an Error node
	ErrEncoding                                // the stream is not UTF-8
	ErrInvalidEscape                           // an escape sequence [62] does not allow; the tree is unaffected
	ErrIndent                                  // indentation the YAML 1.2.2 specification forbids; the tree is unaffected
	ErrUndefinedTagHandle                      // a named tag handle without a %TAG directive in its document
	ErrDuplicateDirective                      // a second %YAML, or a second %TAG for one handle, in a document
	ErrDuplicateProperty                       // a second anchor or tag on one node; the extra one stays in Properties
	ErrInvalidUTF8                             // bytes that are not UTF-8
	ErrInvalidChar                             // a character outside c-printable (nb-json in quoted scalars), or a misplaced BOM
	ErrUnclosedFlow                            // a flow collection without its closing indicator; it is closed where recovery stops
	ErrDepth                                   // nesting deeper than the parser allows; the subtree becomes an Error
	ErrImplicitKeyLine                         // ModeGitHub: an implicit key of a flow mapping whose ':' is not on the line the key starts; the tree is unaffected
	ErrImplicitKeyLength                       // ModeGitHub: an implicit key of a flow mapping longer than 1024 characters; the tree is unaffected
)

// Error is a syntax error or a constraint violation found by Parse.
type Error struct {
	Code ErrorCode
	Span Span
	Msg  string
}

func (e Error) Error() string {
	return fmt.Sprintf("offset %d: %s", e.Span.Start, e.Msg)
}
