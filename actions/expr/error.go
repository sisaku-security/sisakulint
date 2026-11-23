package expr

import "fmt"

// Span is a byte range [Start, End) of the string given to Scan or Parse.
// It is not a position in the YAML input (cst.Span): the model maps it back.
type Span struct{ Start, End int }

// ErrorCode classifies an Error.
type ErrorCode uint8

const (
	ErrUnclosed      ErrorCode = iota + 1 // ${{ without its }}
	ErrEmpty                              // an expression with nothing in it
	ErrUnexpected                         // a symbol the grammar does not allow here
	ErrUnexpectedEnd                      // the expression ends before it is complete
	ErrDepth                              // nested deeper than ExpressionConstants.MaxDepth
	ErrLength                             // longer than ExpressionConstants.MaxLength
	// The errors of CheckNames: what GitHub's parser rejects of the names
	// and the calls of a tree.
	ErrUnknownName     // a context the place does not list (UnrecognizedNamedValue)
	ErrUnknownFunction // a function no place allows, or this place does not (UnrecognizedFunction)
	ErrTooFew          // fewer arguments than the function takes (TooFewParameters)
	ErrTooMany         // more arguments than the function takes (TooManyParameters)
	ErrEven            // case with an even number of arguments (EvenParameters)
)

var errorCodeNames = [...]string{
	ErrUnclosed:        "Unclosed",
	ErrEmpty:           "Empty",
	ErrUnexpected:      "Unexpected",
	ErrUnexpectedEnd:   "UnexpectedEnd",
	ErrDepth:           "Depth",
	ErrLength:          "Length",
	ErrUnknownName:     "UnknownName",
	ErrUnknownFunction: "UnknownFunction",
	ErrTooFew:          "TooFew",
	ErrTooMany:         "TooMany",
	ErrEven:            "Even",
}

func (c ErrorCode) String() string {
	if int(c) < len(errorCodeNames) && errorCodeNames[c] != "" {
		return errorCodeNames[c]
	}
	return "ErrorCode(?)"
}

// Error is a problem found by Scan or Parse.
type Error struct {
	Code ErrorCode
	Span Span
	Msg  string
}

func (e Error) Error() string { return fmt.Sprintf("offset %d: %s", e.Span.Start, e.Msg) }
