package expr

import (
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The lexer follows the runner's Expressions/Tokens/LexicalAnalyzer.cs:
// which token may follow which is checked here (CheckLastToken), so the
// parser only builds the tree.

type tokenKind uint8

const (
	tokStartGroup      tokenKind = iota // ( of a group
	tokStartIndex                       // [
	tokStartParameters                  // ( of a call
	tokEndGroup                         // )
	tokEndIndex                         // ]
	tokEndParameters                    // ) of a call
	tokSeparator                        // ,
	tokDereference                      // .
	tokWildcard                         // *
	tokLogicalOperator                  // ! == != < <= > >= && ||
	tokNull
	tokBoolean
	tokNumber
	tokString
	tokPropertyName // a keyword after .
	tokFunction     // a keyword before (
	tokNamedValue   // any other keyword: a context
)

var tokenKindNames = [...]string{
	tokStartGroup:      "StartGroup",
	tokStartIndex:      "StartIndex",
	tokStartParameters: "StartParameters",
	tokEndGroup:        "EndGroup",
	tokEndIndex:        "EndIndex",
	tokEndParameters:   "EndParameters",
	tokSeparator:       "Separator",
	tokDereference:     "Dereference",
	tokWildcard:        "Wildcard",
	tokLogicalOperator: "LogicalOperator",
	tokNull:            "Null",
	tokBoolean:         "Boolean",
	tokNumber:          "Number",
	tokString:          "String",
	tokPropertyName:    "PropertyName",
	tokFunction:        "Function",
	tokNamedValue:      "NamedValue",
}

func (k tokenKind) String() string { return tokenKindNames[k] }

type token struct {
	kind tokenKind
	span Span
	raw  string
	str  string // the value of a string literal
}

// kindSet is a set of token kinds; noToken stands for "no previous token".
type kindSet uint32

const noToken tokenKind = 31

func set(ks ...tokenKind) kindSet {
	var s kindSet
	for _, k := range ks {
		s |= 1 << k
	}
	return s
}

func (s kindSet) has(k tokenKind) bool { return s&(1<<k) != 0 }

var (
	// what may precede an operand, a group or !
	beforeOperand = set(noToken, tokSeparator, tokStartGroup, tokStartParameters, tokStartIndex, tokLogicalOperator)
	// what may end an operand
	afterOperand = set(tokEndGroup, tokEndParameters, tokEndIndex, tokWildcard, tokNull, tokBoolean, tokNumber, tokString, tokPropertyName, tokNamedValue)
	// what may be indexed or dereferenced
	indexable = set(tokEndGroup, tokEndParameters, tokEndIndex, tokWildcard, tokPropertyName, tokNamedValue)
)

func legalAfter(k tokenKind, raw string) kindSet {
	switch k {
	case tokStartGroup, tokNull, tokBoolean, tokNumber, tokString, tokFunction, tokNamedValue:
		return beforeOperand
	case tokStartIndex, tokDereference:
		return indexable
	case tokStartParameters:
		return set(tokFunction)
	case tokEndGroup, tokEndIndex, tokSeparator:
		return afterOperand
	case tokEndParameters:
		return afterOperand | set(tokStartParameters)
	case tokWildcard:
		return set(tokStartIndex, tokDereference)
	case tokLogicalOperator:
		if raw == "!" {
			return beforeOperand
		}
		return afterOperand
	case tokPropertyName:
		return set(tokDereference)
	}
	return 0
}

type lexer struct {
	src      string
	i        int
	last     tokenKind
	unclosed []tokenKind // open ( [ and call (, innermost last
}

// lex reads all of src. It stops at the first token the grammar does not
// allow and returns it as the error.
func lex(src string) ([]token, *Error) {
	l := &lexer{src: src, last: noToken}
	var toks []token
	for {
		t, ok, err := l.next()
		if err != nil {
			return toks, err
		}
		if !ok {
			return toks, nil
		}
		toks = append(toks, t)
	}
}

func (l *lexer) next() (token, bool, *Error) {
	l.i = skipSpace(l.src, l.i)
	if l.i >= len(l.src) {
		return token{}, false, nil
	}
	start := l.i
	kind, ok := l.read()
	t := token{kind: kind, span: Span{start, l.i}, raw: l.src[start:l.i]}
	if !ok || !legalAfter(t.kind, t.raw).has(l.last) || !l.balance(t.kind) {
		return token{}, false, &Error{Code: ErrUnexpected, Span: t.span, Msg: "unexpected symbol " + strconv.Quote(t.raw)}
	}
	if t.kind == tokString {
		t.str = unquote(t.raw)
	}
	l.last = t.kind
	return t, true, nil
}

// read reads one token from l.i. It is false for text that is no token;
// l.i is then past that text.
func (l *lexer) read() (tokenKind, bool) {
	c := l.src[l.i]
	switch c {
	case '(', '[', ')', ']', ',', '*':
		l.i++
		switch c {
		case '(':
			if l.last == tokFunction {
				return tokStartParameters, true
			}
			return tokStartGroup, true
		case '[':
			return tokStartIndex, true
		case ')':
			if l.top() == tokStartParameters {
				return tokEndParameters, true
			}
			return tokEndGroup, true
		case ']':
			return tokEndIndex, true
		case ',':
			return tokSeparator, true
		}
		return tokWildcard, true
	case '\'':
		return tokString, l.readString()
	case '!', '>', '<', '=', '&', '|':
		return tokLogicalOperator, l.readOperator()
	case '.':
		if !beforeOperand.has(l.last) {
			l.i++
			return tokDereference, true
		}
		return tokNumber, l.readNumber()
	case '-', '+', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return tokNumber, l.readNumber()
	}
	return l.readKeyword()
}

// balance keeps the stack of open brackets (LexicalAnalyzer.CreateToken).
func (l *lexer) balance(k tokenKind) bool {
	var open tokenKind
	switch k {
	case tokStartGroup, tokStartIndex, tokStartParameters:
		l.unclosed = append(l.unclosed, k)
		return true
	case tokSeparator:
		return l.top() == tokStartParameters
	case tokEndGroup:
		open = tokStartGroup
	case tokEndIndex:
		open = tokStartIndex
	case tokEndParameters:
		open = tokStartParameters
	default:
		return true
	}
	if l.top() != open {
		return false
	}
	l.unclosed = l.unclosed[:len(l.unclosed)-1]
	return true
}

func (l *lexer) top() tokenKind {
	if len(l.unclosed) == 0 {
		return noToken
	}
	return l.unclosed[len(l.unclosed)-1]
}

// readString reads a quoted string; a doubled quote is one quote. It is
// false when the string is not closed.
func (l *lexer) readString() bool {
	for l.i++; l.i < len(l.src); l.i++ {
		if l.src[l.i] != '\'' {
			continue
		}
		if l.i+1 < len(l.src) && l.src[l.i+1] == '\'' {
			l.i++
			continue
		}
		l.i++
		return true
	}
	return false
}

// unquote is the value of a closed string literal raw.
func unquote(raw string) string {
	s := raw[1 : len(raw)-1]
	if !strings.Contains(s, "''") {
		return s
	}
	return strings.ReplaceAll(s, "''", "'")
}

func (l *lexer) readOperator() bool {
	if l.i+1 < len(l.src) {
		switch l.src[l.i : l.i+2] {
		case "!=", ">=", "<=", "==", "&&", "||":
			l.i += 2
			return true
		}
	}
	c := l.src[l.i]
	l.i++
	if c == '!' || c == '>' || c == '<' {
		return true
	}
	l.i = toBoundary(l.src, l.i, false)
	return false
}

// readNumber reads to the next boundary other than '.'.
func (l *lexer) readNumber() bool {
	start := l.i
	l.i = toBoundary(l.src, l.i+1, true)
	return isNumber(l.src[start:l.i])
}

func (l *lexer) readKeyword() (tokenKind, bool) {
	start := l.i
	l.i = toBoundary(l.src, l.i+1, false)
	s := l.src[start:l.i]
	switch {
	case !isKeyword(s):
		return 0, false
	case l.last == tokDereference:
		return tokPropertyName, true
	case s == "null":
		return tokNull, true
	case s == "true" || s == "false":
		return tokBoolean, true
	case s == "NaN" || s == "Infinity":
		return tokNumber, true
	}
	if j := skipSpace(l.src, l.i); j < len(l.src) && l.src[j] == '(' {
		return tokFunction, true
	}
	return tokNamedValue, true
}

// toBoundary returns the first index at or after i where a token boundary
// is (TestTokenBoundary); with dot, '.' is no boundary.
func toBoundary(s string, i int, dot bool) int {
	for ; i < len(s); i++ {
		switch s[i] {
		case '.':
			if !dot {
				return i
			}
		case '(', '[', ')', ']', ',', '!', '>', '<', '=', '&', '|':
			return i
		default:
			if spaceAt(s, i) > 0 {
				return i
			}
		}
	}
	return i
}

func skipSpace(s string, i int) int {
	for i < len(s) {
		n := spaceAt(s, i)
		if n == 0 {
			break
		}
		i += n
	}
	return i
}

// spaceAt is the length of the white space character (Char.IsWhiteSpace)
// at s[i], or 0.
func spaceAt(s string, i int) int {
	c := s[i]
	if c < utf8.RuneSelf {
		if c == ' ' || c >= '\t' && c <= '\r' {
			return 1
		}
		return 0
	}
	r, n := utf8.DecodeRuneInString(s[i:])
	if unicode.IsSpace(r) {
		return n
	}
	return 0
}

// isKeyword is ExpressionUtility.IsLegalKeyword: [A-Za-z_][A-Za-z0-9_-]*.
func isKeyword(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case i > 0 && (c >= '0' && c <= '9' || c == '-'):
		default:
			return false
		}
	}
	return s != ""
}

// isNumber is whether ExpressionUtility.ParseNumber gives a number:
// Double.TryParse with AllowLeadingSign, AllowDecimalPoint and
// AllowExponent (which also takes the infinity symbol with a sign, in any
// case), lowercase 0x with the bits of an Int32 in hex, or 0o with those
// bits in octal.
func isNumber(s string) bool {
	if len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'o') {
		base := 16
		if s[1] == 'o' {
			base = 8
		}
		n, err := strconv.ParseUint(s[2:], base, 64)
		return err == nil && n <= math.MaxUint32
	}
	i := 0
	if s[0] == '+' || s[0] == '-' {
		i++
	}
	if strings.EqualFold(s[i:], "Infinity") {
		return true
	}
	digits := 0
	for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		digits++
	}
	if i < len(s) && s[i] == '.' {
		for i++; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
			digits++
		}
	}
	if digits == 0 {
		return false
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		exp := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == exp {
			return false
		}
	}
	return i == len(s)
}
