package expr

import (
	"fmt"
	"math"
	"strings"
)

// ContextName is a context an expression may name: the named values the
// schema's context lists name.
type ContextName uint8

const (
	ContextGithub ContextName = iota
	ContextInputs
	ContextVars
	ContextNeeds
	ContextStrategy
	ContextMatrix
	ContextSecrets
	ContextSteps
	ContextJob
	ContextRunner
	ContextEnv
	ContextJobs
	numContexts
)

var contextNames = [numContexts]string{"github", "inputs", "vars", "needs", "strategy", "matrix", "secrets", "steps", "job", "runner", "env", "jobs"}

func (c ContextName) String() string { return contextNames[c] }

// ParseContextName is the context named s, compared as GitHub compares
// names (FoldName).
func ParseContextName(s string) (ContextName, bool) {
	for c, n := range contextNames {
		if EqualName(s, n) {
			return ContextName(c), true
		}
	}
	return 0, false
}

// ScopedFunc is a function only some places allow, with a number of
// arguments that depends on the place: the functions of the schema's
// context lists.
type ScopedFunc uint8

const (
	FuncAlways ScopedFunc = iota
	FuncCancelled
	FuncFailure
	FuncSuccess
	FuncHashFiles
	numScopedFuncs
)

var scopedFuncNames = [numScopedFuncs]string{"always", "cancelled", "failure", "success", "hashFiles"}

func (f ScopedFunc) String() string { return scopedFuncNames[f] }

// ParseScopedFunc is the scoped function named s, compared without case.
func ParseScopedFunc(s string) (ScopedFunc, bool) {
	for f, n := range scopedFuncNames {
		if EqualName(s, n) {
			return ScopedFunc(f), true
		}
	}
	return 0, false
}

// Arity is the least and the most arguments of a function.
type Arity struct{ Min, Max int }

// MaxArgs is the MAX of a context list's function, Int32.MaxValue.
const MaxArgs = math.MaxInt32

// wellKnown are the functions every place allows, with their arities
// (actions/runner v2.337.0, src/Sdk/Expressions/ExpressionConstants.cs).
var wellKnown = []struct {
	name  string
	arity Arity
	odd   bool // the number of arguments must be odd (EvenParameters)
}{
	{"case", Arity{3, 255}, true},
	{"contains", Arity{2, 2}, false},
	{"endsWith", Arity{2, 2}, false},
	{"format", Arity{1, 255}, false},
	{"join", Arity{1, 2}, false},
	{"startsWith", Arity{2, 2}, false},
	{"toJson", Arity{1, 1}, false},
	{"fromJson", Arity{1, 1}, false},
}

// Names are the contexts and the scoped functions a place allows. The zero
// Names allows none, and so no expression.
type Names struct {
	contexts uint16
	funcs    uint8
	arity    [numScopedFuncs]Arity
}

func (n Names) WithContext(c ContextName) Names {
	n.contexts |= 1 << c
	return n
}

func (n Names) WithFunc(f ScopedFunc, a Arity) Names {
	n.funcs |= 1 << f
	n.arity[f] = a
	return n
}

// Union allows what n or o allows. A function both allow takes the wider
// arity; the runner instead fails every expression of the place when a
// function is listed twice (ExpressionParser.ParseContext adds the
// functions to a dictionary). No place of the pinned schemas lists one
// twice.
func (n Names) Union(o Names) Names {
	u := Names{contexts: n.contexts | o.contexts, funcs: n.funcs | o.funcs}
	for f := range numScopedFuncs {
		switch a, b := n.arity[f], o.arity[f]; {
		case n.funcs&(1<<f) == 0:
			u.arity[f] = b
		case o.funcs&(1<<f) == 0:
			u.arity[f] = a
		default:
			u.arity[f] = Arity{min(a.Min, b.Min), max(a.Max, b.Max)}
		}
	}
	return u
}

func (n Names) IsZero() bool { return n.contexts == 0 && n.funcs == 0 }

// Contexts are the contexts n allows, in the order of ContextName.
func (n Names) Contexts() []ContextName {
	var cs []ContextName
	for c := range numContexts {
		if n.contexts&(1<<c) != 0 {
			cs = append(cs, c)
		}
	}
	return cs
}

func (n Names) context(name string) bool {
	c, ok := ParseContextName(name)
	return ok && n.contexts&(1<<c) != 0
}

// arityOf is the arity of the function name where n allows it, and
// whether its number of arguments must be odd.
func (n Names) arityOf(name string) (a Arity, odd, ok bool) {
	for _, w := range wellKnown {
		if EqualName(name, w.name) {
			return w.arity, w.odd, true
		}
	}
	if f, ok := ParseScopedFunc(name); ok && n.funcs&(1<<f) != 0 {
		return n.arity[f], false, true
	}
	return Arity{}, false, false
}

// CheckNames reports what GitHub's parser rejects in the tree n where the
// place allows the names allowed: a context it does not list, a function
// it does not allow, and a call with a wrong number of arguments (runner
// v2.337.0, src/Sdk/Expressions/ExpressionParser.cs).
// The errors are in the order the nodes are written.
func CheckNames(n Node, allowed Names) []Error {
	var errs []Error
	var walk func(Node)
	walk = func(n Node) {
		switch x := n.(type) {
		case *Context:
			if !allowed.context(x.Name) {
				var avail []string
				for _, c := range allowed.Contexts() {
					avail = append(avail, c.String())
				}
				errs = append(errs, Error{Code: ErrUnknownName, Span: x.Span(), Msg: fmt.Sprintf("Unrecognized named-value: '%s'; the contexts available here are %s", x.Name, strings.Join(avail, ", "))})
			}
		case *Call:
			switch a, odd, ok := allowed.arityOf(x.Name); {
			case !ok:
				errs = append(errs, Error{Code: ErrUnknownFunction, Span: x.NameSpan, Msg: fmt.Sprintf("Unrecognized function: '%s'", x.Name)})
			case len(x.Args) < a.Min:
				errs = append(errs, Error{Code: ErrTooFew, Span: x.Span(), Msg: fmt.Sprintf("Too few parameters supplied: '%s'", x.Name)})
			case len(x.Args) > a.Max:
				errs = append(errs, Error{Code: ErrTooMany, Span: x.Span(), Msg: fmt.Sprintf("Too many parameters supplied: '%s'", x.Name)})
			case odd && len(x.Args)%2 == 0:
				errs = append(errs, Error{Code: ErrEven, Span: x.Span(), Msg: fmt.Sprintf("Even number of parameters supplied, requires an odd number of parameters: '%s'", x.Name)})
			}
		}
		for _, c := range Children(n) {
			walk(c)
		}
	}
	walk(n)
	return errs
}
