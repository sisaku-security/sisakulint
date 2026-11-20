package taint

import (
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// writtenForm is how a ${{ }} writes the value of a reference into what it
// makes, which decides whether what an attacker writes in the value gets
// there.
type writtenForm uint8

const (
	// writtenText: the value made a string, as a run, a value of env and a
	// value of with take it; the runner writes an object or an array as
	// Object or Array, or fails the step when it is all of the value.
	writtenText writtenForm = iota
	// writtenItems: the first argument of join, which writes a primitive as
	// text and each item of an array as text, and nothing of an object.
	writtenItems
	// writtenJSON: all of it, as toJSON writes it.
	writtenJSON
)

var writtenFormNames = [...]string{"writtenText", "writtenItems", "writtenJSON"}

func (w writtenForm) String() string { return writtenFormNames[w] }

// walkWritten calls f with each reference of n whose value a ${{ }} that
// writes n in form may write, with the path of what it writes of it (the
// reference's path, then after: the properties, indexes and stars taken of
// a value that is not a reference, as (a || b).c takes c of a or b) and the
// form it writes it in. A reference that is compared, negated, given to a
// function that makes a bool or a hash, an operand of && before the last
// (written only when falsy, which holds no text an attacker writes), a
// predicate of case, an argument of format no placeholder names, or a part
// taken of a string (null) is not written.
func walkWritten(n expr.Node, form writtenForm, after []expr.PathElem, f func(ref expr.Node, path []expr.PathElem, form writtenForm)) {
	if n == nil {
		return
	}
	if p, ok := expr.AccessPath(n); ok {
		f(n, slices.Concat(p, after), form)
		return
	}
	switch x := n.(type) {
	case *expr.Group:
		walkWritten(x.X, form, after, f)
	case *expr.Logical:
		ops := x.Xs
		if x.Op == expr.OpAnd {
			ops = ops[len(ops)-1:]
		}
		for _, o := range ops {
			walkWritten(o, form, after, f)
		}
	case *expr.Property:
		walkWritten(x.X, form, slices.Concat([]expr.PathElem{{Name: x.Name}}, after), f)
	case *expr.Index:
		walkWritten(x.X, form, slices.Concat([]expr.PathElem{indexElem(x)}, after), f)
	case *expr.Star:
		walkWritten(x.X, form, slices.Concat([]expr.PathElem{{Star: true}}, after), f)
	case *expr.Call:
		walkCall(x, form, after, f)
	}
}

// indexElem is the element of a path the index of x takes, as
// expr.AccessPath reads it: a name for a string literal, else any.
func indexElem(x *expr.Index) expr.PathElem {
	if lit, ok := x.Index.(*expr.Literal); ok && lit.Kind == expr.LitString {
		return expr.PathElem{Name: lit.Str}
	}
	return expr.PathElem{Dynamic: x.Index}
}

func walkCall(x *expr.Call, form writtenForm, after []expr.PathElem, f func(ref expr.Node, path []expr.PathElem, form writtenForm)) {
	args := x.Args
	switch strings.ToLower(x.Name) {
	case "contains", "startswith", "endswith", "hashfiles", "success", "always", "failure", "cancelled":
	case "case":
		for i := 1; i < len(args); i += 2 {
			walkWritten(args[i], form, after, f)
		}
		if len(args)%2 == 1 {
			walkWritten(args[len(args)-1], form, after, f)
		}
	case "format":
		if len(after) > 0 || len(args) == 0 {
			return
		}
		walkWritten(args[0], writtenText, nil, f)
		named := make([]bool, len(args)-1)
		if l, ok := args[0].(*expr.Literal); ok && l.Kind == expr.LitString {
			named, _ = expr.FormatRefs(l.Str, len(args)-1)
		} else {
			for i := range named {
				named[i] = true
			}
		}
		for i, a := range args[1:] {
			if named[i] {
				walkWritten(a, writtenText, nil, f)
			}
		}
	case "join":
		if len(after) > 0 {
			return
		}
		if len(args) > 0 {
			walkWritten(args[0], writtenItems, nil, f)
		}
		if len(args) > 1 {
			walkWritten(args[1], writtenText, nil, f)
		}
	case "tojson":
		if len(after) > 0 {
			return
		}
		for _, a := range args {
			walkWritten(a, writtenJSON, nil, f)
		}
	case "fromjson":
		if form == writtenText && hasStar(after) {
			return // what a star takes is an array: Array
		}
		for _, a := range args {
			walkWritten(a, writtenText, nil, f) // read as text; what it reads is made of that text
		}
	default:
		for _, a := range args {
			walkWritten(a, writtenJSON, nil, f) // a function the parser refuses: all of it, as before
		}
	}
}

// hasStar is whether the path goes through a star: its value is an array.
func hasStar(path []expr.PathElem) bool {
	return slices.ContainsFunc(path, func(e expr.PathElem) bool { return e.Star })
}

// wholeObject is whether the path names an object whatever the event: all
// of a context, github.event, steps.<id> and needs.<id> and their outputs,
// each written out (a name not known may name a string).
func wholeObject(path []expr.PathElem) bool {
	for _, e := range path {
		if e.Name == "" {
			return false
		}
	}
	switch name := func(i int) string { return expr.FoldName(path[i].Name) }; {
	case len(path) == 1:
		return true
	case len(path) == 2:
		return name(0) == "github" && name(1) == "event" || name(0) == "steps" || name(0) == "needs"
	case len(path) == 3:
		return (name(0) == "steps" || name(0) == "needs") && name(2) == "outputs"
	}
	return false
}

// unwritten is whether what a reference of the path writes in form holds
// nothing of its value but Object or Array, whatever the event: through
// a star as text (an array), or an object of wholeObject as text or as the
// items of join, which writes nothing of an object.
func unwritten(path []expr.PathElem, form writtenForm) bool {
	return form == writtenText && hasStar(path) || form != writtenJSON && wholeObject(path)
}

// writing is what an attacker writes of a value on an event: whether they
// control it (on), with line breaks, beginning with - (or whether they do
// is not known, dashUndecided), and a workflow command.
type writing struct {
	on, lines, dash, dashUndecided bool
	repoName                       bool // when dash: every value that may begin with - is the name of a repository
	cmd                            CommandWriting
	path                           bool // an add-path command (PathCommand), whatever cmd is
}

func (w writing) or(o writing) writing {
	dash := w.dash || o.dash
	repo := dash && (w.repoName || !w.on) && (o.repoName || !o.on) // any other value an attacker controls wins
	return writing{on: w.on || o.on, lines: w.lines || o.lines, dash: dash, dashUndecided: w.dashUndecided || o.dashUndecided, repoName: repo, cmd: max(w.cmd, o.cmd), path: w.path || o.path}
}

// writtenPath is a path whose value a reference writes, and whether it is
// read as text (LookupText) or as all of it (Lookup).
type writtenPath struct {
	path []expr.PathElem
	text bool
}

// writtenPaths are the paths whose values a reference of path below
// github, written in form, writes on e: all of it as JSON; the value as
// text; as the items of join, the values through a star, or else the value
// and the items of an array (hasItems; join writes nothing of an object).
// An item is the * of the table alone, not a named
// key.
func writtenPaths(e analysis.EventActivity, path []expr.PathElem, form writtenForm) []writtenPath {
	switch {
	case form == writtenJSON:
		return []writtenPath{{path, false}}
	case form == writtenText || hasStar(path):
		return []writtenPath{{path, true}}
	}
	out := []writtenPath{{path, true}}
	if hasItems(e.Name(), path) {
		out = append(out, writtenPath{slices.Concat(path, []expr.PathElem{{Name: "*"}}), true})
	}
	return out
}

// writingOf is what an attacker writes of the value of path on e, read as
// text or as all of it.
func writingOf(e analysis.EventActivity, path []expr.PathElem, text bool) writing {
	var c Control
	if text {
		c, _ = LookupText(e.Name(), e.ActivityType(), path)
	} else {
		c = Lookup(e.Name(), e.ActivityType(), path)
	}
	switch c {
	case ControlUnknown:
		return writing{on: true, lines: true, dash: true, cmd: CommandWritingWritten}
	case ControlArbitrary:
		// a leaf of hyphenless does not begin with -; any other arbitrary
		// value, objects and github[x] among them, may
		return writing{on: true, lines: true, dash: !hyphenlessLeaf(e.Name(), e.ActivityType(), path), cmd: WorkflowCommand(e.Name(), e.ActivityType(), path)}
	case ControlStructured:
		// a structured value not known to begin with - is not known not to,
		// but one of login-prefixed, which begins with a login
		dash := leadingDash(e.Name(), e.ActivityType(), path, text)
		return writing{on: true, dash: dash, dashUndecided: !dash && !loginPrefixedLeaf(e.Name(), e.ActivityType(), path), repoName: dash && repoName(e.Name(), e.ActivityType(), path, text), cmd: WorkflowCommand(e.Name(), e.ActivityType(), path), path: PathCommand(e.Name(), e.ActivityType(), path)}
	}
	return writing{}
}

// mayBeCollection is whether the value of n, which a ${{ }} writes in a
// value position (after the path after), may be an object or an array on
// one of c's events: a reference to one (collectionPath), a star taken of
// a value that is not a reference (an array), or fromJSON, whose value the
// JSON decides. Only the operands that may be the value count: those of
// ||, the last of && (the others are the value only when falsy, which an
// object never is), the values of case; a function that makes a string or
// a bool does not.
func (c scope) mayBeCollection(n expr.Node, after []expr.PathElem) bool {
	if n == nil {
		return false
	}
	if p, ok := expr.AccessPath(n); ok {
		return c.collectionPath(slices.Concat(p, after))
	}
	switch x := n.(type) {
	case *expr.Group:
		return c.mayBeCollection(x.X, after)
	case *expr.Logical:
		ops := x.Xs
		if x.Op == expr.OpAnd {
			ops = ops[len(ops)-1:]
		}
		return slices.ContainsFunc(ops, func(o expr.Node) bool { return c.mayBeCollection(o, after) })
	case *expr.Property:
		return c.mayBeCollection(x.X, slices.Concat([]expr.PathElem{{Name: x.Name}}, after))
	case *expr.Index:
		return c.mayBeCollection(x.X, slices.Concat([]expr.PathElem{indexElem(x)}, after))
	case *expr.Star:
		return true
	case *expr.Call:
		switch strings.ToLower(x.Name) {
		case "fromjson":
			return true
		case "case":
			for i := 1; i < len(x.Args); i += 2 {
				if c.mayBeCollection(x.Args[i], after) {
					return true
				}
			}
			return len(x.Args)%2 == 1 && c.mayBeCollection(x.Args[len(x.Args)-1], after)
		}
	}
	return false
}

// collectionPath is whether the value of path may be an object or an array
// on one of c's events: through a star, all of a context (wholeObject), a
// name below github not known (github[x]), an object of the payload
// (LookupText, which reads an index not known as any item or key) or a key
// the schema does not have for any activity type of the event
// (ControlUnknown and not inTable, which may be anything), and a
// value of a matrix, which include may make an object.
func (c scope) collectionPath(path []expr.PathElem) bool {
	if hasStar(path) || wholeObject(path) {
		return true
	}
	switch expr.FoldName(path[0].Name) {
	case "github":
		if len(path) > 1 && path[1].Name == "" {
			return true // github[x]: the event, an object, or a text
		}
		for _, e := range c.events {
			if ctl, collection := LookupText(e.Name(), e.ActivityType(), path); collection || ctl == ControlUnknown && expr.HasPrefix(path, "github", "event") && !inTable(e.Name(), path) {
				return true
			}
		}
	case "matrix":
		return len(path) > 1
	}
	return false
}

// collectionParts are the indexes of the parts of v whose value may be an
// object or an array (mayBeCollection).
func (c scope) collectionParts(v workflow.String) []int {
	var out []int
	for i, p := range v.Parts {
		if p.Expr && p.Tree != nil && c.mayBeCollection(p.Tree, nil) {
			out = append(out, i)
		}
	}
	return out
}
