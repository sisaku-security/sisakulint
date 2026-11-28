package expr

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// Truth is a value of Kleene's logic: what the truthiness of a value is,
// or that it is not known.
type Truth uint8

const (
	TruthUnknown Truth = iota
	TruthTrue
	TruthFalse
)

var truthNames = [...]string{"unknown", "true", "false"}

func (t Truth) String() string { return truthNames[t] }

func truth(b bool) Truth {
	if b {
		return TruthTrue
	}
	return TruthFalse
}

type valueKind uint8

const (
	vUnknown valueKind = iota
	vNull
	vBool
	vNumber
	vString
	vArray
	vAbstract
)

// Value is what Partial makes of an expression: null, a bool, a number, a
// string, an array, or not known. A value not known may still be known to
// be truthy or not (a && b with b false).
type Value struct {
	k     valueKind
	b     bool
	n     float64
	s     string
	elems []Value
	t     Truth // of a value not known
	a     Abstract
}

// Abstract is a string Partial does not know, of which the one who made it
// tells how it compares. Equal is given any value: a known one, another
// Abstract, or one not known (a reference lookup does not answer), of
// which nothing but unknown is right. The others are given s with its
// ASCII letters lowered: Within, Prefix and Suffix with the abstract string
// as the second argument of the function, Contains, StartsWith and
// EndsWith with it as the first.
type Abstract interface {
	Truthy() Truth
	Equal(other Value) Truth   // == with a value
	Within(s string) Truth     // contains(s, this)
	Prefix(s string) Truth     // startsWith(s, this)
	Suffix(s string) Truth     // endsWith(s, this)
	Contains(s string) Truth   // contains(this, s)
	StartsWith(s string) Truth // startsWith(this, s)
	EndsWith(s string) Truth   // endsWith(this, s)
}

// AbstractValue is a value of which a tells how it compares.
func AbstractValue(a Abstract) Value { return Value{k: vAbstract, a: a} }

// AbstractOf is the Abstract of an abstract value.
func (v Value) AbstractOf() (Abstract, bool) { return v.a, v.k == vAbstract }

// Str is the string of a known string value.
func (v Value) Str() (string, bool) { return v.s, v.k == vString }

func Null() Value            { return Value{k: vNull} }
func Bool(b bool) Value      { return Value{k: vBool, b: b} }
func Number(n float64) Value { return Value{k: vNumber, n: n} }
func String(s string) Value  { return Value{k: vString, s: s} }

// Array is the array of elems, as a reference to the items of an array of
// objects by * makes (github.event.pull_request.labels.*.name).
func Array(elems ...Value) Value { return Value{k: vArray, elems: elems} }

// Elems are the items of a known array value.
func (v Value) Elems() ([]Value, bool) { return v.elems, v.k == vArray }

// Known is whether the value is known.
func (v Value) Known() bool { return v.k != vUnknown && v.k != vAbstract }

// Truthy is whether the value is truthy, as an if reads it: null, false, 0
// and the empty string are not; any other known value is.
func (v Value) Truthy() Truth {
	switch v.k {
	case vNull:
		return TruthFalse
	case vBool:
		return truth(v.b)
	case vNumber:
		return truth(v.n != 0 && v.n == v.n)
	case vString:
		return truth(v.s != "")
	case vArray:
		return TruthTrue
	case vAbstract:
		return v.a.Truthy()
	}
	return v.t
}

// Partial evaluates n as far as it can be before the run: lookup gives
// the values of the references it knows (by AccessPath), and any other
// reference, the functions of a job's state (success() and the like) and
// what GitHub was not seen to do are not known. It evaluates each node
// once, so the time is linear in n.
//
// What it follows: strings compare ignoring case, which is only known of ASCII; a
// number and a numeric string, and null and a string, compare as numbers;
// true and null are not equal;
// && and || are Kleene's and and or of the truthiness of their operands.
func Partial(n Node, lookup func(path []PathElem) (Value, bool)) Value {
	return PartialWith(n, lookup, nil)
}

// PartialWith is Partial, but where override gives a value of a node, that
// is its value: a reader can read one comparison as another.
func PartialWith(n Node, lookup func(path []PathElem) (Value, bool), override func(Node) (Value, bool)) Value {
	if override != nil {
		if v, ok := override(n); ok {
			return v
		}
	}
	switch x := n.(type) {
	case *Literal:
		return literal(x)
	case *Group:
		return PartialWith(x.X, lookup, override)
	case *Context, *Property, *Index, *Star:
		if p, ok := AccessPath(n); ok && !dynamic(p) {
			if v, ok := lookup(p); ok {
				return v
			}
		}
		return Value{}
	case *Not:
		switch PartialWith(x.X, lookup, override).Truthy() {
		case TruthTrue:
			return Bool(false)
		case TruthFalse:
			return Bool(true)
		}
		return Value{}
	case *Logical:
		return logical(x, lookup, override)
	case *Compare:
		l, r := PartialWith(x.X, lookup, override), PartialWith(x.Y, lookup, override)
		switch x.Op {
		case OpEq, OpNe:
			t := equal(l, r)
			if t == TruthUnknown {
				return Value{}
			}
			return Bool((t == TruthTrue) == (x.Op == OpEq))
		}
		return Value{}
	case *Call:
		args := make([]Value, len(x.Args))
		for i, a := range x.Args {
			args[i] = PartialWith(a, lookup, override)
		}
		return call(x.Name, args)
	}
	return Value{}
}

func dynamic(p []PathElem) bool {
	for _, e := range p {
		if e.Dynamic != nil || e.Star {
			return true
		}
	}
	return false
}

// logical is && (the first operand not truthy, else the last) and || (the
// first truthy, else the last); when an operand is not known, only the
// truthiness of the whole may be.
func logical(x *Logical, lookup func([]PathElem) (Value, bool), override func(Node) (Value, bool)) Value {
	stop := TruthFalse // &&
	if x.Op == OpOr {
		stop = TruthTrue
	}
	var last Value
	allKnown, truthKnown := true, true
	for _, o := range x.Xs {
		v := PartialWith(o, lookup, override)
		t := v.Truthy()
		if t == stop {
			if allKnown {
				return v
			}
			return Value{t: stop}
		}
		allKnown = allKnown && v.Known()
		truthKnown = truthKnown && t != TruthUnknown
		last = v
	}
	switch {
	case allKnown:
		return last
	case truthKnown: // no operand stops it
		return Value{t: last.Truthy()}
	}
	return Value{}
}

var decimal = regexp.MustCompile(`^[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$`)

// number is s as a number, when it is written in decimal (the empty
// string is 0).
func number(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, true
	}
	if !decimal.MatchString(s) {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}

func literal(l *Literal) Value {
	switch l.Kind {
	case LitNull:
		return Null()
	case LitBool:
		return Bool(l.Raw == "true")
	case LitNumber:
		if f, ok := number(l.Raw); ok {
			return Number(f)
		}
		return Value{}
	}
	return String(l.Str)
}

func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// equal is ==: strings ignore the case of ASCII letters; a number and
// a numeric string, and null and a string, compare as numbers; true and
// null are not equal, as GitHub reads true as 1 and null as 0
// (https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#operators).
func equal(a, b Value) Truth {
	if a.k == vAbstract {
		return a.a.Equal(b)
	}
	if b.k == vAbstract {
		return b.a.Equal(a)
	}
	if !a.Known() || !b.Known() || a.k == vArray || b.k == vArray {
		return TruthUnknown
	}
	if a.k == b.k {
		switch a.k {
		case vNull:
			return TruthTrue
		case vBool:
			return truth(a.b == b.b)
		case vNumber:
			return truth(a.n == b.n)
		}
		if a.s == b.s {
			return TruthTrue
		}
		if ascii(a.s) && ascii(b.s) {
			return truth(strings.EqualFold(a.s, b.s))
		}
		return TruthUnknown
	}
	asNumber := func(v Value) (float64, bool) {
		switch v.k {
		case vNull:
			return 0, true
		case vNumber:
			return v.n, true
		case vString:
			return number(v.s)
		}
		return 0, false
	}
	if a.k == vBool || b.k == vBool {
		if (a.k == vNull && b.b) || (b.k == vNull && a.b) {
			return TruthFalse // true is 1 and null is 0
		}
		return TruthUnknown
	}
	x, okA := asNumber(a)
	y, okB := asNumber(b)
	if !okA || !okB {
		return TruthUnknown
	}
	return truth(x == y)
}

// fold is s with its ASCII letters lowered; ok is false when s has other
// letters, whose case GitHub was not seen to ignore.
func fold(s string) (string, bool) {
	if !ascii(s) {
		return "", false
	}
	return strings.ToLower(s), true
}

func call(name string, args []Value) Value {
	strs := func() ([]string, bool) {
		out := make([]string, len(args))
		for i, a := range args {
			if a.k != vString {
				return nil, false
			}
			f, ok := fold(a.s)
			if !ok {
				return nil, false
			}
			out[i] = f
		}
		return out, true
	}
	abstractItem := func() (string, Abstract, bool) {
		if len(args) != 2 || args[0].k != vString || args[1].k != vAbstract {
			return "", nil, false
		}
		s, ok := fold(args[0].s)
		return s, args[1].a, ok
	}
	abstractHolder := func() (Abstract, string, bool) {
		if len(args) != 2 || args[0].k != vAbstract || args[1].k != vString {
			return nil, "", false
		}
		s, ok := fold(args[1].s)
		return args[0].a, s, ok
	}
	switch strings.ToLower(name) {
	case "startswith", "endswith":
		if s, a, ok := abstractItem(); ok {
			if strings.EqualFold(name, "startsWith") {
				return truthValue(a.Prefix(s))
			}
			return truthValue(a.Suffix(s))
		}
		if a, s, ok := abstractHolder(); ok {
			if strings.EqualFold(name, "startsWith") {
				return truthValue(a.StartsWith(s))
			}
			return truthValue(a.EndsWith(s))
		}
		s, ok := strs()
		if !ok || len(s) != 2 {
			return Value{}
		}
		if strings.EqualFold(name, "startsWith") {
			return Bool(strings.HasPrefix(s[0], s[1]))
		}
		return Bool(strings.HasSuffix(s[0], s[1]))
	case "contains":
		if len(args) != 2 {
			return Value{}
		}
		if s, a, ok := abstractItem(); ok {
			return truthValue(a.Within(s))
		}
		if a, s, ok := abstractHolder(); ok {
			return truthValue(a.Contains(s))
		}
		if args[0].k == vArray {
			out := TruthFalse
			for _, e := range args[0].elems {
				switch equal(e, args[1]) {
				case TruthTrue:
					return Bool(true)
				case TruthUnknown:
					out = TruthUnknown
				}
			}
			if out == TruthUnknown {
				return Value{}
			}
			return Bool(false)
		}
		s, ok := strs()
		if !ok {
			return Value{}
		}
		return Bool(strings.Contains(s[0], s[1]))
	case "fromjson":
		if len(args) != 1 || args[0].k != vString {
			return Value{}
		}
		var v any
		if json.Unmarshal([]byte(args[0].s), &v) != nil {
			return Value{}
		}
		return fromJSON(v)
	case "format":
		return format(args)
	}
	return Value{}
}

// truthValue is the bool of t, or a value not known.
func truthValue(t Truth) Value {
	switch t {
	case TruthTrue:
		return Bool(true)
	case TruthFalse:
		return Bool(false)
	}
	return Value{}
}

func fromJSON(v any) Value {
	switch x := v.(type) {
	case nil:
		return Null()
	case bool:
		return Bool(x)
	case float64:
		return Number(x)
	case string:
		return String(x)
	case []any:
		out := Value{k: vArray}
		for _, e := range x {
			out.elems = append(out.elems, fromJSON(e))
		}
		return out
	}
	return Value{}
}

// format fills {0}, {1} and so on of its first argument with the others;
// {{ and }} are braces. Only strings, null and bools are filled in, whose
// text is known.
func format(args []Value) Value {
	if len(args) == 0 || args[0].k != vString {
		return Value{}
	}
	text := make([]string, len(args)-1)
	for i, a := range args[1:] {
		switch a.k {
		case vString:
			text[i] = a.s
		case vNull:
			text[i] = ""
		case vBool:
			text[i] = strconv.FormatBool(a.b)
		default:
			return Value{}
		}
	}
	f := args[0].s
	var b strings.Builder
	for i := 0; i < len(f); i++ {
		switch {
		case strings.HasPrefix(f[i:], "{{"), strings.HasPrefix(f[i:], "}}"):
			b.WriteByte(f[i])
			i++
		case f[i] == '{':
			j := strings.IndexByte(f[i:], '}')
			if j < 0 {
				return Value{}
			}
			k, err := strconv.Atoi(f[i+1 : i+j])
			if err != nil || k < 0 || k >= len(text) {
				return Value{}
			}
			b.WriteString(text[k])
			i += j
		case f[i] == '}':
			return Value{}
		default:
			b.WriteByte(f[i])
		}
	}
	return String(b.String())
}
