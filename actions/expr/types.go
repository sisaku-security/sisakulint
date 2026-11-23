package expr

import (
	"encoding/json"
	"errors"
	"strings"
)

// ValueType is a type of the value of an expression when it runs.
type ValueType uint8

const (
	ValueTypeUnset ValueType = iota
	ValueNull
	ValueBoolean
	ValueNumber
	ValueString
	ValueObject
	ValueArray
)

var valueTypeNames = [...]string{"ValueTypeUnset", "ValueNull", "ValueBoolean", "ValueNumber", "ValueString", "ValueObject", "ValueArray"}

func (v ValueType) String() string { return valueTypeNames[v] }

// valueTypeArgs are the values of $defs/value-type of the schema of
// findings (actions/rules/schema/findings-v0.json).
var valueTypeArgs = [...]string{"", "null", "boolean", "number", "string", "object", "array"}

// MarshalJSON writes v as the schema of findings names it; ValueTypeUnset
// has no name there.
func (v ValueType) MarshalJSON() ([]byte, error) {
	if v == ValueTypeUnset {
		return nil, errors.New("ValueTypeUnset is no type")
	}
	return json.Marshal(valueTypeArgs[v])
}

// ValueTypes are the types, ValueNull to ValueArray.
func ValueTypes() []ValueType {
	return []ValueType{ValueNull, ValueBoolean, ValueNumber, ValueString, ValueObject, ValueArray}
}

// the bits of a Type: each type, and of a boolean, a number and a string
// whether the value is truthy (an if reads null, false, 0 and the empty
// string as false; an object and an array as true)
const (
	bNull uint16 = 1 << iota
	bTrue
	bFalse
	bNonzero
	bZero
	bNonEmpty
	bEmpty
	bObject
	bArray

	bAll    = bNull | bTrue | bFalse | bNonzero | bZero | bNonEmpty | bEmpty | bObject | bArray
	bFalsy  = bNull | bFalse | bZero | bEmpty
	bTruthy = bAll &^ bFalsy
)

var typeBits = [...]uint16{ValueNull: bNull, ValueBoolean: bTrue | bFalse, ValueNumber: bNonzero | bZero, ValueString: bNonEmpty | bEmpty, ValueObject: bObject, ValueArray: bArray}

// Type is what an expression may be when it runs: a set of value types,
// and of a boolean, a number and a string, whether it may be truthy and
// whether it may be falsy, for && and ||, which give one of their operands.
// The zero Type is not known: it may be any value.
type Type struct{ bits uint16 }

func (t Type) set() uint16 {
	if t.bits == 0 {
		return bAll
	}
	return t.bits
}

func typeOfBits(b uint16) Type {
	if b == bAll {
		return Type{}
	}
	return Type{b}
}

// AnyType is a type not known: any value.
func AnyType() Type { return Type{} }

// TypeOf is the type v, truthy or not.
func TypeOf(v ValueType) Type { return typeOfBits(typeBits[v]) }

// Union is a value of t or of o.
func (t Type) Union(o Type) Type { return typeOfBits(t.set() | o.set()) }

// Known is whether t is not AnyType: something is known of the value,
// though it may still be of every type (x || null).
func (t Type) Known() bool { return t.bits != 0 }

// may is whether t may be of the type v.
func (t Type) may(v ValueType) bool { return t.set()&typeBits[v] != 0 }

// ValueTypes are the types t may be, in the order of ValueTypes.
func (t Type) ValueTypes() []ValueType {
	var out []ValueType
	for _, v := range ValueTypes() {
		if t.set()&typeBits[v] != 0 {
			out = append(out, v)
		}
	}
	return out
}

// Only is whether every type t may be is one of vs.
func (t Type) Only(vs ...ValueType) bool {
	var b uint16
	for _, v := range vs {
		b |= typeBits[v]
	}
	return t.set()&^b == 0
}

// falsy and truthy are the bits of the falsy and the truthy part of t;
// 0 when t is never such (not a Type: the zero Type is any value).
func (t Type) falsy() uint16  { return t.set() & bFalsy }
func (t Type) truthy() uint16 { return t.set() & bTruthy }

// TypeOfExpr is the type of n when it runs: the type
// follows the form of n, not its value. lookup gives the types of the
// references it knows (by AccessPath); a reference it does not answer, and
// a function it does not type, may be any value. A reference through a
// star is an array: the runner makes an empty array of a star on what is
// not an object or an array.
func TypeOfExpr(n Node, lookup func(path []PathElem) (Type, bool)) Type {
	switch x := n.(type) {
	case *Literal:
		v := literal(x)
		var b uint16
		switch x.Kind {
		case LitNull:
			b = bNull
		case LitBool:
			b = bFalse
			if v.Truthy() == TruthTrue {
				b = bTrue
			}
		case LitNumber:
			// literal reads decimals only; 0x10 and Infinity may be either
			switch v.Truthy() {
			case TruthTrue:
				b = bNonzero
			case TruthFalse:
				b = bZero
			default:
				b = bNonzero | bZero
			}
		case LitString:
			b = bEmpty
			if x.Str != "" {
				b = bNonEmpty
			}
		}
		return Type{b}
	case *Group:
		return TypeOfExpr(x.X, lookup)
	case *Context, *Property, *Index, *Star:
		p, ok := AccessPath(n)
		if !ok {
			return AnyType()
		}
		for _, e := range p {
			if e.Star {
				return TypeOf(ValueArray)
			}
		}
		if t, ok := lookup(p); ok {
			return t
		}
		return AnyType()
	case *Not, *Compare:
		return TypeOf(ValueBoolean)
	case *Logical:
		return logicalType(x, lookup)
	case *Call:
		return callType(x, lookup)
	}
	return AnyType()
}

// logicalType is the type of x: && gives its first falsy operand, else its
// last; || its first truthy operand, else its last. An operand after one
// that can never let the evaluation go on is not reached.
func logicalType(x *Logical, lookup func([]PathElem) (Type, bool)) Type {
	var acc uint16
	for i, o := range x.Xs {
		t := TypeOfExpr(o, lookup)
		if i == len(x.Xs)-1 {
			acc |= t.set()
			break
		}
		stop, goOn := t.falsy(), t.truthy() // &&
		if x.Op == OpOr {
			stop, goOn = goOn, stop
		}
		acc |= stop
		if goOn == 0 {
			break
		}
	}
	return typeOfBits(acc)
}

func callType(x *Call, lookup func([]PathElem) (Type, bool)) Type {
	switch strings.ToLower(x.Name) {
	case "contains", "startswith", "endswith", "always", "success", "failure", "cancelled":
		return TypeOf(ValueBoolean)
	case "format", "join", "tojson", "hashfiles":
		return TypeOf(ValueString)
	case "fromjson":
		if len(x.Args) == 1 {
			if l, ok := x.Args[0].(*Literal); ok && l.Kind == LitString {
				var v any
				if json.Unmarshal([]byte(l.Str), &v) == nil {
					return jsonType(v)
				}
			}
		}
	case "case":
		if len(x.Args)%2 == 1 {
			var acc Type
			for i := 1; i < len(x.Args); i += 2 {
				acc = typeOfBits(acc.bits | TypeOfExpr(x.Args[i], lookup).set())
			}
			last := TypeOfExpr(x.Args[len(x.Args)-1], lookup)
			return typeOfBits(acc.bits | last.set())
		}
	}
	return AnyType()
}

// jsonType is the type of v, a value json.Unmarshal gave.
func jsonType(v any) Type {
	switch x := v.(type) {
	case nil:
		return Type{bNull}
	case bool:
		if x {
			return Type{bTrue}
		}
		return Type{bFalse}
	case float64:
		if x != 0 {
			return Type{bNonzero}
		}
		return Type{bZero}
	case string:
		if x != "" {
			return Type{bNonEmpty}
		}
		return Type{bEmpty}
	case []any:
		return Type{bArray}
	}
	return Type{bObject}
}

// CallMistakeKind is a call that fails when the runner evaluates it.
type CallMistakeKind uint8

const (
	CallMistakeUnset CallMistakeKind = iota
	// MistakeFormatArguments: format() whose format string, a literal,
	// has a placeholder whose number is not less than the number of the
	// other arguments, before any other error of the format string.
	MistakeFormatArguments
	// MistakeCasePredicate: case() with a predicate that is not a
	// boolean, reached: no predicate before it is always true.
	MistakeCasePredicate
	// MistakeFromJSONArgument: fromJSON() of an object or an array, which
	// it reads as the text Object or Array.
	MistakeFromJSONArgument
)

var callMistakeKindNames = [...]string{"CallMistakeUnset", "MistakeFormatArguments", "MistakeCasePredicate", "MistakeFromJSONArgument"}

func (k CallMistakeKind) String() string { return callMistakeKindNames[k] }

// CallMistake is a call of n that fails when it runs. Arg is the
// predicate of case() or the argument of fromJSON(); nil for format().
type CallMistake struct {
	Kind CallMistakeKind
	Call *Call
	Arg  Node
}

// CallMistakes are the calls of n that fail when the runner evaluates
// them, in the order of n, with the types of the references lookup gives.
// A call the evaluation never reaches is left out when Partial knows it:
// after an operand of && that is false, after an operand of || that is
// true; the value of a predicate of case() that is false, and all after a
// predicate that is true; an argument of format() that no placeholder of
// its literal format string names. A predicate of case() is a mistake
// only when it cannot be a boolean; an argument of fromJSON() only when it
// can only be an object or an array.
func CallMistakes(n Node, lookup func(path []PathElem) (Type, bool)) []CallMistake {
	var out []CallMistake
	var walk func(Node)
	walk = func(n Node) {
		switch x := n.(type) {
		case *Logical:
			for _, o := range x.Xs {
				walk(o)
				t := Partial(o, noValues).Truthy()
				if x.Op == OpAnd && t == TruthFalse || x.Op == OpOr && t == TruthTrue {
					return
				}
			}
			return
		case *Call:
			switch strings.ToLower(x.Name) {
			case "case":
				if len(x.Args)%2 == 0 {
					break // the parser refuses it (CheckNames)
				}
				for i := 0; i+1 < len(x.Args); i += 2 {
					p := x.Args[i]
					walk(p)
					if t := TypeOfExpr(p, lookup); t.Known() && !t.may(ValueBoolean) {
						out = append(out, CallMistake{Kind: MistakeCasePredicate, Call: x, Arg: p})
						return
					}
					switch Partial(p, noValues).Truthy() {
					case TruthTrue:
						walk(x.Args[i+1])
						return
					case TruthUnknown:
						walk(x.Args[i+1])
					}
				}
				walk(x.Args[len(x.Args)-1])
				return
			case "format":
				if len(x.Args) == 0 {
					return // the parser refuses it (CheckNames)
				}
				walk(x.Args[0])
				l, ok := x.Args[0].(*Literal)
				if !ok || l.Kind != LitString {
					for _, a := range x.Args[1:] {
						walk(a)
					}
					return
				}
				refs, missing := FormatRefs(l.Str, len(x.Args)-1)
				for i, a := range x.Args[1:] {
					if refs[i] {
						walk(a)
					}
				}
				if missing {
					out = append(out, CallMistake{Kind: MistakeFormatArguments, Call: x})
				}
				return
			case "fromjson":
				for _, a := range x.Args {
					walk(a)
				}
				if len(x.Args) == 1 {
					if t := TypeOfExpr(x.Args[0], lookup); t.Known() && t.Only(ValueObject, ValueArray) {
						out = append(out, CallMistake{Kind: MistakeFromJSONArgument, Call: x, Arg: x.Args[0]})
					}
				}
				return
			}
		}
		for _, c := range Children(n) {
			walk(c)
		}
	}
	walk(n)
	return out
}

func noValues([]PathElem) (Value, bool) { return Value{}, false }

// FormatRefs reads the format string f with args arguments from the left,
// as the runner does (Format.cs): refs are the arguments its
// placeholders name before an error, and missing is whether the first
// error is a placeholder whose number is not less than args. {{ and }}
// are braces, {N} and {N:specifiers} are placeholders (N is digits, zeros
// first or not, at most 255, as Byte.TryParse reads them), and any other
// brace is an error of another kind, which is not reported.
func FormatRefs(f string, args int) (refs []bool, missing bool) {
	refs = make([]bool, args)
	return refs, formatScan(f, args, refs)
}

func formatScan(f string, args int, refs []bool) bool {
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case '{':
			if i+1 < len(f) && f[i+1] == '{' {
				i++
				continue
			}
			j := i + 1
			for j < len(f) && f[j] >= '0' && f[j] <= '9' {
				j++
			}
			if j == i+1 {
				return false
			}
			end := strings.IndexByte(f[j:], '}')
			if end < 0 || end > 0 && f[j] != ':' {
				return false
			}
			n := 0
			for _, c := range f[i+1 : j] {
				if n = n*10 + int(c-'0'); n > 255 {
					return false
				}
			}
			if n >= args {
				return true
			}
			refs[n] = true
			i = j + end
		case '}':
			if i+1 < len(f) && f[i+1] == '}' {
				i++
				continue
			}
			return false
		}
	}
	return false
}
