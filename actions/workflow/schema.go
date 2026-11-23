package workflow

import "github.com/gh-intel/sisakulint/actions/expr"

//go:generate go run ./internal/schemagen

// defID names a definition of the schema (schema_gen.go).
type defID uint16

type defKind uint8

const (
	kindNull defKind = iota
	kindBool
	kindNumber
	kindString
	kindAllowed // a one-of of string constants
	kindSequence
	kindMapping
	kindOneOf
)

// schemaDef is one definition of the schemas under schema/; those of
// action.yml have names that start with action:.
type schemaDef struct {
	name     string
	kind     defKind
	names    expr.Names // the contexts and the functions it lists: expressions are allowed in it and below it, and the places below add theirs
	constant string
	nonEmpty bool
	allowed  []string
	item     defID
	props    []schemaProp // sorted by name
	loose    bool
	looseKey defID
	// looseValue is the definition of the values of a loose mapping.
	looseValue defID
	oneOf      []defID
}

type schemaProp struct {
	name     string
	def      defID
	required bool
}

// acceptsString is whether the string definition d takes text: its
// constant when it has one, else any string, but the empty one when d is
// non-empty.
func (d *schemaDef) acceptsString(text string) bool {
	if d.constant != "" {
		return text == d.constant
	}
	return !d.nonEmpty || text != ""
}

// prop returns the property of the mapping definition d named name, which
// is compared exactly.
func (d *schemaDef) prop(name string) (schemaProp, bool) {
	lo, hi := 0, len(d.props)
	for lo < hi {
		m := (lo + hi) / 2
		switch p := d.props[m]; {
		case p.name == name:
			return p, true
		case p.name < name:
			lo = m + 1
		default:
			hi = m
		}
	}
	return schemaProp{}, false
}

// ofKind appends the definitions of d, through one-of, whose kind is in
// kinds (DefinitionInfo.getDefinitionsOfType).
func ofKind(d defID, out []defID, kinds ...defKind) []defID {
	def := &schemaDefs[d]
	if def.kind == kindOneOf {
		for _, o := range def.oneOf {
			out = ofKind(o, out, kinds...)
		}
		return out
	}
	for _, k := range kinds {
		if def.kind == k {
			return append(out, d)
		}
	}
	return out
}
