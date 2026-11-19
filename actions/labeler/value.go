package labeler

import (
	"errors"
	"fmt"
	"regexp"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/scalar"
)

// ErrUnsupportedSyntax is a configuration with YAML whose reading by
// js-yaml, which the labeler loads the file with, is not known to be the
// same as the reading here: an anchor, an alias, a tag or a merge key.
var ErrUnsupportedSyntax = errors.New("the configuration has an anchor, an alias, a tag or a merge key")

// valueKind is the kind of a value as the JavaScript of the labeler sees
// it after js-yaml loads the file.
type valueKind uint8

const (
	kindNull valueKind = iota
	kindString
	kindNumber
	kindBool
	kindSequence
	kindMapping
)

// value is a value of the configuration: a scalar resolved by the core
// schema of js-yaml, a sequence or a mapping of string keys.
type value struct {
	kind    valueKind
	text    string // of a scalar
	items   []value
	entries []entry
}

type entry struct {
	key string
	val value
}

// lookup is the value of the key k of the mapping v.
func (v value) lookup(k string) (value, bool) {
	for _, e := range v.entries {
		if e.key == k {
			return e.val, true
		}
	}
	return value{}, false
}

// list is the value as the labeler makes a list of it: a sequence as it
// is, anything else as the one item (Array.isArray(x) ? x : [x]).
func (v value) list() []value {
	if v.kind == kindSequence {
		return v.items
	}
	return []value{v}
}

// readValue reads the one document of text; a file with no document is
// the null value.
func readValue(text []byte) (value, error) {
	t := cst.ParseMode(text, cst.ModeSpec)
	if len(t.Errors()) != 0 {
		return value{}, fmt.Errorf("the configuration is not YAML that reads: %v", t.Errors()[0])
	}
	var docs []cst.Node
	for e := range t.Root().Children() {
		if d, ok := e.Node(); ok && d.Kind() == cst.NodeDocument {
			docs = append(docs, d)
		}
	}
	switch len(docs) {
	case 0:
		return value{}, nil
	case 1:
	default:
		return value{}, errors.New("the configuration has more than one document, which js-yaml's load refuses")
	}
	for c := range docs[0].Children() {
		if n, ok := c.Node(); ok && n.Kind() != cst.NodeDirective {
			return nodeValue(n)
		}
	}
	return value{}, nil
}

func nodeValue(n cst.Node) (value, error) {
	if _, ok := n.Anchor(); ok {
		return value{}, ErrUnsupportedSyntax
	}
	if _, ok := n.Tag(); ok {
		return value{}, ErrUnsupportedSyntax
	}
	if n.Kind() == cst.NodeAlias {
		return value{}, ErrUnsupportedSyntax
	}
	if m, ok := n.Mapping(); ok {
		v := value{kind: kindMapping}
		for e := range m.Entries() {
			k, err := nodeValue(e.Key)
			if err != nil {
				return value{}, err
			}
			if k.kind == kindSequence || k.kind == kindMapping {
				return value{}, ErrUnsupportedSyntax
			}
			if k.kind == kindString && k.text == "<<" {
				return value{}, ErrUnsupportedSyntax
			}
			if _, dup := v.lookup(k.text); dup {
				return value{}, fmt.Errorf("the key %s is there twice, which js-yaml's load refuses", k.text)
			}
			val, err := nodeValue(e.Value)
			if err != nil {
				return value{}, err
			}
			v.entries = append(v.entries, entry{k.text, val})
		}
		return v, nil
	}
	if s, ok := n.Sequence(); ok {
		v := value{kind: kindSequence, items: []value{}}
		for item := range s.Items() {
			iv, err := nodeValue(item)
			if err != nil {
				return value{}, err
			}
			v.items = append(v.items, iv)
		}
		return v, nil
	}
	s, ok := scalar.Decode(n)
	if !ok {
		return value{}, fmt.Errorf("a node of kind %v is not a value", n.Kind())
	}
	if s.Style() != cst.Plain {
		return value{kind: kindString, text: s.String()}, nil
	}
	return plainValue(s.String()), nil
}

var (
	coreNull   = regexp.MustCompile(`^(?:~|null|Null|NULL|)$`)
	coreBool   = regexp.MustCompile(`^(?:true|True|TRUE|false|False|FALSE)$`)
	coreNumber = regexp.MustCompile(`^(?:[-+]?(?:0|[1-9][0-9_]*)|0x[0-9a-fA-F_]+|0o[0-7_]+|[-+]?[0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][-+]?[0-9]+)?|\.[0-9_]+(?:[eE][-+]?[0-9]+)?|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)
)

// plainValue resolves a plain scalar as the core schema of js-yaml does:
// null, a boolean, a number, else a string.
func plainValue(s string) value {
	switch {
	case coreNull.MatchString(s):
		return value{kind: kindNull, text: s}
	case coreBool.MatchString(s):
		return value{kind: kindBool, text: s}
	case coreNumber.MatchString(s):
		return value{kind: kindNumber, text: s}
	}
	return value{kind: kindString, text: s}
}
