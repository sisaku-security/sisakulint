package edit

import (
	"errors"
	"fmt"
	"strconv"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/scalar"
)

// Value is what an operation writes: a Scalar, a Map or a Seq.
type Value interface{ value() }

// Scalar is a scalar value with its core schema tag. Its style is chosen
// where it is written, unless In fixes it.
type Scalar struct {
	s      string
	tag    scalar.Tag
	style  cst.ScalarStyle
	styled bool
}

// Str is a string. It is written plain when a plain scalar can hold it and
// reads back as a string, and double-quoted otherwise.
func Str(s string) Scalar { return Scalar{s: s, tag: scalar.TagStr} }

func Int(n int64) Scalar { return Scalar{s: strconv.FormatInt(n, 10), tag: scalar.TagInt} }

func Bool(b bool) Scalar { return Scalar{s: strconv.FormatBool(b), tag: scalar.TagBool} }

// Null is written empty after a key in a block mapping, and as "null"
// elsewhere.
func Null() Scalar { return Scalar{tag: scalar.TagNull} }

// In fixes the style the scalar is written in. Writing fails when the
// style cannot hold the value, or would give it another tag.
func (s Scalar) In(style cst.ScalarStyle) Scalar {
	s.style, s.styled = style, true
	return s
}

// Map is a mapping, written in the order of its pairs.
type Map []Pair

// Pair is one entry of a Map. Comment, when not empty, is written as
// comment lines above the entry, one for each line of it.
type Pair struct {
	Key     string
	Value   Value
	Comment string
}

// Seq is a sequence.
type Seq []Value

func (Scalar) value() {}
func (Map) value()    {}
func (Seq) value()    {}

// sameValue reports how n, a node read back, differs from v: kinds,
// entries and items in order, keys as strings, scalar values and tags.
func sameValue(n cst.Node, v Value) error {
	d := scalar.DirectivesOf(documentOf(n))
	switch v := v.(type) {
	case Scalar:
		if n.Kind() != cst.NodeScalar {
			return fmt.Errorf("%v, not a scalar", n.Kind())
		}
		got, _ := scalar.Decode(n)
		if v.tag != scalar.TagNull && got.String() != v.s { // null is "", "null" or "~" alike
			return fmt.Errorf("the value is %q, not %q", got.String(), v.s)
		}
		if tag := scalar.Resolve(n, d); tag != v.tag {
			return fmt.Errorf("the tag of %q is %s, not %s", v.s, tag, v.tag)
		}
	case Map:
		m, ok := n.Mapping()
		if !ok {
			return fmt.Errorf("%v, not a mapping", n.Kind())
		}
		i := 0
		for e := range m.Entries() {
			if i == len(v) {
				return fmt.Errorf("more than %d entries", len(v))
			}
			if err := sameValue(e.Key, Str(v[i].Key)); err != nil {
				return fmt.Errorf("key %d: %w", i, err)
			}
			if err := sameValue(e.Value, v[i].Value); err != nil {
				return fmt.Errorf("%q: %w", v[i].Key, err)
			}
			i++
		}
		if i < len(v) {
			return fmt.Errorf("%d entries, not %d", i, len(v))
		}
	case Seq:
		s, ok := n.Sequence()
		if !ok {
			return fmt.Errorf("%v, not a sequence", n.Kind())
		}
		i := 0
		for x := range s.Items() {
			if i == len(v) {
				return fmt.Errorf("more than %d items", len(v))
			}
			if err := sameValue(x, v[i]); err != nil {
				return fmt.Errorf("[%d]: %w", i, err)
			}
			i++
		}
		if i < len(v) {
			return fmt.Errorf("%d items, not %d", i, len(v))
		}
	default:
		return errors.New("no value")
	}
	return nil
}
