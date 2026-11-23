package scalar

import (
	"strings"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// Tag is a tag after expansion, such as "tag:yaml.org,2002:str", a local
// tag "!foo", or the non-specific "!". Explicit, Resolve and PlainTag make
// it; the zero Tag is none.
type Tag struct{ s string }

func (t Tag) String() string { return t.s }

const tagPrefix = "tag:yaml.org,2002:"

// The tags of the failsafe, JSON and core schemas (10.1–10.3), and the
// non-specific tag (6.9.1).
var (
	TagNull        = Tag{tagPrefix + "null"}
	TagBool        = Tag{tagPrefix + "bool"}
	TagInt         = Tag{tagPrefix + "int"}
	TagFloat       = Tag{tagPrefix + "float"}
	TagStr         = Tag{tagPrefix + "str"}
	TagSeq         = Tag{tagPrefix + "seq"}
	TagMap         = Tag{tagPrefix + "map"}
	TagNonSpecific = Tag{"!"}
)

// Directives are a document's %TAG directives (6.8.2): handle → prefix.
type Directives struct {
	handles, prefixes []string
}

// DirectivesOf reads the %TAG directives of doc, a Document node. "!" and
// "!!" are "!" and "tag:yaml.org,2002:" unless a directive changes them.
func DirectivesOf(doc cst.Node) Directives {
	var d Directives
	if doc.Kind() != cst.NodeDocument {
		return d
	}
	for e := range doc.Children() {
		dir, ok := e.Node()
		if !ok || dir.Kind() != cst.NodeDirective {
			continue
		}
		var words []string
		for t := range dir.Tokens() {
			if t.Kind() == cst.TokDirective || t.Kind() == cst.TokDirectiveParam {
				words = append(words, string(t.Bytes()))
			}
		}
		if len(words) == 3 && words[0] == "%TAG" {
			d.handles = append(d.handles, words[1])
			d.prefixes = append(d.prefixes, words[2])
		}
	}
	return d
}

func (d Directives) prefix(handle string) (string, bool) {
	for i, h := range d.handles {
		if h == handle {
			return d.prefixes[i], true
		}
	}
	switch handle {
	case "!":
		return "!", true
	case "!!":
		return tagPrefix, true
	}
	return "", false
}

// Explicit is the tag written on n, expanded (6.9.1): a verbatim tag as
// is, a shorthand with its handle replaced by the prefix and its %xx
// escapes decoded, and the non-specific "!" as "!". A named handle without
// a %TAG directive, which the parser reports, is returned as written.
func Explicit(n cst.Node, d Directives) (Tag, bool) {
	t, ok := n.Tag()
	if !ok {
		return Tag{}, false
	}
	s := string(t.Bytes())
	if strings.HasPrefix(s, "!<") && strings.HasSuffix(s, ">") { // [98] c-verbatim-tag
		return Tag{s[2 : len(s)-1]}, true
	}
	if s == "!" { // [100] c-non-specific-tag
		return TagNonSpecific, true
	}
	handle, suffix := "!", s[1:] // [99] c-ns-shorthand-tag
	if i := strings.IndexByte(s[1:], '!'); i >= 0 {
		handle, suffix = s[:i+2], s[i+2:]
	}
	p, ok := d.prefix(handle)
	if !ok {
		return Tag{s}, true
	}
	return Tag{p + unescapeURI(suffix)}, true
}

// unescapeURI decodes the %xx escapes of [39] ns-uri-char; an invalid one
// is kept.
func unescapeURI(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(hexVal(s[i+1])<<4 | hexVal(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// Resolve is the tag of n after resolution (10.3.2): the explicit tag,
// with "!" meaning str, seq or map by the node's kind; without one, map or
// seq for collections, str for quoted and block scalars, and the core
// schema's tag of a plain scalar's value. An Alias node's tag is that of
// the node it refers to, so Resolve returns the zero Tag for it, as for
// nodes that are no content.
func Resolve(n cst.Node, d Directives) Tag {
	var kind Tag
	switch {
	case n.Kind() == cst.NodeScalar:
		kind = TagStr
	case isMapping(n):
		kind = TagMap
	case isSequence(n):
		kind = TagSeq
	default:
		return Tag{}
	}
	if t, ok := Explicit(n, d); ok {
		if t == TagNonSpecific {
			return kind
		}
		return t
	}
	if kind != TagStr || n.Style() != cst.Plain {
		return kind
	}
	v, _ := Decode(n)
	return PlainTag(v.String())
}

func isMapping(n cst.Node) bool  { _, ok := n.Mapping(); return ok }
func isSequence(n cst.Node) bool { _, ok := n.Sequence(); return ok }

// PlainTag is the tag the core schema gives an untagged plain scalar
// whose value is s.
func PlainTag(s string) Tag {
	switch {
	case isNull(s):
		return TagNull
	case isBool(s):
		return TagBool
	case isInt(s):
		return TagInt
	case isFloat(s):
		return TagFloat
	}
	return TagStr
}
