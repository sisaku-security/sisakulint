package expr

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// PathElem is one step of a reference: a name (a property, or an index by
// a string literal), a star, or an index by any other expression.
type PathElem struct {
	Name    string
	Star    bool
	Dynamic Node
}

// AccessPath returns the steps of a reference that starts at a context and
// goes through properties, indexes and stars; groups are looked through.
// github.event.issue.title and github['event']['issue'].title give the same
// steps. It is false for anything else, such as fromJSON(x).a.
// Names are as written; compare them with EqualName.
func AccessPath(n Node) ([]PathElem, bool) {
	var p []PathElem
	for {
		switch x := n.(type) {
		case *Context:
			p = append(p, PathElem{Name: x.Name})
			for i, j := 0, len(p)-1; i < j; i, j = i+1, j-1 {
				p[i], p[j] = p[j], p[i]
			}
			return p, true
		case *Property:
			p = append(p, PathElem{Name: x.Name})
			n = x.X
		case *Star:
			p = append(p, PathElem{Star: true})
			n = x.X
		case *Index:
			if lit, ok := x.Index.(*Literal); ok && lit.Kind == LitString {
				p = append(p, PathElem{Name: lit.Str})
			} else {
				p = append(p, PathElem{Dynamic: x.Index})
			}
			n = x.X
		case *Group:
			n = x.X
		default:
			return nil, false
		}
	}
}

// HasPrefix is whether p starts with the names names, compared by
// EqualName; a star or an index that is not a string literal matches none.
func HasPrefix(p []PathElem, names ...string) bool {
	if len(p) < len(names) {
		return false
	}
	for i, n := range names {
		if p[i].Name == "" || !EqualName(p[i].Name, n) {
			return false
		}
	}
	return true
}

// PathIs is whether p is the names names and nothing more, compared by
// EqualName; a star or an index that is not a string literal matches none.
func PathIs(p []PathElem, names ...string) bool {
	return len(p) == len(names) && HasPrefix(p, names...)
}

// IsPath is whether n is a reference whose steps are the names names and
// nothing more (PathIs): github['token'] and github . token are the path
// github.token.
func IsPath(n Node, names ...string) bool {
	p, ok := AccessPath(n)
	return ok && PathIs(p, names...)
}

// EqualName compares names the way GitHub compares the keys of a mapping:
// each character lowered. Context and function names, which
// are ASCII, compare the same way.
func EqualName(a, b string) bool {
	for a != "" && b != "" {
		ra, na := utf8.DecodeRuneInString(a)
		rb, nb := utf8.DecodeRuneInString(b)
		switch {
		case na == 1 && ra == utf8.RuneError || nb == 1 && rb == utf8.RuneError:
			if a[:na] != b[:nb] { // invalid UTF-8 compares by its bytes
				return false
			}
		case ra != rb && unicode.ToLower(ra) != unicode.ToLower(rb):
			return false
		}
		a, b = a[na:], b[nb:]
	}
	return a == b
}

// FoldName is name with each character lowered and invalid UTF-8 kept as
// its bytes: EqualName(a, b) is FoldName(a) == FoldName(b), so it keys a
// map of names.
func FoldName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for name != "" {
		r, n := utf8.DecodeRuneInString(name)
		if n == 1 && r == utf8.RuneError {
			b.WriteByte(name[0])
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
		name = name[n:]
	}
	return b.String()
}

// PathString is path as one string, the same for every way of writing it:
// names joined by ., * for a star, and [*] for an index that is not a
// string literal (but [n] for a number written out). Names keep their case
// (FoldName compares them).
func PathString(path []PathElem) string {
	var b strings.Builder
	for i, e := range path {
		switch {
		case e.Star:
			b.WriteString(".*")
		case e.Name == "":
			if lit, ok := e.Dynamic.(*Literal); ok && lit.Kind == LitNumber {
				b.WriteString("[" + lit.Raw + "]")
			} else {
				b.WriteString("[*]")
			}
		default:
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString(e.Name)
		}
	}
	return b.String()
}
