package cst

import "testing"

// builder assembles a tree by hand with the parser primitives, checking
// that each token's text matches the input at the current position.
type builder struct {
	t *testing.T
	p *parser
}

func build(t *testing.T, src string, f func(b *builder)) *Tree {
	t.Helper()
	b := &builder{t, newParser([]byte(src))}
	f(b)
	if b.p.pos != len(src) {
		t.Fatalf("builder consumed %d of %d bytes", b.p.pos, len(src))
	}
	tr := b.p.finish()
	tr.lineStarts = buildLineStarts(tr.src)
	if err := validate(tr); err != nil {
		t.Fatal(err)
	}
	return tr
}

func (b *builder) n(k NodeKind, f func()) {
	i := b.p.open(k)
	if f != nil {
		f()
	}
	b.p.close(i)
}

func (b *builder) tok(k TokenKind, s string) {
	b.t.Helper()
	if got := string(b.p.src[b.p.pos:min(b.p.pos+len(s), len(b.p.src))]); got != s {
		b.t.Fatalf("token %v: input has %q at %d, want %q", k, got, b.p.pos, s)
	}
	b.p.emit(k, b.p.pos+len(s))
}
