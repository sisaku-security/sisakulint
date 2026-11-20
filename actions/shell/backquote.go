package shell

// backquote makes the script of the ` ` part p of script (bashref,
// "Command Substitution"): inside it, a backslash keeps its meaning but
// before $, ` and \ (and " when the ` ` is right inside "...", not inside
// a ${ } or $(( )) of it nor in a heredoc's body), where bash takes
// it off. The script is the bytes with those backslashes taken off,
// parsed, with every position written back as the position in script of
// the byte it comes from, so that the bytes of each part are what bash
// reads. A script bash does not read to its end is not Complete; bash
// refuses it only when it runs the command, so the tree goes on.
func backquote(script string, p *Part, depth int) *Script {
	if depth > maxDepth || p.Span.End-p.Span.Start < 2 {
		return nil
	}
	body := Span{p.Span.Start + 1, p.Span.End - 1}
	text, at := unescapeBackquote(script, body, p.inDouble)
	lx := tokenize(text, nil)
	ps := &parser{s: text, depth: depth}
	sc := parseWith(ps, text, lx)
	m := backquoteMap{at: at, start: body.Start, end: body.End}
	m.script(sc)
	return sc
}

// unescapeBackquote is the bytes at sp of s with the backslashes bash
// takes off inside ` ` taken off, and for each byte of what it gives, the
// position in s of the byte.
func unescapeBackquote(s string, sp Span, inDouble bool) (string, []int) {
	b := make([]byte, 0, sp.End-sp.Start)
	at := make([]int, 0, sp.End-sp.Start)
	for i := sp.Start; i < sp.End; i++ {
		if s[i] == '\\' && i+1 < sp.End {
			switch s[i+1] {
			case '$', '`', '\\':
				i++
			case '"':
				if inDouble {
					i++
				}
			}
		}
		b = append(b, s[i])
		at = append(at, i)
	}
	return string(b), at
}

// backquoteMap writes positions of the unescaped body back as positions of
// the script: a start as the position of its byte, an end as the position
// after the byte before it.
type backquoteMap struct {
	at         []int
	start, end int
}

func (m backquoteMap) from(k int) int {
	if k >= len(m.at) {
		return m.end
	}
	return m.at[k]
}

func (m backquoteMap) to(k int) int {
	if k <= 0 {
		return m.start
	}
	return m.at[min(k, len(m.at))-1] + 1
}

// span writes back sp. An empty span, a place between two bytes, is
// written back right after the byte before it, where the end of a span
// that ends there is written back, so that an empty word at the end of a
// command stays inside the command when a backslash taken off comes
// between (`> \$"`).
func (m backquoteMap) span(sp *Span) {
	if sp.Start == sp.End {
		sp.Start = m.to(sp.Start)
		sp.End = sp.Start
		return
	}
	sp.Start, sp.End = m.from(sp.Start), m.to(sp.End)
}

func (m backquoteMap) script(sc *Script) {
	if sc == nil {
		return
	}
	sc.Stop = m.from(sc.Stop)
	m.commands(sc.List)
}

func (m backquoteMap) commands(cs []Command) {
	for _, c := range cs {
		switch x := c.(type) {
		case *Simple:
			m.span(&x.span)
			x.ext = m.from(x.ext)
			m.words(x.Assigns)
			m.words(x.Words)
			m.redirects(x.Redirects)
		case *Compound:
			m.span(&x.span)
			m.span(&x.list)
			if x.Name != nil {
				m.word(x.Name)
			}
			for _, a := range x.Arith {
				m.arith(a)
			}
			m.commands(x.Body)
			m.redirects(x.Redirects)
		case *FuncDef:
			m.span(&x.span)
			m.word(&x.Name)
			m.commands([]Command{x.Body})
		case *Pipeline:
			m.span(&x.span)
			m.commands(x.Commands)
		case *AndOr:
			m.span(&x.span)
			m.commands(x.Commands)
		case *Asynchronous:
			m.span(&x.span)
			m.commands([]Command{x.Command})
		}
	}
}

func (m backquoteMap) redirects(rs []Redirect) {
	for i := range rs {
		r := &rs[i]
		m.span(&r.Span)
		m.word(&r.Target)
		if d := r.Heredoc; d != nil {
			m.span(&d.Body)
			d.end = m.from(d.end)
			d.Parts = m.parts(d.Parts)
		}
	}
}

func (m backquoteMap) words(ws []Word) {
	for i := range ws {
		m.word(&ws[i])
	}
}

func (m backquoteMap) word(w *Word) {
	m.span(&w.Span)
	w.Parts = m.parts(w.Parts)
}

// parts writes back the positions of ps, splitting a literal at each
// backslash taken off inside it, so that the bytes of each part in the
// script are what bash reads (a\$ gives a and $).
func (m backquoteMap) parts(ps []Part) []Part {
	out := make([]Part, 0, len(ps))
	for _, p := range ps {
		if p.Kind == PartLiteral {
			start := p.Span.Start
			for k := start + 1; k < p.Span.End && k < len(m.at); k++ {
				if m.at[k] != m.at[k-1]+1 { // a byte taken off between
					q := p
					q.Span = Span{start, k}
					m.span(&q.Span)
					out = append(out, q)
					start = k
				}
			}
			p.Span.Start = start
		}
		m.span(&p.Span)
		m.script(p.Sub)
		if x := p.Param; x != nil {
			for _, w := range []*Word{x.Subscript, x.Offset, x.Length} {
				if w != nil {
					m.word(w)
				}
			}
			m.words(x.Words)
		}
		if a := p.Arith; a != nil {
			m.arith(a)
		}
		out = append(out, p)
	}
	return out
}

func (m backquoteMap) arith(a *Arithmetic) {
	m.span(&a.Span)
	a.Parts = m.parts(a.Parts)
	for i := range a.Names {
		m.span(&a.Names[i].Span)
	}
}
