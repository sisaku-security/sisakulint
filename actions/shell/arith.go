package shell

import "strings"

// Arithmetic is an arithmetic expression (bashref, "Shell Arithmetic"):
// the inside of $(( )), of (( )) and of each part of for (( ; ; )). Its
// parts are read as bash expands the expression before it evaluates it,
// as inside "..." (bashref, "Arithmetic Expansion"), with the Sub of their
// substitutions. Names are the names written without $ in its literals,
// which arithmetic reads as the values of those variables, and whether =
// assigns to each.
type Arithmetic struct {
	Span  Span
	Parts []Part
	Names []ArithName
}

// ArithName is a name written without $ in an arithmetic expression.
type ArithName struct {
	Name     VarName
	Span     Span
	Assigned bool // name = …, whose value is then not read
}

// arithmeticAt is the arithmetic expression at sp of script, inside
// paramDepth ${ } and $(( )); nil when its bytes do not make one bash reads
// to its end, or past maxParamDepth: each $(( )) reads its inside again,
// so the time grows with the square of how deep they nest.
func arithmeticAt(script string, sp Span, paramDepth int) *Arithmetic {
	if paramDepth >= maxParamDepth {
		return nil
	}
	l := &tokenizer{s: script, paramDepth: paramDepth}
	w, ok := l.operand(sp, QuoteDouble, false)
	if !ok {
		return nil
	}
	return &Arithmetic{Span: sp, Parts: w.Parts, Names: arithNames(script, w.Parts)}
}

// ArithmeticOf is the word w of script, a subscript or the offset or the
// length of a substring, read as an arithmetic expression; nil when it is
// not one bash reads to its end.
func ArithmeticOf(script string, w Word) *Arithmetic {
	return arithmeticAt(script, w.Span, 0)
}

// arithNames are the names written without $ in the literals of ps: not
// inside '...' or $'...', not after a byte of a name, a $ or a # (16#ff),
// with whether an = (not ==) after the name and its subscript assigns.
func arithNames(script string, ps []Part) []ArithName {
	var out []ArithName
	for _, p := range ps {
		if p.Kind != PartLiteral || p.Quote == QuoteSingle || p.Quote == QuoteANSI {
			continue
		}
		t := script[p.Span.Start:p.Span.End]
		for i := 0; i < len(t); {
			prev := byte(0)
			if i > 0 {
				prev = t[i-1]
			} else if p.Span.Start > 0 {
				prev = script[p.Span.Start-1]
			}
			if !isNameStart(t[i]) || isNameByte(prev) || prev == '$' || prev == '#' {
				i++
				continue
			}
			j := i + 1
			for j < len(t) && isNameByte(t[j]) {
				j++
			}
			after := t[j:]
			if strings.HasPrefix(after, "[") {
				if k := strings.IndexByte(after, ']'); k >= 0 {
					after = after[k+1:] // the element of an array that = assigns
				}
			}
			out = append(out, ArithName{Name: VarName{t[i:j]}, Span: Span{p.Span.Start + i, p.Span.Start + j}, Assigned: assigned(after)})
			i = j
		}
	}
	return out
}

// arithmetics are the expressions inside the (( )) at sp of script (one),
// or inside the (( ; ; )) of for (three: the bytes between the ;).
func arithmetics(script string, sp Span, three bool) []*Arithmetic {
	inner := Span{sp.Start + 2, sp.End - 2}
	if inner.End < inner.Start || !strings.HasPrefix(script[sp.Start:], "((") || !strings.HasSuffix(script[:sp.End], "))") {
		return nil
	}
	var spans []Span
	if three {
		for at := inner.Start; ; {
			semi := topLevel(script, at, inner.End, false, func(c byte) bool { return c == ';' })
			spans = append(spans, Span{at, semi})
			if semi >= inner.End {
				break
			}
			at = semi + 1
		}
	} else {
		spans = []Span{inner}
	}
	var out []*Arithmetic
	for _, s := range spans {
		if a := arithmeticAt(script, s, 0); a != nil {
			out = append(out, a)
		}
	}
	return out
}
