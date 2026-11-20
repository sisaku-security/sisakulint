package shell

// condRole is how bash reads a word inside [[ ]].
type condRole uint8

const (
	condOperator condRole = iota // [[, ]], !, and an operator that is a word (-n, ==, -eq)
	condString                   // an operand read as a string
	condPattern                  // the pattern after ==, = and !=, or the regular expression after =~
	condArith                    // an operand evaluated as arithmetic: of -eq and the like, and the name of -v, whose subscript is
)

var (
	// condUnary are the operators of [[ ]] that take one operand
	condUnary = map[string]bool{"-a": true, "-b": true, "-c": true, "-d": true, "-e": true, "-f": true, "-g": true, "-h": true, "-k": true, "-p": true, "-r": true, "-s": true, "-t": true, "-u": true, "-w": true, "-x": true,
		"-G": true, "-L": true, "-N": true, "-O": true, "-S": true, "-z": true, "-n": true, "-o": true, "-v": true, "-R": true}
	// condBinary are the operators of [[ ]] between two operands that are
	// words; < and > are tokens of their own
	condBinary = map[string]bool{"==": true, "=": true, "!=": true, "=~": true, "-nt": true, "-ot": true, "-ef": true,
		"-eq": true, "-ne": true, "-lt": true, "-le": true, "-gt": true, "-ge": true}
	condArithOps = map[string]bool{"-eq": true, "-ne": true, "-lt": true, "-le": true, "-gt": true, "-ge": true}
)

// condRoles is the role of each word of [[ ... ]] whose tokens between [[
// and ]] are toks, [[ and ]] with them; nil where they are not an
// expression of [[ ]] (bash refuses them, or an operator is not written
// out).
func condRoles(s string, toks []token) []condRole {
	r := &condReader{s: s, roles: []condRole{condOperator}}
	for _, t := range toks {
		if t.kind != tokNewline {
			r.toks = append(r.toks, t)
		}
	}
	r.or()
	if r.failed || r.i < len(r.toks) {
		return nil
	}
	return append(r.roles, condOperator)
}

// condReader reads the tokens of [[ ]] as bash's conditional expression,
// giving each word its role in order. failed is whether they are none.
type condReader struct {
	s      string
	toks   []token
	i      int
	roles  []condRole
	failed bool
	depth  int // of ( ) and !, which stops at maxDepth as the parser does
}

// word is the bytes of the token at i when it is a word written out:
// unquoted, with no expansion; "" otherwise.
func (r *condReader) word(i int) string {
	if i >= len(r.toks) || r.toks[i].kind != tokWord {
		return ""
	}
	w := r.toks[i].w
	if len(w.Parts) != 1 || w.Parts[0].Kind != PartLiteral || w.Parts[0].Quote != QuoteNone {
		return ""
	}
	return r.s[w.Span.Start:w.Span.End]
}

func (r *condReader) isOp(i int, op opKind) bool {
	return i < len(r.toks) && r.toks[i].kind == tokOp && r.toks[i].op == op
}

func (r *condReader) isWord(i int) bool { return i < len(r.toks) && r.toks[i].kind == tokWord }

// take reads the word at i as role.
func (r *condReader) take(role condRole) {
	if !r.isWord(r.i) {
		r.failed = true
		return
	}
	r.roles = append(r.roles, role)
	r.i++
}

func (r *condReader) or() {
	r.and()
	for !r.failed && r.isOp(r.i, opOr) {
		r.i++
		r.and()
	}
}

func (r *condReader) and() {
	r.term()
	for !r.failed && r.isOp(r.i, opAnd) {
		r.i++
		r.term()
	}
}

func (r *condReader) term() {
	if r.depth++; r.depth > maxDepth {
		r.failed = true
	}
	defer func() { r.depth-- }()
	switch {
	case r.failed:
	case r.word(r.i) == "!":
		r.take(condOperator)
		r.term()
	case r.isOp(r.i, opLParen):
		r.i++
		r.or()
		if !r.isOp(r.i, opRParen) {
			r.failed = true
			return
		}
		r.i++
	case condUnary[r.word(r.i)] && r.isWord(r.i+1):
		op := r.word(r.i)
		r.take(condOperator)
		r.take(pick(op == "-v", condArith, condString))
	case r.isWord(r.i) && r.isWord(r.i+1):
		op := r.word(r.i + 1)
		if !condBinary[op] {
			r.failed = true // two operands, or an operator not written out
			return
		}
		role := pick(condArithOps[op], condArith, condString)
		r.take(role)
		r.take(condOperator)
		if role == condString && op != "-nt" && op != "-ot" && op != "-ef" {
			r.pattern()
			return
		}
		r.take(role)
	case r.isWord(r.i) && r.i+1 < len(r.toks) && r.toks[r.i+1].kind == tokRedir:
		if t := r.toks[r.i+1]; t.fd >= 0 || t.redir != RedirIn && t.redir != RedirOut {
			r.failed = true
			return
		}
		r.take(condString)
		r.i++ // < or >
		r.take(condString)
	default:
		r.take(condString)
	}
}

// pattern reads the pattern after ==, = and != (extglob's @( ) and the
// like too) or the regular expression after =~: one word, whose ( ) and |
// are its own, and blanks inside ( ) too.
func (r *condReader) pattern() {
	depth, end := 0, -1
	for ; r.i < len(r.toks); r.i++ {
		t := r.toks[r.i]
		if end >= 0 && depth == 0 && t.span.Start > end {
			break // a blank ends it
		}
		switch {
		case t.kind == tokWord:
			r.roles = append(r.roles, condPattern)
		case t.kind == tokOp && t.op == opLParen:
			depth++
		case t.kind == tokOp && t.op == opRParen:
			if depth == 0 {
				r.failed = end < 0 // the ) of a ( ) around the expression
				return
			}
			depth--
		case t.kind == tokOp && (t.op == opPipe || t.op == opOr):
		default:
			r.failed = true
			return
		}
		end = t.span.End
	}
	r.failed = r.failed || end < 0 || depth > 0
}
