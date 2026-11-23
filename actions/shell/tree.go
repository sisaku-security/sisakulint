package shell

import (
	"slices"
	"strings"
)

// Span is the bytes [Start, End) of a script.
type Span struct{ Start, End int }

// Script is a script as bash reads it, as far as it can be followed: its
// commands, in order. Complete is false where the script does not end (a
// quote or a heredoc left open) or where a form not followed (the package
// doc) stops it; the tree then ends at Stop. When Complete, Stop is the
// length of the script.
type Script struct {
	List     []Command
	Complete bool
	Stop     int
	// unterminated: the tokenizer did not follow the script to its end (an
	// open quote, a heredoc not closed); bash refuses the line it cannot read
	// to its end (VariableCodes)
	unterminated bool
}

// Command is a command of a list: *Simple, *Compound, *FuncDef, *Pipeline,
// *AndOr or *Asynchronous.
type Command interface{ Span() Span }

// Simple is a simple command: the assignments before its command word, its
// words (the first is the command word), and its redirects. [[ ... ]] is
// one up to its ]]: its words are [[, the words inside and ]], without the
// operators that are no words (&&, ||, (, ), < and >), and its redirects
// are those after the ]].
type Simple struct {
	span      Span
	ext       int // where the command ends: the next operator or line
	Assigns   []Word
	Words     []Word
	Redirects []Redirect
	cond      []condRole // [[ ... ]]: the role of each word, or nil where it is not read (condRoles)
	isCond    bool
}

// Compound is a compound command and the redirects after it, which take
// what every command in it writes or reads. Body is the commands of its
// lists in order, the condition of an if or a while with the rest; the
// words of for and select and the inside of case and (( )) are not read
// into it.
type Compound struct {
	span      Span
	list      Span // for and select: the words after the name
	Kind      CompoundKind
	Name      *Word         // coproc: the name before the command, which bash expands in the shell that starts the coproc; nil without one
	Arith     []*Arithmetic // (( )): its expression; for (( ; ; )): its three
	Var       *Word         // for and select: the name they assign; nil for for (( ; ; ))
	In        []Word        // for and select: the words after in, which bash expands before the loop
	HasIn     bool          // for and select: in is written (without it, the words are "$@")
	Body      []Command
	Redirects []Redirect
	// lists: for if, where each list of Body starts, in order: the
	// condition, the commands after then, and so for each elif, then the
	// commands after else when there is an else (elseAt); for while and
	// until, the condition and the commands after do
	lists  []int
	elseAt bool
}

// FuncDef defines a function: function f { ...; }, or f() { ...; }.
type FuncDef struct {
	span Span
	Name Word
	Body Command // a *Compound
}

// Pipeline is commands joined by | or |&. Stderr[i] is whether the
// operator between Commands[i] and Commands[i+1] is |&, which joins the
// standard error of Commands[i] to the pipe too, after its own redirects.
type Pipeline struct {
	span     Span
	Commands []Command
	Stderr   []bool
}

// AndOr is pipelines joined by && or ||: Ops[i] is between Commands[i] and
// Commands[i+1].
type AndOr struct {
	span     Span
	Commands []Command
	Ops      []AndOrOp
}

// Asynchronous is an and-or list ended by &, which bash runs
// asynchronously in a subshell (bashref, "Lists of Commands"). Its span
// holds the &.
type Asynchronous struct {
	span    Span
	Command Command
}

func (c *Asynchronous) Span() Span { return c.span }
func (c *Simple) Span() Span       { return c.span }
func (c *Compound) Span() Span     { return c.span }
func (c *FuncDef) Span() Span      { return c.span }
func (c *Pipeline) Span() Span     { return c.span }
func (c *AndOr) Span() Span        { return c.span }

// Redirect is a redirect: its operator, the number before it (-1 when
// none is written) or the {name} before it (Var), and its target, the file or the number it names; a
// heredoc's target is its delimiter as written, and its body is Heredoc.
type Redirect struct {
	Span    Span
	Op      RedirOp
	Fd      int
	Var     VarName // {name} before the operator: bash opens a descriptor of 10 or more and assigns its number to name (or closes the one name holds, with >&- and <&-); zero when none is written
	Target  Word
	Heredoc *HeredocBody
}

// HeredocBody is the body of a heredoc: the lines up to the one that is
// its delimiter. When the delimiter is not quoted, the shell expands the
// body, and Parts are its literals and expansions.
type HeredocBody struct {
	Delim  Delim
	Quoted bool
	Body   Span
	Parts  []Part
	end    int // where the line of the delimiter ends
}

// Delim is the delimiter of a heredoc as the shell compares it, its quotes
// taken off: <<'EOF' and <<"E"OF end at the line EOF.
type Delim struct{ s string }

func (d Delim) String() string { return d.s }

// Word is a word: its parts in order, split where the quotes or the kind
// of expansion change. "t=${T}"x'y'$N is t= and ${T} (inside "..."), x,
// y (inside '...') and $N.
type Word struct {
	id    int // the order of the words outside substitutions; -1 inside one
	Span  Span
	Parts []Part
}

// Part is a part of a word. Its Span has no quotes; "" is an empty
// Literal inside "...". Sub is the script inside $( ), <( ) and >( ), whose
// positions are those of the whole script.
type Part struct {
	Span      Span
	Quote     Quote
	Kind      PartKind
	Name      VarName         // Param and ParamOp
	Sub       *Script         // Subst, ProcIn and ProcOut
	Backquote bool            // Subst written as ` `: its Sub is its script, its backslashes taken off (backquote)
	Param     *ParamExpansion // ParamOp, when bash reads its operator; nil for one not read
	Arith     *Arithmetic     // Arith, when bash reads it to its end; nil for one not read
	toks      []token         // Subst, ProcIn and ProcOut: what parse makes Sub of
	inDouble  bool            // Backquote: right inside "...", not inside a ${ } or $(( )) of it, nor in a heredoc's body (backquote)
}

// VarName is the name of a shell variable or parameter: NAME, 1, @.
type VarName struct{ s string }

func (n VarName) String() string { return n.s }

// NameOf is s as the name of a variable, when a shell reads it as one: a
// letter or _, then letters, digits and _. A parameter such as 1 or @
// comes only from a script.
func NameOf(s string) (VarName, bool) {
	if !isName(s) {
		return VarName{}, false
	}
	return VarName{s}, true
}

// Quote is the quotes a part is inside.
type Quote uint8

const (
	QuoteNone   Quote = iota // outside quotes, or in a heredoc's body
	QuoteSingle              // '...'
	QuoteANSI                // $'...'
	QuoteDouble              // "..."
)

var quoteNames = [...]string{"QuoteNone", "QuoteSingle", "QuoteANSI", "QuoteDouble"}

func (q Quote) String() string { return quoteNames[q] }

// PartKind is what a part is.
type PartKind uint8

const (
	PartLiteral PartKind = iota // bytes as they are
	PartParam                   // $NAME, ${NAME}, $1, $@
	PartParamOp                 // ${NAME...} with an operator: ${NAME:-x}, ${#NAME}
	PartSubst                   // $( )
	PartProcIn                  // <( )
	PartProcOut                 // >( )
	PartOpaque                  // the ( ) of an array's assignment, a heredoc's body not read: not read
	PartArith                   // $(( )): Arith is its expression
)

var partKindNames = [...]string{"PartLiteral", "PartParam", "PartParamOp", "PartSubst", "PartProcIn", "PartProcOut", "PartOpaque", "PartArith"}

func (k PartKind) String() string { return partKindNames[k] }

// CompoundKind is the kind of a compound command.
type CompoundKind uint8

const (
	CompoundUnset    CompoundKind = iota
	CompoundBrace                 // { ...; }
	CompoundSubshell              // ( ... )
	CompoundIf
	CompoundWhile
	CompoundUntil
	CompoundFor
	CompoundSelect
	CompoundCase
	CompoundArith  // (( ... ))
	CompoundCoproc // coproc [NAME] command: Body is the command, which bash runs in a subshell whose standard input and output are pipes to the shell
)

var compoundKindNames = [...]string{"CompoundUnset", "CompoundBrace", "CompoundSubshell", "CompoundIf", "CompoundWhile", "CompoundUntil", "CompoundFor", "CompoundSelect", "CompoundCase", "CompoundArith", "CompoundCoproc"}

func (k CompoundKind) String() string { return compoundKindNames[k] }

// Words are the words of c itself that the tree holds and bash expands,
// not those of the commands in it: the assignments and the words of a
// simple command, the name of a coproc, and the words after in of for and
// select, which bash expands once before the loop. bash runs the commands
// of their substitutions in a child of the shell that runs c. The name of
// a function and the name of for and select are not expanded.
func Words(c Command) []Word {
	switch x := c.(type) {
	case *Simple:
		return append(slices.Clone(x.Assigns), x.Words...)
	case *Compound:
		if x.Name != nil {
			return []Word{*x.Name}
		}
		return x.In
	}
	return nil
}

// PipesToShell is whether the standard input and the standard output of a
// compound of kind k are pipes to the shell that starts it, not those of
// the place where it is written (a coproc).
func (k CompoundKind) PipesToShell() bool { return k == CompoundCoproc }

// Loop is whether a compound of kind k runs its body in rounds: while,
// until, for and select.
func (k CompoundKind) Loop() bool {
	return k == CompoundWhile || k == CompoundUntil || k == CompoundFor || k == CompoundSelect
}

// RedirOp is the operator of a redirect.
type RedirOp uint8

const (
	RedirUnset        RedirOp = iota
	RedirIn                   // <
	RedirOut                  // >
	RedirAppend               // >>
	RedirClobber              // >|
	RedirReadWrite            // <>
	RedirDupIn                // <&
	RedirDupOut               // >&
	RedirAll                  // &>
	RedirAppendAll            // &>>
	RedirHereString           // <<<
	RedirHeredoc              // <<
	RedirHeredocStrip         // <<-
)

var redirOpNames = [...]string{"RedirUnset", "RedirIn", "RedirOut", "RedirAppend", "RedirClobber", "RedirReadWrite", "RedirDupIn", "RedirDupOut", "RedirAll", "RedirAppendAll", "RedirHereString", "RedirHeredoc", "RedirHeredocStrip"}

func (o RedirOp) String() string { return redirOpNames[o] }

// redirOps are the operators of redirects other than heredocs and
// here-strings, by how they are written, longest first.
var redirOps = []struct {
	s  string
	op RedirOp
}{
	{"&>>", RedirAppendAll}, {"&>", RedirAll}, {">>", RedirAppend}, {">|", RedirClobber}, {">&", RedirDupOut},
	{"<>", RedirReadWrite}, {"<&", RedirDupIn}, {">", RedirOut}, {"<", RedirIn},
}

// AndOrOp joins two pipelines.
type AndOrOp uint8

const (
	AndOrUnset AndOrOp = iota
	AndOrAnd           // &&
	AndOrOr            // ||
)

var andOrOpNames = [...]string{"AndOrUnset", "AndOrAnd", "AndOrOr"}

func (o AndOrOp) String() string { return andOrOpNames[o] }

// isName is whether s is the name of a variable.
func isName(s string) bool {
	if s == "" || !isNameStart(s[0]) {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool { return r > 0x7f || !isNameByte(byte(r)) }) < 0
}

func isNameStart(c byte) bool { return c == '_' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
func isNameByte(c byte) bool  { return isNameStart(c) || '0' <= c && c <= '9' }
