package workflow

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/expr"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/anchor"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/scalar"
)

// Status is what became of a value.
type Status uint8

const (
	Absent  Status = iota // the key is not there
	Present               // read
	Dynamic               // a ${{ }} stands where a mapping or a sequence belongs; its content is not known
	Invalid               // the value does not fit the schema; a diagnostic says why. What could be read may still be in Value
)

var statusNames = [...]string{"Absent", "Present", "Dynamic", "Invalid"}

func (s Status) String() string { return statusNames[s] }

// Field is a value under a key.
type Field[T any] struct {
	Status Status
	Key    cst.Node // the key as written, an alias included; zero when Absent
	Value  T        // when Present
	Expr   *String  // when Dynamic
}

// Base is where an element is. Node is its content, after following
// aliases; Via are the aliases followed to reach it, outermost first. An
// element with Via is shared with every other place its anchor is used:
// changing Node's bytes changes them all.
type Base struct {
	Node cst.Node
	Via  []cst.Node
}

func (b Base) Shared() bool { return len(b.Via) > 0 }

// Primary is where a diagnostic about the element belongs: the outermost
// alias it is used through, or the element itself.
func (b Base) Primary() cst.Span {
	if len(b.Via) > 0 {
		return b.Via[0].ContentSpan()
	}
	return b.Node.ContentSpan()
}

// Map is a mapping whose keys are names: env, with, jobs, outputs. Entries
// are in the order written, duplicates included; the value of a duplicate
// is not read and is Invalid.
type Map[T any] struct {
	Base
	Entries []Entry[T]
}

type Entry[T any] struct {
	Key   String
	Value Field[T]
}

// Lookup returns the first entry named name, compared the way GitHub
// compares keys (expr.EqualName).
func (m Map[T]) Lookup(name string) (Entry[T], bool) {
	for _, e := range m.Entries {
		if expr.EqualName(e.Key.AsString(), name) {
			return e, true
		}
	}
	return Entry[T]{}, false
}

// List is a sequence, or a single value where the schema allows one in
// place of a sequence (needs: a).
type List[T any] struct {
	Base
	Items []T
}

// Code classifies a Diagnostic.
type Code uint8

const (
	Syntax          Code = iota + 1 // a YAML syntax error
	UnknownKey                      // a key the schema does not have here
	MissingKey                      // a required key is not there
	WrongKind                       // a mapping, a sequence or a scalar where the schema wants another
	InvalidValue                    // a value GitHub does not take here: not one the schema allows, or one a check of GitHub's reader beyond the schema rejects (readerchecks.go)
	DuplicateKey                    // a key already in the mapping
	Ambiguous                       // the keys do not tell which of the schema's mappings it is, such as a job with neither runs-on nor uses
	ExprSyntax                      // a ${{ }} GitHub's expression parser rejects: its syntax, a context or a function the place does not list, or the number of arguments
	ExprNotAllowed                  // a ${{ }} where the schema allows none
	UnresolvedAlias                 // an alias without an anchor, or inside the node it refers to
)

var codeNames = [...]string{
	Syntax:          "Syntax",
	UnknownKey:      "UnknownKey",
	MissingKey:      "MissingKey",
	WrongKind:       "WrongKind",
	InvalidValue:    "InvalidValue",
	DuplicateKey:    "DuplicateKey",
	Ambiguous:       "Ambiguous",
	ExprSyntax:      "ExprSyntax",
	ExprNotAllowed:  "ExprNotAllowed",
	UnresolvedAlias: "UnresolvedAlias",
}

func (c Code) String() string {
	if int(c) < len(codeNames) && codeNames[c] != "" {
		return codeNames[c]
	}
	return "Code(?)"
}

// Diagnostic is a problem of the workflow. Span is where it is used;
// Related is where the shared content it is about is written, if it is
// reached through an alias.
type Diagnostic struct {
	Code    Code
	Span    cst.Span
	Related []cst.Span
	Msg     string
}

// Parse reads the workflow in t, which should be read with
// cst.ModeGitHub. It reads the first document only (GitHub does not read
// the others) and never fails: what cannot be read is reported
// and left Invalid.
func Parse(t *cst.Tree) (*Workflow, []Diagnostic) {
	w := &Workflow{}
	// workflow-root-strict requires both.
	r := readDocument(t, false, dWorkflowRootStrict, []string{"on", "jobs"}, func(r *reader, content cst.Node) { r.readWorkflow(w, content) })
	return w, r.diags
}

// readDocument reads the first document of t with read, then checks what
// read left against root (checkRest). required are the keys reported as
// missing when the document is empty or null; action is whether t is an
// action.yml.
func readDocument(t *cst.Tree, action bool, root defID, required []string, read func(*reader, cst.Node)) *reader {
	r := &reader{anchors: anchor.Build(t), read: map[cst.Node]bool{}, action: action, valued: map[valKey]val{}, mapped: map[mapKey][]entry{}, walked: map[valKey]bool{}}
	doc, content := firstDocument(t)
	for _, e := range t.Errors() {
		if doc == (cst.Node{}) || e.Span.Start < doc.Span().End {
			r.diags = append(r.diags, Diagnostic{Code: Syntax, Span: e.Span, Msg: e.Msg})
		}
	}
	if doc != (cst.Node{}) {
		r.dirs = scalar.DirectivesOf(doc)
	}
	if content == (cst.Node{}) || content.Kind() == cst.NodeScalar && r.litOf(content) == litNull {
		for _, k := range required {
			r.report(MissingKey, cst.Span{}, pos{}, "%q is required", k)
		}
		return r
	}
	r.checkTags(content)
	read(r, content)
	r.checkRest(content, pos{}, root, false)
	r.checkUnread(content)
	return r
}

func firstDocument(t *cst.Tree) (doc, content cst.Node) {
	for e := range t.Root().Children() {
		d, ok := e.Node()
		if !ok || d.Kind() != cst.NodeDocument {
			continue
		}
		for c := range d.Children() {
			if n, ok := c.Node(); ok && n.Kind() != cst.NodeDirective {
				return d, n
			}
		}
		return d, cst.Node{}
	}
	return cst.Node{}, cst.Node{}
}

type reader struct {
	anchors anchor.Index
	dirs    scalar.Directives
	diags   []Diagnostic
	read    map[cst.Node]bool // the scalars newString has read
	action  bool              // an action.yml, which the runner reads
	// valued and mapped are the values and mappings the typed reading
	// checked, which checkRest does not check again; nil in tests that
	// read a part alone.
	valued map[valKey]val
	mapped map[mapKey][]entry
	walked map[valKey]bool // the values checkRest has walked
}

// pos is where the reader is: the aliases followed to get there, and the
// contexts and the functions the definitions on the way list, which allow
// expressions below them; each definition adds to those of the definitions
// above it (TemplateReader.DefinitionInfo).
type pos struct {
	via   []cst.Node
	names expr.Names
}

func (p pos) in(d defID) pos {
	p.names = p.names.Union(schemaDefs[d].names)
	return p
}

// exprAllowed is whether a ${{ }} may be at p.
func (p pos) exprAllowed() bool { return !p.names.IsZero() }

// report adds a diagnostic about sp, which is inside the content reached
// through p.via.
func (r *reader) report(c Code, sp cst.Span, p pos, format string, args ...any) {
	d := Diagnostic{Code: c, Span: sp, Msg: fmt.Sprintf(format, args...)}
	if len(p.via) > 0 {
		d.Span = p.via[0].ContentSpan()
		d.Related = []cst.Span{sp}
	}
	r.diags = append(r.diags, d)
}

// peek is n after following its aliases, without reporting anything; it
// is n itself when an alias does not resolve. The value is then read with
// deref, which reports.
func (r *reader) peek(n cst.Node) cst.Node {
	for i := 0; n.Kind() == cst.NodeAlias && i < 100; i++ {
		def, ok := r.anchors.Resolve(n)
		if !ok {
			return n
		}
		n = def
	}
	return n
}

// deref follows aliases from n. It is false for an alias without an anchor
// or inside the node it refers to, which is reported.
func (r *reader) deref(n cst.Node, p pos) (cst.Node, pos, bool) {
	for n.Kind() == cst.NodeAlias {
		def, ok := r.anchors.Resolve(n)
		if !ok {
			r.report(UnresolvedAlias, n.ContentSpan(), p, "the alias %s has no anchor", n.Bytes())
			return n, p, false
		}
		if s, a := def.Span(), n.Span(); s.Start <= a.Start && a.End <= s.End {
			r.report(UnresolvedAlias, n.ContentSpan(), p, "the alias %s is inside the node it refers to", n.Bytes())
			return n, p, false
		}
		// a pos is copied as it goes down, and the copies share via: the
		// capacity cut makes append copy it, so a sibling's aliases stay its own
		p.via = append(p.via[:len(p.via):len(p.via)], n)
		n = def
	}
	return n, p, true
}

type litKind uint8

const (
	litNull litKind = iota
	litBool
	litNumber
	litString
)

func (r *reader) litOf(n cst.Node) litKind {
	switch scalar.Resolve(n, r.dirs) {
	case scalar.TagNull:
		return litNull
	case scalar.TagBool:
		return litBool
	case scalar.TagInt, scalar.TagFloat:
		return litNumber
	}
	return litString
}

type valKind uint8

const (
	valScalar valKind = iota
	valMapping
	valSequence
)

// val is a value read against a definition.
type val struct {
	n    cst.Node // the content, after aliases
	p    pos      // at the value
	kind valKind
	st   Status
	s    String // a scalar: its value, or the ${{ }} that stands for a collection
}

// value reads n against d the way TemplateReader.readValue does. A mapping
// or a sequence is Present where d has one; a scalar must fit a scalar
// definition of d (validate). A ${{ }} is allowed where a definition on
// the way lists contexts: it is Present where d has a scalar, and Dynamic
// where d has only collections.
func (r *reader) value(n cst.Node, p pos, d defID) val {
	v := r.readValue(n, p, d)
	if r.valued != nil {
		r.valued[keyOf(n, p, d)] = v
	}
	return v
}

func (r *reader) readValue(n cst.Node, p pos, d defID) val {
	n, p, ok := r.deref(n, p)
	v := val{n: n, p: p.in(d), st: Invalid}
	if !ok {
		return v
	}
	if _, isMap := n.Mapping(); isMap {
		v.kind = valMapping
		if len(ofKind(d, nil, kindMapping)) == 0 {
			r.report(WrongKind, n.ContentSpan(), v.p, "a mapping is not expected here")
			return v
		}
		v.st = Present
		return v
	}
	if _, isSeq := n.Sequence(); isSeq {
		v.kind = valSequence
		if len(ofKind(d, nil, kindSequence)) == 0 {
			r.report(WrongKind, n.ContentSpan(), v.p, "a sequence is not expected here")
			return v
		}
		v.st = Present
		return v
	}
	v.s = r.newString(n, v.p)
	v.st = r.checkScalar(v.s, v.p, d)
	return v
}

var scalarKinds = []defKind{kindNull, kindBool, kindNumber, kindString, kindAllowed}

// checkScalar is TemplateReader.validate for the scalar s at p.
func (r *reader) checkScalar(s String, p pos, d defID) Status {
	scalars := ofKind(d, nil, scalarKinds...)
	switch {
	case s.broken():
		return Invalid // reported as ExprSyntax
	case s.HasExpr():
		switch {
		case !p.exprAllowed():
			r.report(ExprNotAllowed, s.Node.ContentSpan(), p, "a ${{ }} is not allowed here")
			return Invalid
		case len(scalars) == 0:
			return Dynamic
		}
		return Present
	case len(scalars) == 0:
		r.report(WrongKind, s.Node.ContentSpan(), p, "a %s is expected here", collectionName(d))
		return Invalid
	}
	text := s.AsString()
	if matchScalar(scalars, s.lit, text) || s.lit != litString && matchScalar(scalars, litString, text) {
		return Present
	}
	r.report(InvalidValue, s.Node.ContentSpan(), p, "unexpected value %q", text)
	return Invalid
}

func matchScalar(defs []defID, lit litKind, text string) bool {
	for _, d := range defs {
		def := &schemaDefs[d]
		switch def.kind {
		case kindNull:
			if lit == litNull {
				return true
			}
		case kindBool:
			if lit == litBool {
				return true
			}
		case kindNumber:
			if lit == litNumber {
				return true
			}
		case kindString:
			if lit == litString && def.acceptsString(text) {
				return true
			}
		case kindAllowed:
			if lit == litString {
				for _, a := range def.allowed {
					if a == text {
						return true
					}
				}
			}
		}
	}
	return false
}

func collectionName(d defID) string {
	switch {
	case len(ofKind(d, nil, kindMapping)) > 0 && len(ofKind(d, nil, kindSequence)) > 0:
		return "mapping or sequence"
	case len(ofKind(d, nil, kindSequence)) > 0:
		return "sequence"
	}
	return "mapping"
}

// entry is one key of a mapping read against the schema.
type entry struct {
	key     String
	keyNode cst.Node // as written: it may be an alias
	name    string
	value   cst.Node // as written: it may be an alias
	def     defID    // the definition of the value
	dup     bool     // the key is already in the mapping (reported)
	prop    bool     // a property of the definition, not a loose key
	exprKey bool     // the key is a ${{ }}
}

// mapping checks the keys of v, a mapping, against d, a mapping definition
// or a one-of of them, the way the template reader does: each key narrows
// the definitions to those that have it (matchPropertyAndFilter); a key
// none has is unknown; a key equal to an earlier one is a duplicate; a
// loose key must fit the loose key definition; a ${{ }}
// key is read as any. When more than one definition still fits, that is
// reported, ambiguous is true, and the first is used.
func (r *reader) mapping(v val, d defID) (ents []entry, chosen defID, ambiguous bool) {
	ents, chosen, ambiguous = r.matchKeys(v, d)
	if r.mapped != nil {
		r.mapped[mapKey{v.n, d, viaOf(v.p)}] = ents
	}
	return ents, chosen, ambiguous
}

func (r *reader) matchKeys(v val, d defID) (ents []entry, chosen defID, ambiguous bool) {
	m, _ := v.n.Mapping()
	cands := ofKind(d, nil, kindMapping)
	count := 0
	for range m.Entries() {
		count++
	}
	ents = make([]entry, 0, count)
	seen := make(map[string]bool, count) // every key by expr.FoldName, for the duplicate and required checks
	exprKeys := false
	for e := range m.Entries() {
		kn, kp, ok := r.deref(e.Key, v.p)
		if !ok {
			continue
		}
		if kn.Kind() != cst.NodeScalar {
			r.report(WrongKind, kn.ContentSpan(), kp, "a key must be a scalar")
			continue
		}
		ent := entry{key: r.newKey(kn, kp), keyNode: e.Key, value: e.Value}
		switch {
		case ent.key.broken():
			continue
		case ent.key.HasExpr():
			if !kp.exprAllowed() {
				r.report(ExprNotAllowed, kn.ContentSpan(), kp, "a ${{ }} is not allowed here")
				continue
			}
			ent.exprKey, ent.def, exprKeys = true, dAny, true
			ents = append(ents, ent)
			continue
		}
		ent.name = ent.key.AsString()
		if fold := expr.FoldName(ent.name); seen[fold] {
			r.report(DuplicateKey, kn.ContentSpan(), kp, "%q is already defined", ent.name)
			ent.dup = true
		} else {
			seen[fold] = true
		}
		if len(cands) == 1 {
			c := &schemaDefs[cands[0]]
			if _, ent.prop = c.prop(ent.name); !ent.prop && !c.loose {
				r.unknown(ent, kn, kp)
				continue
			}
		} else if !r.narrow(&cands, &ent) {
			r.unknown(ent, kn, kp)
			continue
		}
		ents = append(ents, ent)
	}
	chosen = cands[0]
	def := &schemaDefs[chosen]
	// The template reader reads the value of a ${{ }} key against the
	// loose value of a mapping that has loose keys alone, and as any
	// otherwise (TemplateReader.HandleMappingWithAllLooseProperties).
	allLoose := len(cands) == 1 && def.loose && len(def.props) == 0
	for i := range ents {
		switch e := &ents[i]; {
		case e.exprKey:
			if allLoose {
				e.def = def.looseValue
			}
		case e.prop:
			pr, _ := def.prop(e.name)
			e.def = pr.def
		default:
			e.def = def.looseValue
			if !e.dup {
				r.checkScalar(e.key, pos{via: e.key.Via, names: v.p.names}, def.looseKey)
			}
		}
	}
	if len(cands) > 1 {
		r.report(Ambiguous, v.n.ContentSpan(), v.p, "the keys do not tell what this is: add one of %s", strings.Join(distinguishing(cands), ", "))
		return ents, chosen, true
	}
	if exprKeys {
		return ents, chosen, false
	}
	for _, pr := range def.props {
		if pr.required && !seen[expr.FoldName(pr.name)] {
			r.report(MissingKey, v.n.ContentSpan(), v.p, "%q is required", pr.name)
		}
	}
	return ents, chosen, false
}

// narrow keeps the candidates that have ent's key as a property, or else
// those with loose keys. It is false when none has the key.
func (r *reader) narrow(cands *[]defID, ent *entry) bool {
	var with, loose []defID
	for _, c := range *cands {
		if _, ok := schemaDefs[c].prop(ent.name); ok {
			with = append(with, c)
		} else if schemaDefs[c].loose {
			loose = append(loose, c)
		}
	}
	switch {
	case len(with) > 0:
		*cands, ent.prop = with, true
	case len(loose) > 0:
		*cands = loose
	default:
		return false
	}
	return true
}

func (r *reader) unknown(ent entry, kn cst.Node, kp pos) {
	if !ent.dup {
		r.report(UnknownKey, kn.ContentSpan(), kp, "unexpected key %q", ent.name)
	}
}

// distinguishing are the properties that only one of cands has.
func distinguishing(cands []defID) []string {
	count := map[string]int{}
	for _, c := range cands {
		for _, p := range schemaDefs[c].props {
			count[p.name]++
		}
	}
	var names []string
	for n, k := range count {
		if k == 1 {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

// get is the entry of the property name, compared exactly; a later
// duplicate is not returned.
func get(ents []entry, name string) *entry {
	for i := range ents {
		if ents[i].prop && !ents[i].dup && ents[i].name == name {
			return &ents[i]
		}
	}
	return nil
}

// getAny is the entry named name, a property or a loose key.
func getAny(ents []entry, name string) *entry {
	for i := range ents {
		if !ents[i].dup && !ents[i].exprKey && ents[i].name == name {
			return &ents[i]
		}
	}
	return nil
}

// field starts the Field of e from v.
func field[T any](e *entry, v val) Field[T] {
	f := Field[T]{Key: e.keyNode, Status: v.st}
	if v.st == Dynamic {
		s := v.s
		f.Expr = &s
	}
	return f
}

// str reads the value of e, which the schema allows only as a scalar.
func (r *reader) str(e *entry, p pos) Field[String] {
	if e == nil {
		return Field[String]{}
	}
	v := r.value(e.value, p, e.def)
	f := field[String](e, v)
	f.Value = v.s
	return f
}

// strMap reads the value of e as a loose mapping of scalars.
func (r *reader) strMap(e *entry, p pos) Field[Map[String]] {
	return readMap(r, e, p, r.str)
}

// readMap reads the value of e as a loose mapping whose values item reads.
func readMap[T any](r *reader, e *entry, p pos, item func(*entry, pos) Field[T]) Field[Map[T]] {
	if e == nil {
		return Field[Map[T]]{}
	}
	v := r.value(e.value, p, e.def)
	f := field[Map[T]](e, v)
	if v.st != Present || v.kind != valMapping {
		return f
	}
	ents, _, _ := r.mapping(v, e.def)
	f.Value.Base = Base{Node: v.n, Via: v.p.via}
	f.Value.Entries = make([]Entry[T], 0, len(ents))
	for i := range ents {
		ent := &ents[i]
		var val Field[T]
		if ent.dup {
			val = Field[T]{Key: ent.keyNode, Status: Invalid}
		} else {
			val = item(ent, v.p)
		}
		f.Value.Entries = append(f.Value.Entries, Entry[T]{Key: ent.key, Value: val})
	}
	return f
}

// strList reads the value of e as a sequence of scalars, or one scalar
// where the schema allows it in place of the sequence.
func (r *reader) strList(e *entry, p pos) Field[List[String]] {
	if e == nil {
		return Field[List[String]]{}
	}
	v := r.value(e.value, p, e.def)
	f := field[List[String]](e, v)
	if v.st == Present {
		var ok bool
		if f.Value, ok = r.list(v, e.def); !ok {
			f.Status = Invalid
		}
	}
	return f
}

// list is v, read against d, as a list of scalars. It is false when an
// item is not one; the items that are stay in the list.
func (r *reader) list(v val, d defID) (List[String], bool) {
	l := List[String]{Base: Base{Node: v.n, Via: v.p.via}}
	switch v.kind {
	case valScalar:
		l.Items = []String{v.s}
	case valSequence:
		item := schemaDefs[ofKind(d, nil, kindSequence)[0]].item
		seq, _ := v.n.Sequence()
		ok := true
		for n := range seq.Items() {
			iv := r.value(n, v.p, item)
			if iv.st == Present && iv.kind == valScalar {
				l.Items = append(l.Items, iv.s)
			} else {
				ok = false
			}
		}
		return l, ok
	default:
		return l, false
	}
	return l, true
}
