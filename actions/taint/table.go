package taint

//go:generate go run ./internal/tablegen

import (
	"slices"
	"strings"
	"sync"

	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// Control is what an attacker controls of a context.
type Control uint8

const (
	// ControlUnknown: the table does not say, as for a field the schema of the
	// payload does not have. It counts as what an attacker may control.
	ControlUnknown Control = iota
	// ControlAbsent: the payload of the event has no such value.
	ControlAbsent
	// ControlFixed: nothing an attacker can shape into code, such as a SHA, a
	// number or a username.
	ControlFixed
	// ControlStructured: an attacker shapes it within a form that still holds
	// what a shell reads, such as a branch name or a URL.
	ControlStructured
	// ControlArbitrary: an attacker writes it, such as a title or a body.
	ControlArbitrary
)

var controlNames = [...]string{"ControlUnknown", "ControlAbsent", "ControlFixed", "ControlStructured", "ControlArbitrary"}

func (c Control) String() string { return controlNames[c] }

type row struct {
	path        string // below github.event, lowered: segments joined by ., * for an item or any key
	capability  Control
	mask        uint64 // the activity types of the event the path is in
	leadingDash bool   // capabilities dashed, repo-name and page-name of the table: structured, and it may begin with - (a head branch's name, a repository's name, a wiki page's name)
	command     CommandWriting
	// text is the most an attacker controls of the choices of the schema
	// that are not objects or arrays, ControlFixed when there are none: what
	// the value holds where a ${{ }} writes it as text, which writes an
	// object as Object
	text   Control
	object bool // some choice of the schema is an object without properties
	// hyphenless is the capability hyphenless of the table: arbitrary that
	// holds no - of ASCII, so that it does not begin with - and holds, as
	// written, no workflow command that sets outputs, env or the PATH (the
	// title of a wiki page)
	hyphenless bool
	// pageName is the capability page-name of the table: structured that
	// may begin with -, holds no blank, and where an attacker writes
	// add-path but no workflow command that takes a property (the name of a
	// wiki page made on the web interface); command is
	// CommandWritingUndecided, for a page pushed by git keeps its blanks
	pageName bool
	// repoName is the capability repo-name of the table: it may begin with
	// - and holds only ASCII letters, digits, ., - and _ (the name of a
	// repository)
	repoName bool
	// loginPrefixed is the capability login-prefixed of the table: named
	// that begins with the login of an account, so that it does not begin
	// with - (the label of a pull request's head, the full name of a
	// repository)
	loginPrefixed bool
}

// CommandWriting is whether an attacker can write a workflow command of
// the runner (::set-env or ::set-output at the head of a line, ##[set-env
// ...] or ##[set-output ...] anywhere) in a value.
type CommandWriting uint8

const (
	CommandWritingNone      CommandWriting = iota // fixed, a name that holds no [ and does not begin with : (a ref's, a repository's, a label's), or a text that holds no - (hyphenless: a wiki page's title)
	CommandWritingUndecided                       // structured, and whether it holds : and [ was not checked
	CommandWritingWritten                         // a text an attacker writes, or the email of a git commit
)

var commandWritingNames = [...]string{"CommandWritingNone", "CommandWritingUndecided", "CommandWritingWritten"}

func (w CommandWriting) String() string { return commandWritingNames[w] }

// topName is what an attacker controls of a name below github, and the
// events it has a value for (nil: all; for the others it is Absent).
type topName struct {
	capability  Control
	events      []workflow.EventName
	leadingDash bool // as row.leadingDash
	command     CommandWriting
}

type eventTable struct {
	activityTypes []workflow.ActivityType // by name; ActivityTypeUnset for an event without activity types
	rows          []row                   // by path
	keys          []string                // the paths whose last * is a key of an object of free keys, not an item of an array
}

// Lookup is what an attacker controls of the context path when event,
// with activityType (all its activity types when ActivityTypeUnset), triggers the run. Names are
// compared the way GitHub compares them (expr.FoldName); a star or an index
// that is not a string literal stands for any item or key.
//
// Below github.event, a path the payload has is its row of the table; an
// object is the most an attacker controls of what is in it (toJSON writes
// it all out); a path below a leaf is the leaf. A path under a key the
// payload does not have is Absent (the payload of push has no issue); one
// under a key it has, but that the schema does not describe, is Unknown.
// An activity type the table does not have is read as any of the event's:
// its payload has the event's objects. An
// attacker's event has none now (TestTableCoversActivityTypes), so this is
// for a pin of the workflow schema that runs ahead of GitHub's webhooks. An
// event that is not an attacker's (TableEvents) is Unknown: the table is
// not for it.
func Lookup(event workflow.EventName, activityType workflow.ActivityType, path []expr.PathElem) Control {
	if !expr.HasPrefix(path, "github") {
		return ControlUnknown
	}
	if len(path) == 1 || path[1].Name == "" {
		return ControlArbitrary // all of github, the event with it
	}
	if !expr.EqualName(path[1].Name, "event") {
		n, ok := top[expr.FoldName(path[1].Name)]
		switch {
		case !ok:
			return ControlUnknown
		case n.events != nil && !slices.Contains(n.events, event):
			return ControlAbsent
		}
		return n.capability
	}
	t, ok := events[event]
	if !ok {
		return ControlUnknown
	}
	root, rest, mask := pathIn(event, activityType, path, t)
	if c, found := root.find(rest, mask); found {
		return c
	}
	if len(rest) > 0 && root.has(rest[0], mask) {
		return ControlUnknown
	}
	return ControlAbsent
}

// pathIn is the trie of the rows of event, the segments of path below
// github.event, and the mask of activityType, for Lookup and LeadingDash.
func pathIn(event workflow.EventName, activityType workflow.ActivityType, path []expr.PathElem, t eventTable) (*node, []string, uint64) {
	root := tries()[event]
	mask := ^uint64(0)
	if activityType != workflow.ActivityTypeUnset {
		if i := slices.Index(t.activityTypes, activityType); i >= 0 {
			mask = 1 << i
			if j := slices.Index(t.activityTypes, workflow.ActivityTypeUnset); j >= 0 {
				mask |= 1 << j // a webhook without activity types: any of them
			}
		}
	}
	rest := make([]string, len(path)-2) // "" for any
	for i, e := range path[2:] {
		if e.Name != "" {
			rest[i] = expr.FoldName(e.Name)
		}
	}
	return root, rest, mask
}

// LeadingDash is whether an attacker can make the value of the context path
// begin with - when event, with activityType, triggers the run: a value they
// write (ControlArbitrary, and ControlUnknown, which counts as one), the
// name of a pull request's head branch, which GitHub takes with a - first,
// or the name of a repository an attacker names, which GitHub took with a
// - first (overrides.tsv gives the basis of each). A
// value of the capability login-prefixed (the label of a pull request's
// head, the full name of a repository) does not: it begins with a login.
// The other structured values (URLs, emails) are not known to, and an
// object does not: its JSON begins with {. A leaf of the capability hyphenless (a
// wiki page's title) does not.
func LeadingDash(event workflow.EventName, activityType workflow.ActivityType, path []expr.PathElem) bool {
	return leadingDash(event, activityType, path, false)
}

// RepoName is whether the value of the context path, when event with
// activityType triggers the run, is the name of a repository an attacker
// names: it may begin with -, and holds only ASCII letters, digits, ., -
// and _ (the capability repo-name of the table).
func RepoName(event workflow.EventName, activityType workflow.ActivityType, path []expr.PathElem) bool {
	return repoName(event, activityType, path, false)
}

// repoName is RepoName of all of the value, or of the value as text.
func repoName(event workflow.EventName, activityType workflow.ActivityType, path []expr.PathElem, text bool) bool {
	if !leadingDash(event, activityType, path, text) || len(path) < 3 || !expr.EqualName(path[1].Name, "event") {
		return false
	}
	root, rest, mask := pathIn(event, activityType, path, events[event])
	return root.leafIs(rest, mask, func(n *node) bool { return n.repo })
}

// leadingDash is LeadingDash of all of the value (JSON), or of the value
// itself as text (LookupText): an object as text is Object.
func leadingDash(event workflow.EventName, activityType workflow.ActivityType, path []expr.PathElem, text bool) bool {
	c := Lookup(event, activityType, path)
	if text {
		c, _ = LookupText(event, activityType, path) // an object alone is ControlFixed; one of several keys may be a text
	}
	if c != ControlArbitrary && c != ControlUnknown && c != ControlStructured || len(path) < 2 || path[1].Name == "" {
		return false // all of github is an object, whose JSON begins with {
	}
	if !expr.EqualName(path[1].Name, "event") {
		return c != ControlStructured || top[expr.FoldName(path[1].Name)].leadingDash
	}
	if len(path) == 2 {
		return false // the event, an object
	}
	root, rest, mask := pathIn(event, activityType, path, events[event])
	if !text && root.object(rest) {
		return false // its JSON begins with {
	}
	if c == ControlStructured {
		return root.dashed(rest, mask)
	}
	return !hyphenlessLeaf(event, activityType, path)
}

// hyphenlessLeaf is whether the value of path, below github.event, is a
// leaf of the capability hyphenless: it holds no -, and does not begin with
// one. Any other path, an object among them, is not.
func hyphenlessLeaf(event workflow.EventName, activityType workflow.ActivityType, path []expr.PathElem) bool {
	if len(path) <= 2 || !expr.EqualName(path[1].Name, "event") {
		return false
	}
	root, rest, mask := pathIn(event, activityType, path, events[event])
	return root.leafIs(rest, mask, func(n *node) bool { return n.free })
}

// PathCommand is whether an attacker can write an add-path command of the
// runner, but no command that takes a property (set-env, set-output), in
// the value of the context path when event, with activityType, triggers the
// run: a leaf of the capability page-name below github.event (the name of a
// wiki page, which holds no blank, so that the name of a command ends at
// ] or ::). Any other path is not.
func PathCommand(event workflow.EventName, activityType workflow.ActivityType, path []expr.PathElem) bool {
	if len(path) <= 2 || !expr.EqualName(path[1].Name, "event") {
		return false
	}
	root, rest, mask := pathIn(event, activityType, path, events[event])
	return root.leafIs(rest, mask, func(n *node) bool { return n.page })
}

// loginPrefixedLeaf is whether the value of path, below github.event, is a
// leaf of the capability login-prefixed: it begins with the login of an
// account, so that it does not begin with -. Any other path is not.
func loginPrefixedLeaf(event workflow.EventName, activityType workflow.ActivityType, path []expr.PathElem) bool {
	if len(path) <= 2 || !expr.EqualName(path[1].Name, "event") {
		return false
	}
	root, rest, mask := pathIn(event, activityType, path, events[event])
	return root.leafIs(rest, mask, func(n *node) bool { return n.login })
}

// node is a node of the trie of the rows of an event: a segment of paths.
type node struct {
	kids  map[string]*node // "*" for an item or any key
	row   bool             // a row ends here
	cap   Control          // of the row
	mask  uint64           // the activity types of the row
	dash  bool             // the row's leadingDash
	free  bool             // the row's hyphenless: it does not begin with -
	page  bool             // the row's pageName: it holds add-path
	repo  bool             // the row's repoName
	login bool             // the row's loginPrefixed: it does not begin with -
	sub   [ControlArbitrary + 1]uint64
	// sub is, by capability, the activity types some row at or below has with it
	cmd    CommandWriting // of the row
	cmdSub [CommandWritingWritten + 1]uint64
	// cmdSub is, by CommandWriting, the activity types some row at or below has with it
	text       Control // the row's text
	bareObject bool    // the row's object
	key        bool    // the * of an object of free keys (eventTable.keys)
}

var (
	trieOnce sync.Once
	trieMap  map[workflow.EventName]*node
)

// tries are the rows of each event, as a trie by segment.
func tries() map[workflow.EventName]*node {
	trieOnce.Do(func() {
		trieMap = map[workflow.EventName]*node{}
		for name, t := range events {
			root := &node{}
			for _, r := range t.rows {
				n := root
				n.sub[r.capability] |= r.mask
				n.cmdSub[r.command] |= r.mask
				for seg := range strings.SplitSeq(r.path, ".") {
					if n.kids == nil {
						n.kids = map[string]*node{}
					}
					k := n.kids[seg]
					if k == nil {
						k = &node{}
						n.kids[seg] = k
					}
					n = k
					n.sub[r.capability] |= r.mask
					n.cmdSub[r.command] |= r.mask
				}
				n.row, n.cap, n.mask, n.dash, n.cmd, n.free, n.page, n.repo, n.login = true, r.capability, r.mask, r.leadingDash, r.command, r.hyphenless, r.pageName, r.repoName, r.loginPrefixed
				n.text, n.bareObject = r.text, r.object
			}
			for _, k := range t.keys {
				n := root
				for seg := range strings.SplitSeq(k, ".") {
					if n = n.kids[seg]; n == nil {
						break
					}
				}
				if n != nil {
					n.key = true
				}
			}
			trieMap[name] = root
		}
	})
	return trieMap
}

// LookupText is what an attacker controls of the value of the context path
// itself, where a ${{ }} writes it as text (as Lookup reads the event and
// the names), and whether the value may be an object or an array
// (collection), which the runner writes as Object or Array, with nothing
// of what is in it. A star
// stands for any item: a reader of a path through a star sees an array,
// which the caller tells. All of github and github.event are objects. Below
// github.event, a path the payload has is the text of its row (what its
// choices that are not objects hold), and an object when it has a row of
// the activity type below it and no such text; any other path is read as
// Lookup reads it, which a row's text does not change (a path below a leaf
// is the leaf's capability).
func LookupText(event workflow.EventName, activityType workflow.ActivityType, path []expr.PathElem) (c Control, collection bool) {
	if !expr.HasPrefix(path, "github") {
		return ControlUnknown, false
	}
	if len(path) == 1 || len(path) == 2 && expr.EqualName(path[1].Name, "event") {
		return ControlFixed, true
	}
	if path[1].Name == "" || !expr.EqualName(path[1].Name, "event") {
		return Lookup(event, activityType, path), false
	}
	if _, ok := events[event]; ok {
		root, rest, mask := pathIn(event, activityType, path, events[event])
		if c, collection, found := root.textIn(rest, mask); found {
			return c, collection
		}
	}
	return Lookup(event, activityType, path), false
}

// textIn is LookupText at rest below n, for the activity types of mask;
// found is false when no row of mask is there, for Lookup to read.
func (n *node) textIn(rest []string, mask uint64) (c Control, collection, found bool) {
	if len(rest) == 0 {
		kids := false
		for _, k := range n.kids {
			kids = kids || k.any(mask)
		}
		switch {
		case n.row && n.mask&mask != 0:
			return n.text, kids || n.bareObject, true
		case kids:
			return ControlFixed, true, true // an object: Object
		}
		return ControlUnknown, false, false
	}
	if n.row && n.mask&mask != 0 && len(n.kids) == 0 {
		if n.bareObject {
			return n.cap, false, true // below an object the schema does not describe, as find
		}
		return ControlFixed, false, true // a part of a text, a number or a bool is null
	}
	take := func(k *node) {
		if k == nil {
			return
		}
		if kc, kcol, ok := k.textIn(rest[1:], mask); ok {
			if !found || stronger(kc, c) {
				c = kc
			}
			collection, found = collection || kcol, true
		}
	}
	if seg := rest[0]; seg == "" {
		for key, k := range n.kids {
			if key != "*" {
				// a key not known of an object: maybe one the schema does
				// not have, as Lookup reads a name it does not have
				return ControlUnknown, true, true
			}
			take(k)
		}
	} else {
		take(n.kids[seg])
		if seg != "*" {
			take(n.kids["*"])
		}
	}
	return c, collection, found
}

// stronger is whether an attacker controls more of c than of d:
// ControlUnknown counts as what an attacker may control, the most.
func stronger(c, d Control) bool {
	rank := func(c Control) Control {
		if c == ControlUnknown {
			return ControlArbitrary + 1
		}
		return c
	}
	return rank(c) > rank(d)
}

// inTable is whether the payload of event has the path below github.event
// for some activity type: a node of the table at each name (a star or an
// index not known goes through any).
func inTable(event workflow.EventName, path []expr.PathElem) bool {
	if _, ok := events[event]; !ok || len(path) < 3 {
		return false
	}
	ns := []*node{tries()[event]}
	for _, e := range path[2:] {
		var next []*node
		for _, n := range ns {
			if e.Name == "" || e.Name == "*" {
				for _, k := range n.kids {
					next = append(next, k)
				}
				continue
			}
			if k := n.kids[expr.FoldName(e.Name)]; k != nil {
				next = append(next, k)
			}
			if k := n.kids["*"]; k != nil {
				next = append(next, k)
			}
		}
		if ns = next; len(ns) == 0 {
			return false
		}
	}
	return true
}

// hasItems is whether the value of path, below github.event, may be an
// array of event, whose items join writes: false when the payload has the
// path and its * is none or a key of an object of free keys
// (eventTable.keys), as join writes nothing of an object; true when that
// is not known (a star or an index not known on the
// way, a path the table does not have).
func hasItems(event workflow.EventName, path []expr.PathElem) bool {
	if len(path) < 3 || !expr.HasPrefix(path, "github", "event") {
		return true
	}
	if _, ok := events[event]; !ok {
		return true
	}
	n := tries()[event]
	for _, e := range path[2:] {
		if e.Name == "" {
			return true
		}
		if n = n.kids[expr.FoldName(e.Name)]; n == nil {
			return true
		}
	}
	k := n.kids["*"]
	return k != nil && !k.key
}

// find is the most an attacker controls of the rows at rest below n, for
// the activity types of mask: the rows under an object, or the leaf above rest.
func (n *node) find(rest []string, mask uint64) (Control, bool) {
	if len(rest) == 0 {
		for c := ControlArbitrary; c >= ControlFixed; c-- {
			if n.sub[c]&mask != 0 {
				return c, true
			}
		}
		return ControlUnknown, false
	}
	best, found := ControlUnknown, false
	take := func(c Control, ok bool) {
		if ok {
			best, found = max(best, c), true
		}
	}
	if n.row && n.mask&mask != 0 && len(n.kids) == 0 {
		take(n.cap, true) // a leaf above rest
	}
	seg := rest[0]
	if seg == "" {
		for _, k := range n.kids {
			take(k.find(rest[1:], mask))
		}
		return best, found
	}
	if k := n.kids[seg]; k != nil {
		take(k.find(rest[1:], mask))
	}
	if k := n.kids["*"]; k != nil && seg != "*" {
		take(k.find(rest[1:], mask))
	}
	return best, found
}

// object is whether the path rest below n names an object of the payload:
// a node with keys below it and no row of a leaf, along the segments
// written out (a star, or an index not known, goes through any key).
func (n *node) object(rest []string) bool {
	if len(rest) == 0 {
		return len(n.kids) > 0
	}
	if n.row && len(n.kids) == 0 {
		return false // below a leaf
	}
	if k := n.kids[rest[0]]; k != nil && rest[0] != "" {
		return k.object(rest[1:])
	}
	if k := n.kids["*"]; k != nil {
		return k.object(rest[1:])
	}
	return false
}

// dashed is whether the row at rest below n, for the activity types of
// mask, may begin with - (row.leadingDash): only a leaf, as an
// object's JSON begins with {.
func (n *node) dashed(rest []string, mask uint64) bool {
	return n.leafIs(rest, mask, func(n *node) bool { return n.dash })
}

// leafIs is whether a leaf row at rest below n, for the activity types of
// mask, is one that is: an object's JSON begins with {, so only a leaf
// counts.
func (n *node) leafIs(rest []string, mask uint64, is func(*node) bool) bool {
	if len(rest) == 0 {
		return n.row && is(n) && n.mask&mask != 0 && len(n.kids) == 0
	}
	if n.row && len(n.kids) == 0 {
		return is(n) && n.mask&mask != 0 // a leaf above rest
	}
	if rest[0] == "" {
		for _, k := range n.kids {
			if k.leafIs(rest[1:], mask, is) {
				return true
			}
		}
		return false
	}
	if k := n.kids[rest[0]]; k != nil && k.leafIs(rest[1:], mask, is) {
		return true
	}
	k := n.kids["*"]
	return k != nil && rest[0] != "*" && k.leafIs(rest[1:], mask, is)
}

// has is whether n has a key seg (or any key) with a row of mask.
func (n *node) has(seg string, mask uint64) bool {
	if seg == "" {
		for _, k := range n.kids {
			if k.any(mask) {
				return true
			}
		}
		return false
	}
	return n.kids[seg] != nil && n.kids[seg].any(mask) || n.kids["*"] != nil && n.kids["*"].any(mask)
}

func (n *node) any(mask uint64) bool {
	for _, m := range n.sub {
		if m&mask != 0 {
			return true
		}
	}
	return false
}

// TableEvents are the events an attacker triggers with what they
// control, by name: those of the table.
func TableEvents() []workflow.EventName {
	var out []workflow.EventName
	for name := range events {
		out = append(out, name)
	}
	slices.SortFunc(out, func(a, b workflow.EventName) int { return strings.Compare(a.String(), b.String()) })
	return out
}

// ActivityTypes are the activity types of the attacker's event e, by name; nil for an
// event without activity types or not an attacker's.
func ActivityTypes(e workflow.EventName) []workflow.ActivityType {
	t := events[e]
	if len(t.activityTypes) == 1 && t.activityTypes[0] == workflow.ActivityTypeUnset {
		return nil
	}
	return slices.Clone(t.activityTypes)
}

// WorkflowCommand is whether an attacker can write a workflow command of
// the runner in the value of the context path when event, with
// activityType, triggers the run: in a value they write
// (ControlArbitrary, and ControlUnknown, which counts as one) but a leaf of
// hyphenless, where it cannot as written; and in a structured value the
// table says so of; an
// object's JSON has what is in it. A command of the script that decodes
// escapes (printf, echo -e) can make a - of \055 in any value, which the
// table does not read.
func WorkflowCommand(event workflow.EventName, activityType workflow.ActivityType, path []expr.PathElem) CommandWriting {
	switch Lookup(event, activityType, path) {
	case ControlArbitrary:
		// hyphenless holds no command that sets outputs or env: what the
		// rows say
		if len(path) > 2 && expr.EqualName(path[1].Name, "event") {
			root, rest, mask := pathIn(event, activityType, path, events[event])
			if w, ok := root.commandIn(rest, mask); ok {
				return w
			}
		}
		return CommandWritingWritten
	case ControlUnknown:
		return CommandWritingWritten
	case ControlStructured:
	default:
		return CommandWritingNone
	}
	if len(path) < 2 || path[1].Name == "" || len(path) == 2 && expr.EqualName(path[1].Name, "event") {
		return CommandWritingWritten // all of github, or the event
	}
	if !expr.EqualName(path[1].Name, "event") {
		return top[expr.FoldName(path[1].Name)].command
	}
	root, rest, mask := pathIn(event, activityType, path, events[event])
	if w, ok := root.commandIn(rest, mask); ok {
		return w
	}
	return CommandWritingUndecided
}

// commandIn is the most an attacker writes of a workflow command in the
// rows at rest below n, for the activity types of mask, as find.
func (n *node) commandIn(rest []string, mask uint64) (CommandWriting, bool) {
	if len(rest) == 0 {
		for w := CommandWritingWritten; ; w-- {
			if n.cmdSub[w]&mask != 0 {
				return w, true
			}
			if w == CommandWritingNone {
				return CommandWritingNone, false
			}
		}
	}
	best, found := CommandWritingNone, false
	take := func(w CommandWriting, ok bool) {
		if ok {
			best, found = max(best, w), true
		}
	}
	if n.row && n.mask&mask != 0 && len(n.kids) == 0 {
		take(n.cmd, true) // a leaf above rest
	}
	if rest[0] == "" {
		for _, k := range n.kids {
			take(k.commandIn(rest[1:], mask))
		}
		return best, found
	}
	if k := n.kids[rest[0]]; k != nil {
		take(k.commandIn(rest[1:], mask))
	}
	if k := n.kids["*"]; k != nil && rest[0] != "*" {
		take(k.commandIn(rest[1:], mask))
	}
	return best, found
}
