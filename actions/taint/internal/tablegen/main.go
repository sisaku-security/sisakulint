// Command tablegen writes table_gen.go, the table of what an attacker
// controls in the payload of each event, from the OpenAPI description of
// GitHub's webhooks (schema/api.github.com.json.gz, @octokit/openapi-webhooks
// v12.2.0) and the overrides written by hand (schema/overrides.tsv). Run
// it with go generate in actions/taint.
//
// A string is arbitrary, unless it has an enum or a format: date-time and
// date are fixed, uri, uri-template and email structured (they can hold $,
// ( and )); a format not listed stops the generator. A number, a bool and
// null are fixed. An object without properties, and one that refers to a
// schema it is already inside of, is an arbitrary leaf. Where a schema has
// several choices (anyOf, oneOf, a list of types), the path takes the most
// an attacker controls of them; allOf is all of its branches, so a path
// takes the least of those branches that have it.
//
// Each row also has the same capability of its choices that are not
// objects or arrays alone (text: what a ${{ }} that writes it as text
// writes, as an object is written Object), whether a choice is an object
// without properties, and each event the paths whose last * is a key of an
// object of free keys and never an item of an array, which join writes
// nothing of.
//
// In a pattern of the overrides below github.event, {a,b} stands for a
// pattern with each choice in its place, and a choice may hold dots. Every
// line must match some path, and every choice of its braces too, so that
// a key misspelled or gone from the schema stops the generator.
//
// The fourth column of an override, a list of events, means two things.
// Of a name below github, it is the events the name has a value for, and
// in the others the name is Absent. Of a path below github.event, it is
// the events whose tables the override is for, and in the others the path
// keeps what the schema gives; the path must match some path in each of
// those events.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/internal/ident"
	"github.com/sisaku-security/sisakulint/actions/internal/webhook"
)

// Events are the events an attacker triggers with what they control, by
// name. Each takes its payload from the webhook
// webhook.Subcategory names.
var Events = []string{
	"check_run",
	"check_suite",
	"discussion",
	"discussion_comment",
	"fork",
	"gollum",
	"issue_comment",
	"issues",
	"merge_group",
	"pull_request_review",
	"pull_request_review_comment",
	"pull_request_target",
	"push",
	"status",
	"workflow_run",
}

func main() {
	in := flag.String("in", "schema/api.github.com.json.gz", "the OpenAPI description of the webhooks, gzipped")
	over := flag.String("overrides", "schema/overrides.tsv", "the overrides")
	out := flag.String("out", "table_gen.go", "the Go file to write")
	flag.Parse()
	spec, err := webhook.Read(*in)
	if err != nil {
		log.Fatal(err)
	}
	o, err := os.ReadFile(*over)
	if err != nil {
		log.Fatal(err)
	}
	b, err := Generate(spec, o, Events)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		log.Fatal(err)
	}
}

// capabilities are those of the table, the least first. named is
// structured that holds no [ and does not begin with :, so that no
// workflow command of the runner is in it: the name of a ref, a repository
// or a label. login-prefixed is named that begins with the login of an
// account, so that it does not begin with -: the label of a pull request's
// head (owner:branch) and the full name of a repository (owner/name).
// GitHub refused a login that begins with - at sign-up and at a rename,
// seen on 2026-11-01. A path below github.event only: a name below github
// has no place for it. repo-name is named that may begin with - and holds only
// ASCII letters, digits, ., - and _: the name of a repository, which GitHub
// took with a - first. dashed is named that may begin with - and holds
// other characters too, such as = and $: the name of a pull request's head
// branch. commit-email is structured where an attacker writes a workflow
// command: the email of a git commit. page-name is
// structured that may begin with -, holds no blank or line break, and
// where an attacker writes add-path but no workflow command that takes a
// property (set-env, set-output, save-state): the name of a wiki page made
// on the web interface, whose blanks, +, < and > GitHub turns into -; a
// page pushed by git keeps its blanks, so whether the name holds a command
// that takes a property is not known. hyphenless is
// arbitrary that holds no - of ASCII, so that, as written, no workflow
// command that sets outputs, env or the PATH is in it, all of whose names
// have a -: the title of a wiki page. overrides.tsv gives the basis of
// each capability in the reason of its lines.
var capabilities = []string{"fixed", "login-prefixed", "named", "repo-name", "dashed", "structured", "page-name", "commit-email", "hyphenless", "arbitrary"}

// most is the one of a and b an attacker controls more of.
func most(a, b string) string {
	if slices.Index(capabilities, b) > slices.Index(capabilities, a) {
		return b
	}
	return a
}

// least is the less an attacker controls of a and b.
func least(a, b string) string {
	if most(a, b) == a {
		return b
	}
	return a
}

var formats = map[string]string{"date-time": "fixed", "date": "fixed", "uri": "structured", "uri-template": "structured", "email": "structured"}

type row struct {
	path       string // below github.event: segments joined by ., * for an item or any key
	capability string
	mask       uint64 // the actions the path is in
	text       string // the most an attacker controls of its primitive choices, of every webhook: what a text of it holds; fixed when it has none
	object     bool   // some choice of some webhook is an object without properties, or a value of any type
}

type eventTable struct {
	actions []string // by name; "" for a webhook without actions
	rows    []row    // by path
	keys    []string // the paths whose last * is a key of an object of free keys, and no item of an array; by path
}

// shape is what the choices of the schemas at a path are, gathered over
// all of them: a value the runner writes as Object (an object without
// properties) is told from a text, and a key of an object from an item of
// an array, which the table writes both as *.
type shape uint8

const (
	shapePrimitive  shape = 1 << iota // a string, a number, a boolean, null, or a value not known: it has a text (walker.texts)
	shapeObjectLeaf                   // an object without properties, or a value of any type (with shapePrimitive)
	shapeKey                          // the last * is a key of an object of free keys
	shapeItem                         // the last * is an item of an array
)

type schema struct {
	Ref                  string                     `json:"$ref"`
	Type                 json.RawMessage            `json:"type"`
	Format               string                     `json:"format"`
	Enum                 []json.RawMessage          `json:"enum"`
	Properties           map[string]json.RawMessage `json:"properties"`
	Items                json.RawMessage            `json:"items"`
	AdditionalProperties json.RawMessage            `json:"additionalProperties"`
	AnyOf                []json.RawMessage          `json:"anyOf"`
	OneOf                []json.RawMessage          `json:"oneOf"`
	AllOf                []json.RawMessage          `json:"allOf"`
}

type walker struct {
	schemas map[string]json.RawMessage
	out     map[string]string // path to capability
	shapes  map[string]shape  // path to its shape
	texts   map[string]string // path to the most an attacker controls of its primitive choices
	err     error
}

func newWalker(schemas map[string]json.RawMessage) *walker {
	return &walker{schemas: schemas, out: map[string]string{}, shapes: map[string]shape{}, texts: map[string]string{}}
}

// add is the primitive value at path, of capability c.
func (w *walker) add(path []string, c string) {
	w.addShaped(path, c, shapePrimitive)
}

func (w *walker) addShaped(path []string, c string, s shape) {
	p := strings.Join(path, ".")
	if s&shapePrimitive != 0 {
		w.addText(p, c)
	}
	if old, ok := w.out[p]; ok {
		c = most(old, c)
	}
	w.out[p] = c
	w.shapes[p] |= s
}

func (w *walker) addText(p, c string) {
	if old, ok := w.texts[p]; ok {
		c = most(old, c)
	}
	w.texts[p] = c
}

// star is the path of the * below path, marked as a key or an item.
func (w *walker) star(path []string, s shape) []string {
	out := append(slices.Clone(path), "*")
	w.shapes[strings.Join(out, ".")] |= s
	return out
}

func (w *walker) walk(raw json.RawMessage, path []string, inside []string) {
	if w.err != nil {
		return
	}
	var s schema
	if err := json.Unmarshal(raw, &s); err != nil {
		w.err = fmt.Errorf("%s: %v", strings.Join(path, "."), err)
		return
	}
	if s.Ref != "" {
		name := s.Ref[strings.LastIndexByte(s.Ref, '/')+1:]
		if slices.Contains(inside, name) {
			w.addShaped(path, "arbitrary", shapePrimitive|shapeObjectLeaf) // a schema inside itself: not followed; any value
			return
		}
		target, ok := w.schemas[name]
		if !ok {
			w.err = fmt.Errorf("%s: no schema %s", strings.Join(path, "."), s.Ref)
			return
		}
		w.walk(target, path, append(inside, name))
		return
	}
	for _, sub := range slices.Concat(s.AnyOf, s.OneOf) {
		w.walk(sub, path, inside)
	}
	if len(s.AllOf) > 0 {
		w.walkAll(s.AllOf, path, inside)
	}
	var types []string
	if len(s.Type) > 0 {
		var one string
		if json.Unmarshal(s.Type, &one) == nil {
			types = []string{one}
		} else if err := json.Unmarshal(s.Type, &types); err != nil {
			w.err = fmt.Errorf("%s: type: %v", strings.Join(path, "."), err)
			return
		}
	} else if s.Properties != nil {
		types = []string{"object"}
	}
	for _, t := range types {
		switch t {
		case "object":
			for _, k := range sortedKeys(s.Properties) {
				w.walk(s.Properties[k], append(slices.Clone(path), strings.ToLower(k)), inside)
			}
			switch ap := strings.TrimSpace(string(s.AdditionalProperties)); {
			case ap == "true" || ap == "{}":
				w.addShaped(w.star(path, shapeKey), "arbitrary", shapePrimitive|shapeObjectLeaf) // any value
			case ap != "" && ap != "false":
				w.walk(s.AdditionalProperties, w.star(path, shapeKey), inside)
			case len(s.Properties) == 0:
				w.addShaped(path, "arbitrary", shapeObjectLeaf)
			}
		case "array":
			if len(s.Items) == 0 {
				w.addShaped(w.star(path, shapeItem), "arbitrary", shapePrimitive|shapeObjectLeaf) // any value
				continue
			}
			w.walk(s.Items, w.star(path, shapeItem), inside)
		case "string":
			c := "arbitrary"
			switch {
			case s.Format != "":
				f, ok := formats[s.Format]
				if !ok {
					w.err = fmt.Errorf("%s: the format %q is not known", strings.Join(path, "."), s.Format)
					return
				}
				c = f
			case len(s.Enum) > 0:
				c = "fixed"
			}
			w.add(path, c)
		case "integer", "number", "boolean", "null":
			w.add(path, "fixed")
		default:
			w.err = fmt.Errorf("%s: the type %q is not known", strings.Join(path, "."), t)
			return
		}
	}
}

// walkAll walks the branches of an allOf, each on its own, and adds a path
// with the least an attacker controls of the branches that have it: a
// value meets all of them.
func (w *walker) walkAll(subs []json.RawMessage, path []string, inside []string) {
	merged, mergedText := map[string]string{}, map[string]string{}
	for _, sub := range subs {
		b := newWalker(w.schemas)
		b.walk(sub, path, inside)
		if b.err != nil {
			w.err = b.err
			return
		}
		for p, s := range b.shapes {
			w.shapes[p] |= s
		}
		for p, c := range b.texts {
			if old, ok := mergedText[p]; ok {
				c = least(old, c)
			}
			mergedText[p] = c // as the capability: a value meets all the branches
		}
		for p, c := range b.out {
			if old, ok := merged[p]; ok {
				c = least(old, c)
			}
			merged[p] = c
		}
	}
	for _, p := range sortedKeys(merged) {
		w.addShaped(strings.Split(p, "."), merged[p], 0) // the shapes of the branches are above
	}
	for _, p := range sortedKeys(mergedText) {
		w.addText(p, mergedText[p])
	}
}

type override struct {
	segs       []string  // the name below github
	text       string    // the pattern below github.event, as written
	pats       []pattern // below github.event: one for each choice of the braces
	event      bool
	capability string
	events     []string // of a name below github: the events it has a value for; of a path below github.event: the events it is for; nil for all
	hit        bool
	hitOn      map[string]map[alt]bool // of a path below github.event with events: the choices some path matched in each event
	hits       map[alt]bool            // the choices of the braces some path matched
	alts       [][]string              // the choices of each pair of braces, in order
}

// pattern is a path below github.event with the braces taken out, and the
// choice of each pair of braces it was made with.
type pattern struct {
	segs []string
	alts []alt
}

// alt is a choice of a pair of braces: the index of the pair in the
// pattern and of the choice in the pair.
type alt struct{ group, choice int }

// expand is the patterns p stands for, one for each choice of each pair of
// braces ({a,b}), and the choices of each pair; a choice may hold dots.
func expand(p string) ([]pattern, [][]string, error) {
	var groups [][]string
	var texts []string // the text before each pair, and after the last
	rest := p
	for {
		i := strings.IndexAny(rest, "{}")
		if i < 0 {
			texts = append(texts, rest)
			break
		}
		if rest[i] == '}' {
			return nil, nil, errors.New("a brace } without {")
		}
		j := strings.IndexAny(rest[i+1:], "{}")
		switch {
		case j < 0:
			return nil, nil, errors.New("a brace { without }")
		case rest[i+1+j] == '{':
			return nil, nil, errors.New("braces nested in braces")
		}
		texts = append(texts, rest[:i])
		choices := strings.Split(rest[i+1:i+1+j], ",")
		for k, c := range choices {
			switch {
			case c == "":
				return nil, nil, errors.New("an empty choice in braces")
			case slices.Contains(choices[:k], c):
				return nil, nil, fmt.Errorf("the choice %q twice in braces", c)
			}
		}
		groups = append(groups, choices)
		rest = rest[i+2+j:]
	}
	out := []pattern{{}}
	text := []string{texts[0]}
	for g, choices := range groups {
		var next []pattern
		var nextText []string
		for k, prev := range out {
			for c, choice := range choices {
				next = append(next, pattern{alts: append(slices.Clone(prev.alts), alt{g, c})})
				nextText = append(nextText, text[k]+choice+texts[g+1])
			}
		}
		out, text = next, nextText
	}
	for i := range out {
		out[i].segs = strings.Split(text[i], ".")
	}
	return out, groups, nil
}

// topName is what an attacker controls of a name below github, and the
// events it has a value for (nil for all; for the others it is Absent).
type topName struct {
	capability string
	events     []string
}

func parseOverrides(src []byte) ([]*override, error) {
	var out []*override
	for i, line := range strings.Split(string(src), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 && len(f) != 4 || strings.TrimSpace(f[2]) == "" {
			return nil, fmt.Errorf("overrides line %d: a pattern, a capability, a reason and, if any, the events, separated by tabs", i+1)
		}
		if !slices.Contains(capabilities, f[1]) {
			return nil, fmt.Errorf("overrides line %d: %q is not a capability", i+1, f[1])
		}
		o := &override{capability: f[1], hits: map[alt]bool{}, hitOn: map[string]map[alt]bool{}}
		switch p := strings.ToLower(f[0]); {
		case strings.HasPrefix(p, "github.event."):
			o.text = strings.TrimPrefix(p, "github.event.")
			pats, alts, err := expand(o.text)
			if err != nil {
				return nil, fmt.Errorf("overrides line %d: %v", i+1, err)
			}
			o.event, o.pats, o.alts = true, pats, alts
		case strings.ContainsAny(p, "{}"):
			return nil, fmt.Errorf("overrides line %d: a brace is for a path below github.event", i+1)
		case strings.HasPrefix(p, "github.") && !strings.Contains(p[len("github."):], "."):
			if o.capability == "login-prefixed" {
				return nil, fmt.Errorf("overrides line %d: login-prefixed is for a path below github.event", i+1)
			}
			o.segs = []string{p[len("github."):]}
		default:
			return nil, fmt.Errorf("overrides line %d: %q is neither github.event.<path> nor github.<name>", i+1, f[0])
		}
		if len(f) == 4 {
			o.events = strings.Split(f[3], ",")
		}
		out = append(out, o)
	}
	return out, nil
}

// match is whether the pattern pat, where ** is any number of segments,
// is the path segs.
func match(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if match(pat[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	return len(segs) > 0 && pat[0] == segs[0] && match(pat[1:], segs[1:])
}

// build makes the table of each event of events, and the table of the
// names below github.
func build(src, overSrc []byte, events []string) (map[string]eventTable, map[string]topName, error) {
	sp, err := webhook.Parse(src)
	if err != nil {
		return nil, nil, err
	}
	over, err := parseOverrides(overSrc)
	if err != nil {
		return nil, nil, err
	}
	tables := map[string]eventTable{}
	for _, event := range events {
		byAction := map[string]map[string]string{}
		shapes := map[string]shape{}
		texts := map[string]string{}
		for _, name := range sortedKeys(sp.Webhooks) {
			h := sp.Webhooks[name]
			if h.Subcategory() != webhook.Subcategory(event) {
				continue
			}
			body, ok := h.Body()
			if !ok {
				return nil, nil, fmt.Errorf("the webhook %s has no JSON body", name)
			}
			w := newWalker(sp.Components.Schemas)
			w.walk(body, nil, nil)
			if w.err != nil {
				return nil, nil, fmt.Errorf("the webhook %s: %w", name, w.err)
			}
			for p, s := range w.shapes {
				shapes[p] |= s
			}
			for p, c := range w.texts {
				texts[p] = most(texts[p], c)
			}
			for _, a := range webhook.ActionsOf(sp.Components.Schemas, body) {
				if byAction[a] == nil {
					byAction[a] = map[string]string{}
				}
				for p, c := range w.out {
					byAction[a][p] = most(byAction[a][p], c)
				}
			}
		}
		if len(byAction) == 0 {
			return nil, nil, fmt.Errorf("no webhook for the event %s (%s)", event, webhook.Subcategory(event))
		}
		t := eventTable{actions: sortedKeys(byAction)}
		if len(t.actions) > 64 {
			return nil, nil, fmt.Errorf("the event %s has more than 64 actions", event)
		}
		rows := map[string]*row{}
		for i, a := range t.actions {
			for p, c := range byAction[a] {
				r := rows[p]
				if r == nil {
					r = &row{path: p, capability: c}
					rows[p] = r
				}
				r.capability = most(r.capability, c)
				r.mask |= 1 << i
				r.object, r.text = shapes[p]&shapeObjectLeaf != 0, texts[p]
			}
		}
		for _, p := range sortedKeys(rows) {
			r := rows[p]
			segs := strings.Split(p, ".")
			for _, o := range over {
				if o.events != nil && !slices.Contains(o.events, event) {
					continue // an override for other events
				}
				for _, pat := range o.pats {
					if !match(pat.segs, segs) {
						continue
					}
					r.capability, o.hit = o.capability, true
					if o.hitOn[event] == nil {
						o.hitOn[event] = map[alt]bool{}
					}
					if r.text != "" {
						r.text = o.capability // what the override says of the value, of its texts too
					}
					for _, a := range pat.alts {
						o.hits[a], o.hitOn[event][a] = true, true
					}
				}
			}
			if r.text == "" {
				r.text = "fixed" // no text: an object writes Object, and nothing an attacker controls
			}
			t.rows = append(t.rows, *r)
		}
		for _, p := range sortedKeys(shapes) {
			if shapes[p]&shapeKey != 0 && shapes[p]&shapeItem == 0 {
				t.keys = append(t.keys, p)
			}
		}
		tables[event] = t
	}
	top := map[string]topName{}
	for _, o := range over {
		name := "github." + strings.Join(o.segs, ".")
		if o.event {
			name = "github.event." + o.text
		}
		for _, e := range o.events {
			if !slices.Contains(events, e) {
				return nil, nil, fmt.Errorf("the override %s names the event %s, which is not in the table", name, e)
			}
			if !o.event {
				continue
			}
			if o.hitOn[e] == nil {
				return nil, nil, fmt.Errorf("the override %s matches no path in the event %s", name, e)
			}
			for g, choices := range o.alts {
				for c, choice := range choices {
					if !o.hitOn[e][alt{g, c}] {
						return nil, nil, fmt.Errorf("the override %s: the choice %q matches no path in the event %s", name, choice, e)
					}
				}
			}
		}
		if !o.event {
			top[o.segs[0]], o.hit = topName{o.capability, o.events}, true
		}
		if !o.hit {
			return nil, nil, fmt.Errorf("the override github.event.%s matches no path", o.text)
		}
		for g, choices := range o.alts {
			for c, choice := range choices {
				if !o.hits[alt{g, c}] {
					return nil, nil, fmt.Errorf("the override github.event.%s: the choice %q matches no path", o.text, choice)
				}
			}
		}
	}
	return tables, top, nil
}

var goControl = map[string]string{"fixed": "ControlFixed", "login-prefixed": "ControlStructured", "named": "ControlStructured", "repo-name": "ControlStructured", "dashed": "ControlStructured", "structured": "ControlStructured", "page-name": "ControlStructured", "commit-email": "ControlStructured", "hyphenless": "ControlArbitrary", "arbitrary": "ControlArbitrary"}

// goCommand is whether an attacker can write a workflow command in a value
// of each capability.
var goCommand = map[string]string{"fixed": "CommandWritingNone", "login-prefixed": "CommandWritingNone", "named": "CommandWritingNone", "repo-name": "CommandWritingNone", "dashed": "CommandWritingNone", "structured": "CommandWritingUndecided", "page-name": "CommandWritingUndecided", "commit-email": "CommandWritingWritten", "hyphenless": "CommandWritingNone", "arbitrary": "CommandWritingWritten"}

// dashed is whether a value of capability c may begin with -.
func dashed(c string) bool { return c == "dashed" || c == "repo-name" || c == "page-name" }

// Generate makes table_gen.go.
func Generate(src, overrides []byte, events []string) ([]byte, error) {
	tables, top, err := build(src, overrides, events)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString("// Code generated by tablegen from schema/api.github.com.json.gz and schema/overrides.tsv; DO NOT EDIT.\n\npackage taint\n\nimport \"github.com/sisaku-security/sisakulint/actions/workflow\"\n\n")
	b.WriteString("// events are the events an attacker triggers, and what they control in the payload of each.\nvar events = map[workflow.EventName]eventTable{\n")
	for _, name := range sortedKeys(tables) {
		t := tables[name]
		var as []string
		for _, a := range t.actions {
			as = append(as, activityConst(a))
		}
		fmt.Fprintf(&b, "\t%s: {activityTypes: []workflow.ActivityType{%s}, rows: []row{\n", eventConst(name), strings.Join(as, ", "))
		for _, r := range t.rows {
			fmt.Fprintf(&b, "\t\t{%q, %s, %#x, %v, %s, %s, %v, %v, %v, %v, %v},\n", r.path, goControl[r.capability], r.mask, dashed(r.capability), goCommand[r.capability], goControl[r.text], r.object, r.capability == "hyphenless", r.capability == "page-name", r.capability == "repo-name", r.capability == "login-prefixed")
		}
		b.WriteString("\t}, keys: []string{")
		for i, k := range t.keys {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", k)
		}
		b.WriteString("}},\n")
	}
	b.WriteString("}\n\n// top is what an attacker controls of the names below github, other than event,\n// and the events they have a value for (nil: all).\nvar top = map[string]topName{\n")
	for _, k := range sortedKeys(top) {
		ev := "nil"
		if top[k].events != nil {
			var cs []string
			for _, e := range top[k].events {
				cs = append(cs, eventConst(e))
			}
			ev = "[]workflow.EventName{" + strings.Join(cs, ", ") + "}"
		}
		fmt.Fprintf(&b, "\t%q: {%s, %s, %v, %s},\n", k, goControl[top[k].capability], ev, dashed(top[k].capability), goCommand[top[k].capability])
	}
	b.WriteString("}\n")
	out, err := format.Source(b.Bytes())
	if err != nil {
		return nil, errors.Join(errors.New("the generated code does not format"), err)
	}
	return out, nil
}

// eventConst is the constant of workflow.EventName of the event name; the
// build fails on a name GitHub does not take.
func eventConst(name string) string { return "workflow.EventName" + ident.GoName(name) }

// activityConst is the constant of workflow.ActivityType of the action a;
// ActivityTypeUnset for a webhook without actions. The build fails on an
// action the workflow schema and the webhooks do not have.
func activityConst(a string) string {
	if a == "" {
		return "workflow.ActivityTypeUnset"
	}
	return "workflow.ActivityType" + ident.GoName(a)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
