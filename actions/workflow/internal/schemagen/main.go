// Command schemagen writes schema_gen.go, the table of the workflow schema
// that the package workflow checks keys and values against. Run it with go
// generate in actions/workflow.
//
// The table is the schema of actions/languageservices
// (schema/workflow-v1.0.json) with its on replaced by the on-new of the
// runner's schema (schema/runner-workflow-v1.0.json): GitHub checks the
// names of events but reads what is in them loosely, as on-new does and
// on-strict does not.
// The schema additions (schema/additions.json) are then added: definitions
// and properties of mappings that GitHub takes and languageservices does
// not have yet, each with its basis. Generation fails when languageservices
// has what an addition adds, so that the addition is removed once it has
// caught up.
// The runner's schema of action.yml (schema/runner-action_yaml.json) is
// added with the prefix action: on its names, since some of them are
// those of the workflow schema with other meanings.
//
// The activity types (ActivityType, and those of each event) are those of
// the definitions <event>-activity-type of the workflow schema and the
// actions of the event's webhooks (../taint/schema/api.github.com.json.gz):
// a run without types runs on an action only the webhook has.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"log"
	"maps"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/internal/enumsrc"
	goname "github.com/sisaku-security/sisakulint/actions/internal/ident"
	"github.com/sisaku-security/sisakulint/actions/internal/webhook"
)

func main() {
	in := flag.String("in", "schema/workflow-v1.0.json", "the schema of languageservices")
	overlay := flag.String("overlay", "schema/runner-workflow-v1.0.json", "the schema of the runner, for on")
	adds := flag.String("additions", "schema/additions.json", "the schema additions")
	action := flag.String("action", "schema/runner-action_yaml.json", "the runner's schema of action.yml")
	hooks := flag.String("webhooks", "../taint/schema/api.github.com.json.gz", "GitHub's webhooks (@octokit/openapi-webhooks), gzipped, for the activity types")
	out := flag.String("out", "schema_gen.go", "the Go file to write")
	flag.Parse()
	src, err := os.ReadFile(*in)
	if err != nil {
		log.Fatal(err)
	}
	over, err := os.ReadFile(*overlay)
	if err != nil {
		log.Fatal(err)
	}
	ad, err := os.ReadFile(*adds)
	if err != nil {
		log.Fatal(err)
	}
	act, err := os.ReadFile(*action)
	if err != nil {
		log.Fatal(err)
	}
	raw, err := webhook.Read(*hooks)
	if err != nil {
		log.Fatal(err)
	}
	spec, err := webhook.Parse(raw)
	if err != nil {
		log.Fatal(err)
	}
	b, err := Generate(src, over, ad, act, spec)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		log.Fatal(err)
	}
}

type property struct {
	Type     string
	Required bool
}

func (p *property) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		return json.Unmarshal(b, &p.Type)
	}
	var v struct {
		Type        string `json:"type"`
		Required    bool   `json:"required"`
		Description string `json:"description"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	err := d.Decode(&v)
	p.Type, p.Required = v.Type, v.Required
	return err
}

type definition struct {
	Description string   `json:"description"`
	Context     []string `json:"context"`
	// CoerceRaw is read and not used, as the runner's OneOfDefinition and
	// StringDefinition do.
	CoerceRaw bool      `json:"coerce-raw"`
	OneOf     *[]string `json:"one-of"`
	Allowed   *[]string `json:"allowed-values"`
	Null      *struct{} `json:"null"`
	Boolean   *struct{} `json:"boolean"`
	Number    *struct{} `json:"number"`
	Sequence  *struct {
		ItemType string `json:"item-type"`
	} `json:"sequence"`
	Mapping *struct {
		Properties map[string]property `json:"properties"`
		LooseKey   string              `json:"loose-key-type"`
		LooseValue string              `json:"loose-value-type"`
	} `json:"mapping"`
	String *struct {
		Constant        string `json:"constant"`
		RequireNonEmpty bool   `json:"require-non-empty"`
		// IsExpression is read and not used, as the runner's
		// StringDefinition does: its TemplateReader never looks at it.
		IsExpression bool `json:"is-expression"`
	} `json:"string"`
}

const (
	root  = "workflow-root-strict"
	onNew = "on-new"
)

func decode(src []byte) (map[string]definition, error) {
	var s struct {
		Version     string                `json:"version"`
		Definitions map[string]definition `json:"definitions"`
	}
	// A field this program does not know (ignore-case, say) would change
	// what a definition means: fail rather than drop it.
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(src, []byte("\xef\xbb\xbf"))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, err
	}
	for n, d := range builtins() {
		if _, ok := s.Definitions[n]; ok {
			return nil, fmt.Errorf("the schema redefines the built-in %q", n)
		}
		s.Definitions[n] = d
	}
	return s.Definitions, nil
}

// refs are the definitions d refers to.
func refs(d definition) []string {
	var r []string
	if d.OneOf != nil {
		r = append(r, *d.OneOf...)
	}
	if d.Sequence != nil {
		r = append(r, d.Sequence.ItemType)
	}
	if m := d.Mapping; m != nil {
		for _, p := range m.Properties {
			r = append(r, p.Type)
		}
		if m.LooseKey != "" {
			r = append(r, m.LooseKey, m.LooseValue)
		}
	}
	return r
}

// reachable are the definitions reached from start; skip is a property of
// start not to follow.
func reachable(defs map[string]definition, start, skip string) map[string]bool {
	seen := map[string]bool{}
	var walk func(string)
	walk = func(n string) {
		d, ok := defs[n]
		if !ok || seen[n] {
			return
		}
		seen[n] = true
		for _, r := range refs(d) {
			walk(r)
		}
	}
	d := defs[start]
	seen[start] = true
	if d.Mapping != nil && skip != "" {
		for name, p := range d.Mapping.Properties {
			if name != skip {
				walk(p.Type)
			}
		}
		if m := d.Mapping; m.LooseKey != "" {
			walk(m.LooseKey)
			walk(m.LooseValue)
		}
		return seen
	}
	for _, r := range refs(d) {
		walk(r)
	}
	return seen
}

func same(a, b definition) bool {
	a.Description, b.Description = "", ""
	a.Context, b.Context = nil, nil
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}

// merge puts the definitions reached from on-new of overlay into base and
// makes it the type of on. A definition of overlay replaces the one of the
// same name in base, which must then not be used outside on.
func merge(base, overlay map[string]definition) error {
	lsStrict := base["on-string-strict"].OneOf
	outside := reachable(base, root, "on")
	for n := range reachable(overlay, onNew, "") {
		od := overlay[n]
		if bd, ok := base[n]; ok {
			if !same(bd, od) && outside[n] {
				return fmt.Errorf("%q differs between the schemas and is used outside on", n)
			}
			// unionContexts gave bd the contexts of both
			od.Context = unionList(bd.Context, od.Context)
		}
		base[n] = od
	}
	// An event name either schema knows is known: the runner's on-string
	// lacks pull_request_comment, which languageservices has and GitHub
	// accepts (its reader test events-mapping-all), and languageservices
	// lacks interactive_component and member, which the runner has.
	for _, set := range []string{"on-string", onNew} {
		d := base[set]
		if d.OneOf == nil || lsStrict == nil {
			return fmt.Errorf("%q or on-string-strict is no one-of", set)
		}
		have := map[string]bool{}
		for _, m := range *d.OneOf {
			have[m] = true
		}
		members := append([]string{}, *d.OneOf...)
		for _, m := range *lsStrict {
			if !have[m] {
				members = append(members, m)
			}
		}
		d.OneOf = &members
		base[set] = d
	}
	r, ok := base[root]
	if !ok || r.Mapping == nil {
		return fmt.Errorf("the schema has no mapping %q", root)
	}
	r.Mapping.Properties["on"] = property{Type: onNew, Required: true}
	return nil
}

// unionContexts gives a definition both schemas have the contexts either
// lists: what one of them allows is not reported (the two differ on
// snapshot and snapshot-if, which an experiment could not settle).
func unionContexts(base, overlay map[string]definition) {
	for n, od := range overlay {
		if bd, ok := base[n]; ok {
			bd.Context = unionList(bd.Context, od.Context)
			base[n] = bd
		}
	}
}

// unionList is a, then the items of b that a lacks.
func unionList(a, b []string) []string {
	have := map[string]bool{}
	for _, c := range a {
		have[c] = true
	}
	for _, c := range b {
		if !have[c] {
			a = append(a, c)
			have[c] = true
		}
	}
	return a
}

// contextFunc is an element of a context list that names a function and
// its least and most arguments (the runner's ExpressionToken.s_function).
var contextFunc = regexp.MustCompile(`^([a-zA-Z0-9_]+)\(([0-9]+),([0-9]+|MAX)\)$`)

// namesOf is the Go expression of the expr.Names of a context list.
func namesOf(list []string) (string, error) {
	upper := func(s string) string { return strings.ToUpper(s[:1]) + s[1:] }
	var b strings.Builder
	b.WriteString("expr.Names{}")
	for _, item := range list {
		if m := contextFunc.FindStringSubmatch(item); m != nil {
			f, ok := expr.ParseScopedFunc(m[1])
			if !ok {
				return "", fmt.Errorf("unknown function %q", m[1])
			}
			lo, _ := strconv.Atoi(m[2])
			hi := "expr.MaxArgs"
			if m[3] != "MAX" {
				n, _ := strconv.Atoi(m[3])
				hi = strconv.Itoa(n)
			}
			fmt.Fprintf(&b, ".WithFunc(expr.Func%s, expr.Arity{Min: %d, Max: %s})", upper(f.String()), lo, hi)
			continue
		}
		c, ok := expr.ParseContextName(item)
		if !ok {
			return "", fmt.Errorf("unknown context %q", item)
		}
		fmt.Fprintf(&b, ".WithContext(expr.Context%s)", upper(c.String()))
	}
	return b.String(), nil
}

// actionPrefix is put on the names of the action schema's definitions.
const actionPrefix = "action:"

// addAction puts the definitions of the action schema act into defs, with
// actionPrefix on their names and on the names they refer to. The
// built-ins are shared.
func addAction(defs map[string]definition, act []byte) error {
	adefs, err := decode(act)
	if err != nil {
		return fmt.Errorf("action: %w", err)
	}
	b := builtins()
	name := func(n string) string {
		if _, ok := b[n]; ok || n == "" {
			return n
		}
		return actionPrefix + n
	}
	for n, d := range adefs {
		if _, ok := b[n]; ok {
			continue
		}
		if d.OneOf != nil {
			o := make([]string, len(*d.OneOf))
			for i, m := range *d.OneOf {
				o[i] = name(m)
			}
			d.OneOf = &o
		}
		if d.Sequence != nil {
			sq := *d.Sequence
			sq.ItemType = name(sq.ItemType)
			d.Sequence = &sq
		}
		if d.Mapping != nil {
			m := *d.Mapping
			m.LooseKey, m.LooseValue = name(m.LooseKey), name(m.LooseValue)
			m.Properties = make(map[string]property, len(d.Mapping.Properties))
			for k, p := range d.Mapping.Properties {
				p.Type = name(p.Type)
				m.Properties[k] = p
			}
			d.Mapping = &m
		}
		defs[name(n)] = d
	}
	return nil
}

// Generate returns schema_gen.go for the schema of languageservices src,
// the runner's schema overlay, the schema additions, the runner's schema
// of action.yml act, and GitHub's webhooks hooks.
func Generate(src, overlay, additions, act []byte, hooks webhook.Spec) ([]byte, error) {
	defs, err := decode(src)
	if err != nil {
		return nil, err
	}
	over, err := decode(overlay)
	if err != nil {
		return nil, fmt.Errorf("overlay: %w", err)
	}
	unionContexts(defs, over)
	if err := merge(defs, over); err != nil {
		return nil, err
	}
	adds, err := decodeAdditions(additions)
	if err != nil {
		return nil, fmt.Errorf("additions: %w", err)
	}
	if err := add(defs, adds); err != nil {
		return nil, fmt.Errorf("additions: %w", err)
	}
	if err := addAction(defs, act); err != nil {
		return nil, err
	}
	s := struct{ Definitions map[string]definition }{defs}
	names := make([]string, 0, len(s.Definitions))
	for n := range s.Definitions {
		names = append(names, n)
	}
	sort.Strings(names)
	id := func(n string) (string, error) {
		if _, ok := s.Definitions[n]; !ok {
			return "", fmt.Errorf("undefined definition %q", n)
		}
		return ident(n), nil
	}

	events, err := eventNames(defs)
	if err != nil {
		return nil, err
	}
	types, byEvent, err := activityTypes(defs, events, hooks)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	b.WriteString("// Code generated by internal/schemagen from schema/workflow-v1.0.json, schema/runner-workflow-v1.0.json, schema/additions.json, schema/runner-action_yaml.json and ../taint/schema/api.github.com.json.gz; DO NOT EDIT.\n\npackage workflow\n\nimport (\n\t\"encoding/json\"\n\t\"fmt\"\n\n\t\"github.com/sisaku-security/sisakulint/actions/expr\"\n)\n\n")
	b.WriteString("const (\n")
	for i, n := range names {
		if i == 0 {
			fmt.Fprintf(&b, "\t%s defID = iota // %s\n", ident(n), n)
		} else {
			fmt.Fprintf(&b, "\t%s // %s\n", ident(n), n)
		}
	}
	b.WriteString(")\n\nvar schemaDefs = [...]schemaDef{\n")
	for _, n := range names {
		d := s.Definitions[n]
		var f []string
		f = append(f, "name: "+strconv.Quote(n))
		if len(d.Context) > 0 {
			names, err := namesOf(d.Context)
			if err != nil {
				return nil, fmt.Errorf("definition %q: %w", n, err)
			}
			f = append(f, "names: "+names)
		}
		switch {
		case d.OneOf != nil:
			ids := []string{}
			for _, o := range *d.OneOf {
				x, err := id(o)
				if err != nil {
					return nil, err
				}
				ids = append(ids, x)
			}
			f = append(f, "kind: kindOneOf", "oneOf: []defID{"+strings.Join(ids, ", ")+"}")
		case d.Allowed != nil:
			f = append(f, "kind: kindAllowed", "allowed: "+quoteList(*d.Allowed))
		case d.Null != nil:
			f = append(f, "kind: kindNull")
		case d.Boolean != nil:
			f = append(f, "kind: kindBool")
		case d.Number != nil:
			f = append(f, "kind: kindNumber")
		case d.Sequence != nil:
			x, err := id(d.Sequence.ItemType)
			if err != nil {
				return nil, err
			}
			f = append(f, "kind: kindSequence", "item: "+x)
		case d.Mapping != nil:
			f = append(f, "kind: kindMapping")
			m := d.Mapping
			if m.LooseKey != "" {
				k, err := id(m.LooseKey)
				if err != nil {
					return nil, err
				}
				v, err := id(m.LooseValue)
				if err != nil {
					return nil, err
				}
				f = append(f, "loose: true", "looseKey: "+k, "looseValue: "+v)
			}
			if len(m.Properties) > 0 {
				pn := make([]string, 0, len(m.Properties))
				for p := range m.Properties {
					pn = append(pn, p)
				}
				sort.Strings(pn)
				var ps []string
				for _, p := range pn {
					x, err := id(m.Properties[p].Type)
					if err != nil {
						return nil, err
					}
					e := "{" + strconv.Quote(p) + ", " + x
					if m.Properties[p].Required {
						e += ", true"
					} else {
						e += ", false"
					}
					ps = append(ps, e+"}")
				}
				f = append(f, "props: []schemaProp{"+strings.Join(ps, ", ")+"}")
			}
		case d.String != nil:
			f = append(f, "kind: kindString")
			if d.String.Constant != "" {
				f = append(f, "constant: "+strconv.Quote(d.String.Constant))
			}
			if d.String.RequireNonEmpty {
				f = append(f, "nonEmpty: true")
			}
		default:
			return nil, fmt.Errorf("definition %q has no kind", n)
		}
		fmt.Fprintf(&b, "\t%s: {%s},\n", ident(n), strings.Join(f, ", "))
	}
	b.WriteString("}\n")
	if err := enumsrc.Write(&b, []enumsrc.Enum{events, types}); err != nil {
		return nil, err
	}
	b.WriteString("\n// activityTypesOf are the activity types of each event that has them, by name.\nvar activityTypesOf = map[EventName][]ActivityType{\n")
	for _, e := range slices.Sorted(maps.Keys(byEvent)) {
		var cs []string
		for _, a := range byEvent[e] {
			cs = append(cs, "ActivityType"+goname.GoName(a))
		}
		fmt.Fprintf(&b, "\tEventName%s: {%s},\n", goname.GoName(e), strings.Join(cs, ", "))
	}
	b.WriteString("}\n")
	return format.Source(b.Bytes())
}

// eventNames is the enumeration EventName: the constants of the members of
// on-string, in its order, with the first paragraph of their descriptions
// as their doc.
func eventNames(defs map[string]definition) (enumsrc.Enum, error) {
	d := defs["on-string"]
	if d.OneOf == nil {
		return enumsrc.Enum{}, fmt.Errorf("on-string is no one-of")
	}
	var values []enumsrc.Value
	for _, m := range *d.OneOf {
		s := defs[m].String
		if s == nil || s.Constant == "" {
			return enumsrc.Enum{}, fmt.Errorf("%q of on-string is not a constant string", m)
		}
		doc, _, _ := strings.Cut(defs[m].Description, "\n\n")
		values = append(values, enumsrc.Value{Name: s.Constant, GoName: goname.GoName(s.Constant), Doc: strings.ReplaceAll(doc, "\n", " ")})
	}
	return enumsrc.New("EventName", "event name", "The names of events GitHub takes: the constants of on-string, in its order.", values, "")
}

// activityTypes is the enumeration ActivityType, the activity types of all
// events, by name, and the activity types of each event: those of its
// definition <event>-activity-type, and the actions of its webhooks.
func activityTypes(defs map[string]definition, events enumsrc.Enum, hooks webhook.Spec) (enumsrc.Enum, map[string][]string, error) {
	known := map[string]bool{}
	for _, v := range events.Values {
		known[v.Name] = true
	}
	byEvent := map[string][]string{}
	all := map[string]bool{}
	for n, d := range defs {
		e, ok := strings.CutSuffix(n, "-activity-type")
		if !ok || strings.HasPrefix(n, actionPrefix) {
			continue
		}
		e = strings.ReplaceAll(e, "-", "_")
		if !known[e] {
			return enumsrc.Enum{}, nil, fmt.Errorf("%q is of no event", n)
		}
		if d.Allowed == nil {
			return enumsrc.Enum{}, nil, fmt.Errorf("%q has no allowed-values", n)
		}
		set := append(slices.Clone(*d.Allowed), hooks.Actions(e)...)
		slices.Sort(set)
		set = slices.Compact(set)
		byEvent[e] = set
		for _, a := range set {
			all[a] = true
		}
	}
	var values []enumsrc.Value
	for _, a := range slices.Sorted(maps.Keys(all)) {
		values = append(values, enumsrc.Value{Name: a, GoName: goname.GoName(a)})
	}
	en, err := enumsrc.New("ActivityType", "activity type", "The activity types of the events, by name: those of the workflow schema and of GitHub's webhooks.", values, "")
	return en, byEvent, err
}

// builtins are the definitions every schema has (languageservices
// templates/schema/template-schema.ts, the TemplateSchema constructor).
func builtins() map[string]definition {
	type seq = struct {
		ItemType string `json:"item-type"`
	}
	type mapping = struct {
		Properties map[string]property `json:"properties"`
		LooseKey   string              `json:"loose-key-type"`
		LooseValue string              `json:"loose-value-type"`
	}
	type str = struct {
		Constant        string `json:"constant"`
		RequireNonEmpty bool   `json:"require-non-empty"`
		IsExpression    bool   `json:"is-expression"`
	}
	any := []string{"null", "boolean", "number", "string", "sequence", "mapping"}
	return map[string]definition{
		"null":     {Null: &struct{}{}},
		"boolean":  {Boolean: &struct{}{}},
		"number":   {Number: &struct{}{}},
		"string":   {String: &str{}},
		"sequence": {Sequence: &seq{ItemType: "any"}},
		"mapping":  {Mapping: &mapping{LooseKey: "string", LooseValue: "any"}},
		"any":      {OneOf: &any},
	}
}

func quoteList(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = strconv.Quote(x)
	}
	return "[]string{" + strings.Join(q, ", ") + "}"
}

// ident is the Go name of a definition: workflow-root-strict is
// dWorkflowRootStrict.
func ident(n string) string {
	var b strings.Builder
	b.WriteByte('d')
	up := true
	for _, c := range n {
		switch {
		case c == '-' || c == '_' || c == ':':
			up = true
		case up:
			b.WriteString(strings.ToUpper(string(c)))
			up = false
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}
