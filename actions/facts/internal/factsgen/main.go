// Command factsgen writes query_gen.go, the Go types of the kinds of facts
// of schema/facts-v0.json. Run it with go generate in actions/facts.
//
// The kinds are the members of $defs that $defs/query lists in its oneOf.
// Each is a closed object whose property kind is the constant of its name
// and whose other properties are strings or members of $defs with an
// x-go-type (Repo, SHA). They are required, but for a member whose Go type
// has an IsZero and whose pattern refuses the empty string: that one may
// be left out, and is written only when it is not zero, so that no fact
// has two spellings, none and empty. A kind has no unevaluatedProperties
// and no oneOf of objects, which would change its members by their values.
// x-value is the schema of its value: a boolean, a string, an integer, a
// member with an x-go-type, or an array of these (minItems and uniqueItems
// on an array change no Go type, and are taken). x-provider says where it
// comes from. x-assume, on a kind not from the API, is the answer with
// which the findings of the false positive forms of the kind hold, and
// when to write the other answer: {"value": ..., "reason": ...}, the value
// fitting x-value.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"log"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/internal/ident"
	"github.com/gh-intel/sisakulint/actions/internal/jsonschema"
)

func main() {
	in := flag.String("in", "schema/facts-v0.json", "the schema of facts")
	out := flag.String("out", "query_gen.go", "the Go file to write")
	flag.Parse()
	src, err := os.ReadFile(*in)
	if err != nil {
		log.Fatal(err)
	}
	b, err := Generate(src)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		log.Fatal(err)
	}
}

// goTypes are the Go types an x-go-type may name, written by hand in
// actions/facts (types.go, actionpattern.go).
var goTypes = map[string]bool{"Repo": true, "SHA": true, "RefName": true, "RefCommit": true, "InputPath": true, "StepPath": true, "EnvironmentName": true, "RunnerLabel": true, "SecretName": true, "RequestDestination": true, "PackageName": true, "PackageVersion": true, "GHSAID": true, "Advisory": true, "UsesPath": true, "RunsUsing": true, "ActionFile": true, "WorkflowFile": true, "PackageEcosystem": true, "RenovateManager": true, "ActionPattern": true, "ConfigurationVariableName": true, "AllowedActionsSetting": true, "AllowedActionsPattern": true}

// zeroIsNone are the x-go-types whose zero value is none (IsZero): an
// argument of one may be left out.
var zeroIsNone = map[string]bool{"Repo": true, "RefName": true, "InputPath": true, "PackageVersion": true, "UsesPath": true}

// mayOmit says why the argument s, of the Go type goType, must be required,
// or nil when it may be left out.
func mayOmit(s *jsonschema.Schema, goType string) error {
	d := s.Resolve()
	ok := zeroIsNone[goType] && d.Pattern != ""
	if ok {
		re, err := regexp.Compile(d.Pattern)
		ok = err == nil && !re.MatchString("")
	}
	if !ok {
		return errors.New("must be required: only an argument of an x-go-type whose zero value is none and whose pattern refuses the empty string may be left out, so that no fact has two spellings, none and empty")
	}
	return nil
}

// permission is the form of x-permission: a scope of a token's permissions
// and its level, such as contents: read.
var permission = regexp.MustCompile(`^([a-z]+(?:-[a-z]+)*): (read|write)$`)

var kindName = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`)

type arg struct {
	name     string // as in JSON
	goName   string
	goType   string
	optional bool // may be left out: written only when not zero
}

type kind struct {
	name, goName, value, from, description string
	scope                                  string // of x-permission; empty when none
	write                                  bool
	args                                   []arg
	optional                               []string // the names of the args that may be left out
	assumed, assumedReason                 string   // of x-assume: the value as JSON, and why; empty when none
}

// Generate makes query_gen.go from the schema of facts.
func Generate(src []byte) ([]byte, error) {
	set, err := jsonschema.Load(map[string][]byte{"facts-v0.json": src}, jsonschema.Options{SchemaAnnotations: []string{"x-value"}})
	if err != nil {
		return nil, err
	}
	root := set.Root("facts-v0.json")
	froms, err := fromValues(root)
	if err != nil {
		return nil, err
	}
	named := map[*jsonschema.Schema]string{} // a member of $defs with an x-go-type -> the Go type
	for _, d := range root.Defs {
		raw, ok := d.Schema.Annotations["x-go-type"]
		if !ok {
			continue
		}
		var t string
		if json.Unmarshal(raw, &t) != nil || !goTypes[t] {
			return nil, fmt.Errorf("$defs/%s: x-go-type %s is not one of the types of actions/facts", d.Name, raw)
		}
		named[d.Schema] = t
	}
	var query *jsonschema.Schema
	for _, d := range root.Defs {
		if d.Name == "query" {
			query = d.Schema
		}
	}
	if query == nil || query.OneOf == nil {
		return nil, fmt.Errorf("$defs/query must list the kinds in its oneOf")
	}
	listed := map[string]bool{}
	var kinds []kind
	for i, o := range query.OneOf {
		name, ok := strings.CutPrefix(o.Ref, "#/$defs/")
		if !ok || o.Type != jsonschema.TypeAny || o.OneOf != nil {
			return nil, fmt.Errorf("$defs/query/oneOf/%d must be only a $ref to a member of $defs", i)
		}
		if t := o.Target(); t == nil || t.Ref != "" {
			// a kind with a $ref would have keywords beside the $ref that
			// readKind, reading the target, does not see
			return nil, fmt.Errorf("$defs/%s must be an object, not a $ref", name)
		}
		k, err := readKind(name, o.Target(), named, froms, set)
		if err != nil {
			return nil, fmt.Errorf("$defs/%s: %w", name, err)
		}
		listed[name] = true
		kinds = append(kinds, k)
	}
	for _, d := range root.Defs {
		if strings.Contains(d.Name, ".") && !listed[d.Name] {
			return nil, fmt.Errorf("$defs/%s looks like a kind, but $defs/query does not list it", d.Name)
		}
	}
	slices.SortFunc(kinds, func(a, b kind) int { return strings.Compare(a.name, b.name) })
	return write(kinds)
}

// fromValues are the values of x-provider ($defs/provider), and the constants of
// Provider that enumgen makes of them.
func fromValues(root *jsonschema.Schema) (map[string]string, error) {
	froms := map[string]string{}
	for _, d := range root.Defs {
		if d.Name != "provider" {
			continue
		}
		for _, c := range d.Schema.OneOf {
			var v string
			if json.Unmarshal(c.Const, &v) != nil {
				return nil, fmt.Errorf("$defs/provider must be a oneOf of consts")
			}
			froms[v] = "Provider" + ident.GoName(v)
		}
	}
	if len(froms) == 0 {
		return nil, fmt.Errorf("$defs/provider must list the values of x-provider")
	}
	return froms, nil
}

func readKind(name string, s *jsonschema.Schema, named map[*jsonschema.Schema]string, froms map[string]string, set *jsonschema.Set) (kind, error) {
	if !kindName.MatchString(name) {
		return kind{}, fmt.Errorf("the name of a kind must be lower-case parts joined by dots, such as git.ref-commit")
	}
	k := kind{name: name, goName: ident.GoName(name), description: s.Description}
	if s.Type != jsonschema.TypeObject || !s.AdditionalFalse {
		return kind{}, fmt.Errorf("a kind must be an object with additionalProperties false")
	}
	if s.ShapesObject() {
		return kind{}, fmt.Errorf("a kind has unevaluatedProperties or a oneOf of objects, which change the shape of the object; the Go type of a kind has one field for each property")
	}
	kp, ok := s.Property("kind")
	if !ok || string(kp.Const) != fmt.Sprintf("%q", name) {
		return kind{}, fmt.Errorf("the property kind must be the const %q", name)
	}
	for _, p := range s.Properties {
		required := slices.Contains(s.Required, p.Name)
		if p.Name == "kind" {
			if !required {
				return kind{}, fmt.Errorf("the property kind must be required")
			}
			continue
		}
		t, err := argType(p.Schema, named)
		if err != nil {
			return kind{}, fmt.Errorf("the argument %s: %w", p.Name, err)
		}
		if !required {
			if err := mayOmit(p.Schema, t); err != nil {
				return kind{}, fmt.Errorf("the property %s %w", p.Name, err)
			}
			if t == "Repo" && slices.ContainsFunc(k.args, func(a arg) bool { return a.optional && a.goType == "Repo" }) {
				return kind{}, fmt.Errorf("the property %s: a kind may leave out one repository at most, which WithRepo names", p.Name)
			}
			k.optional = append(k.optional, p.Name)
		}
		k.args = append(k.args, arg{name: p.Name, goName: ident.GoName(p.Name), goType: t, optional: !required})
	}
	v, ok := s.SchemaAnnotations["x-value"]
	if !ok {
		return kind{}, fmt.Errorf("a kind must have an x-value")
	}
	vt, err := valueType(v, named)
	if err != nil {
		return kind{}, fmt.Errorf("x-value: %w", err)
	}
	k.value = vt
	var from string
	if json.Unmarshal(s.Annotations["x-provider"], &from) != nil || froms[from] == "" {
		return kind{}, fmt.Errorf("x-provider must be one of %s", strings.Join(slices.Sorted(maps.Keys(froms)), ", "))
	}
	k.from = froms[from]
	if raw, ok := s.Annotations["x-permission"]; ok {
		var p string
		m := []string(nil)
		if json.Unmarshal(raw, &p) == nil {
			m = permission.FindStringSubmatch(p)
		}
		if m == nil {
			return kind{}, fmt.Errorf("x-permission must be a scope and a level, such as contents: read")
		}
		k.scope, k.write = m[1], m[2] == "write"
	}
	if raw, ok := s.Annotations["x-assume"]; ok {
		if from == "github" {
			return kind{}, fmt.Errorf("x-assume: a kind from the API has none: the API answers it")
		}
		var a struct {
			Value  json.RawMessage `json:"value"`
			Reason string          `json:"reason"`
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&a) != nil || len(a.Value) == 0 || a.Reason == "" {
			return kind{}, fmt.Errorf(`x-assume must be {"value": ..., "reason": ...} with a reason`)
		}
		if err := set.Validate("facts-v0.json", "#/$defs/"+name+"/x-value", a.Value); err != nil {
			return kind{}, fmt.Errorf("x-assume: the value does not fit x-value: %w", err)
		}
		var c bytes.Buffer
		if err := json.Compact(&c, a.Value); err != nil {
			return kind{}, fmt.Errorf("x-assume: %w", err)
		}
		k.assumed, k.assumedReason = c.String(), a.Reason
	}
	return k, nil
}

// argType is the Go type of an argument: a string, or a member of $defs
// with an x-go-type. An array or an object would make the Go type of the
// kind one that cannot be compared with ==.
func argType(s *jsonschema.Schema, named map[*jsonschema.Schema]string) (string, error) {
	if t, ok := named[s.Resolve()]; ok && s.Ref != "" {
		return t, nil
	}
	if s.Ref == "" && s.Type == jsonschema.TypeString {
		return "string", nil
	}
	return "", fmt.Errorf("an argument must be a string or a member of $defs with an x-go-type")
}

func valueType(s *jsonschema.Schema, named map[*jsonschema.Schema]string) (string, error) {
	if s.Ref != "" {
		if t, ok := named[s.Resolve()]; ok {
			return t, nil
		}
		s = s.Resolve()
	}
	switch s.Type {
	case jsonschema.TypeBoolean:
		return "bool", nil
	case jsonschema.TypeString:
		return "string", nil
	case jsonschema.TypeInteger:
		return "int64", nil
	case jsonschema.TypeArray:
		if s.Items == nil {
			return "", fmt.Errorf("an array must have items")
		}
		t, err := valueType(s.Items, named)
		if err != nil {
			return "", err
		}
		return "[]" + t, nil
	}
	return "", fmt.Errorf("a value must be a boolean, a string, an integer, a member of $defs with an x-go-type, or an array of these")
}

func write(kinds []kind) ([]byte, error) {
	var b bytes.Buffer
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	p("// Code generated by factsgen from schema/facts-v0.json; DO NOT EDIT.\n\n")
	p("package facts\n\n")
	p("import (\n\t\"context\"\n\t\"encoding/json\"\n)\n\n")
	p("// The kinds of facts, in the order of their names. KindUnset is none.\n")
	p("const (\n\tKindUnset Kind = iota\n")
	for _, k := range kinds {
		p("\tKind%s\n", k.goName)
	}
	p(")\n\n")
	p("var kindNames = [...]string{\"\"")
	for _, k := range kinds {
		p(", %q", k.name)
	}
	p("}\n\n")
	for _, k := range kinds {
		p("// %s is the fact %s: %s\n", k.goName, k.name, k.description)
		p("type %s struct {\n", k.goName)
		for _, a := range k.args {
			p("\t%s %s\n", a.goName, a.goType)
		}
		p("}\n\n")
		p("func (%s) Kind() Kind { return Kind%s }\n\n", k.goName, k.goName)
		p("func (%s) query() {}\n\n", k.goName)
		p("// Ask asks r about q.\n")
		p("func (q %s) Ask(ctx context.Context, r Resolver) Answer[%s] { return ask[%s](ctx, r, q) }\n\n", k.goName, k.value, k.value)
		p("func (q %s) encodeJSON() ([]byte, error) {\n", k.goName)
		if len(k.optional) == 0 {
			p("\treturn encodeFields(%q", k.name)
			for _, a := range k.args {
				p(", field{%q, q.%s}", a.name, a.goName)
			}
			p(")\n}\n\n")
		} else {
			p("\tvar fs []field\n")
			for _, a := range k.args {
				if a.optional {
					p("\tif !q.%s.IsZero() {\n\t\tfs = append(fs, field{%q, q.%s})\n\t}\n", a.goName, a.name, a.goName)
				} else {
					p("\tfs = append(fs, field{%q, q.%s})\n", a.name, a.goName)
				}
			}
			p("\treturn encodeFields(%q, fs...)\n}\n\n", k.name)
		}
	}
	p("var kinds = []KindInfo{\n")
	for _, k := range kinds {
		perm := "Permission{}"
		if k.scope != "" {
			perm = fmt.Sprintf("Permission{scope: %q, write: %t}", k.scope, k.write)
		}
		assume := ""
		if k.assumed != "" {
			assume = fmt.Sprintf(", AssumedValue: json.RawMessage(%q), AssumedReason: %q", k.assumed, k.assumedReason)
		}
		p("\t{Kind: Kind%s, Provider: %s, Permission: %s, Description: %q%s},\n", k.goName, k.from, perm, k.description, assume)
	}
	p("}\n\n")
	p("// kindOf is the kind of q, when q is one of the types above: not a\n")
	p("// pointer to one, and not a type that embeds one.\n")
	p("func kindOf(q Query) (Kind, bool) {\n\tswitch q.(type) {\n")
	for _, k := range kinds {
		p("\tcase %s:\n\t\treturn Kind%s, true\n", k.goName, k.goName)
	}
	p("\t}\n\treturn KindUnset, false\n}\n\n")
	p("// WithRepo is q naming the repository r (none, when r is zero), when the\n")
	p("// kind of q has a repo that may be left out; ok is false of another kind.\n")
	p("func WithRepo(q Query, r Repo) (_ Query, ok bool) {\n\tswitch q := q.(type) {\n")
	for _, k := range kinds {
		for _, a := range k.args {
			if a.optional && a.goType == "Repo" {
				p("\tcase %s:\n\t\tq.%s = r\n\t\treturn q, true\n", k.goName, a.goName)
			}
		}
	}
	p("\t}\n\treturn q, false\n}\n\n")
	p("// normalizers read a value into the Go type of its kind and write it\n")
	p("// again, so that a Repo or a SHA in it is in lower case.\n")
	p("var normalizers = map[Kind]func([]byte) ([]byte, error){\n")
	for _, k := range kinds {
		p("\tKind%s: normalize[%s],\n", k.goName, k.value)
	}
	p("}\n\n")
	p("var decoders = map[Kind]func([]byte) (Query, error){\n")
	for _, k := range kinds {
		p("\tKind%s: func(b []byte) (Query, error) {\n\t\tvar v struct {\n", k.goName)
		for _, a := range k.args {
			p("\t\t\t%s %s `json:%q`\n", a.goName, a.goType, a.name)
		}
		p("\t\t}\n\t\tif err := json.Unmarshal(b, &v); err != nil {\n\t\t\treturn nil, err\n\t\t}\n")
		p("\t\treturn %s(v), nil\n\t},\n", k.goName)
	}
	p("}\n")
	return format.Source(b.Bytes())
}
