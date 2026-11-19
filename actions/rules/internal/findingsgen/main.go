// Command findingsgen writes finding_gen.go, the Go types of the kinds of
// findings of schema/findings-v0.json. Run it with go generate in
// actions/rules.
//
// The kinds are the members of $defs that $defs/args lists in its oneOf,
// named <rule>.<kind>. Each is a closed object whose property kind is the
// constant of its name, and whose other properties, all required, are its
// arguments: a string, a member of $defs with an x-go-type (here, or the
// Repo, SHA, PackageName, PackageVersion and GHSAID of facts-v0.json), an
// enumeration of $defs (a oneOf of
// consts, whose x-text is the text of each value), or an array of one of
// these (minItems and uniqueItems on an array change no Go type, and are
// taken; a kind has no unevaluatedProperties and no oneOf of objects,
// which would change its members by their values). x-detected is the text
// of what is detected: {name} stands for the argument
// name, and an array is joined by a comma and a space; any other brace is
// itself. x-consequence and x-remedy are texts with no argument. The
// description of each argument (or, without one, that of what it refers
// to, or of the items of an array) is what the argument holds, which
// lint.FindingText keeps with the name of the argument.
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
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/internal/ident"
	"github.com/sisaku-security/sisakulint/actions/internal/jsonschema"
)

func main() {
	in := flag.String("in", "schema/findings-v0.json", "the schema of findings")
	factsIn := flag.String("facts", "../facts/schema/facts-v0.json", "the schema of facts, for its $ref")
	out := flag.String("out", "finding_gen.go", "the Go file to write")
	flag.Parse()
	src, err := os.ReadFile(*in)
	if err != nil {
		log.Fatal(err)
	}
	factsSrc, err := os.ReadFile(*factsIn)
	if err != nil {
		log.Fatal(err)
	}
	b, err := Generate(src, factsSrc)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		log.Fatal(err)
	}
}

const (
	findingsFile = "findings-v0.json"
	factsFile    = "facts-v0.json"
)

// packages are the Go packages the types of the arguments are in.
var packages = map[string]string{
	"analysis": "github.com/sisaku-security/sisakulint/actions/analysis",
	"expr":     "github.com/sisaku-security/sisakulint/actions/expr",
	"facts":    "github.com/sisaku-security/sisakulint/actions/facts",
	"workflow": "github.com/sisaku-security/sisakulint/actions/workflow",
}

// goTypes are the x-go-type a member of $defs may name: of this schema, a
// type of another package; of facts-v0.json, one of actions/facts.
var goTypes = map[string]map[string]string{
	findingsFile: {"workflow.EventName": "workflow", "analysis.SinkKind": "analysis", "analysis.CodeReading": "analysis", "analysis.Approval": "analysis", "analysis.ImageSiteKind": "analysis", "analysis.WriteAll": "analysis", "analysis.AgentAction": "analysis", "analysis.AgentInput": "analysis", "analysis.LogPlace": "analysis", "analysis.FlagPlace": "analysis", "analysis.StatusFunction": "analysis", "analysis.AuthoredCommandName": "analysis", "analysis.ExpressionKey": "analysis", "analysis.EvaluationError": "analysis", "expr.ValueType": "expr"},
	factsFile:    {"Repo": "facts", "SHA": "facts", "PackageName": "facts", "PackageVersion": "facts", "GHSAID": "facts"},
}

var placeholder = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)

// argType is the Go type of an argument, and how its value is text.
type argType struct {
	goType string
	pkg    string                // the package it needs; empty for none
	text   func(v string) string // the Go expression of the text of the value v
	array  bool                  // written by orEmpty, so that nil is []
}

type arg struct {
	name, goName string
	t            argType
	text         string // what it holds: its description nearest to it (argText)
}

type kind struct {
	name, goName, description string
	detected, impact, remedy  string
	args                      []arg // in the order of the properties
	// declared are the arguments as the kind declares them: those detected
	// names, in the order it first names them, then the rest in the order
	// of required
	declared []declaredArg
}

// declaredArg is an argument and whether the text of detected names it.
type declaredArg struct {
	arg
	inDetected bool
}

// enum is an enumeration of $defs, and the text of each value.
type enum struct {
	goName string
	texts  []struct{ goName, text string } // in the order of the oneOf
	// of another package (x-go-type): its Go type is goName, pkg its
	// package, fn the name of the function of its text, and the goName of
	// each text the JSON of the value
	pkg, fn string
}

// Generate makes finding_gen.go from the schema of findings and the schema
// of facts it refers to.
func Generate(src, factsSrc []byte) ([]byte, error) {
	set, err := jsonschema.Load(map[string][]byte{findingsFile: src, factsFile: factsSrc}, jsonschema.Options{SchemaAnnotations: []string{"x-value"}})
	if err != nil {
		return nil, err
	}
	root := set.Root(findingsFile)
	enums := map[*jsonschema.Schema]enum{}
	for _, d := range root.Defs {
		e, ok, err := readEnum(d.Name, d.Schema)
		if err != nil {
			return nil, fmt.Errorf("$defs/%s: %w", d.Name, err)
		}
		if ok {
			enums[d.Schema] = e
		}
	}
	var args *jsonschema.Schema
	for _, d := range root.Defs {
		if d.Name == "args" {
			args = d.Schema
		}
	}
	if args == nil || args.OneOf == nil {
		return nil, fmt.Errorf("$defs/args must list the kinds in its oneOf")
	}
	listed := map[string]bool{}
	var kinds []kind
	for i, o := range args.OneOf {
		name, ok := strings.CutPrefix(o.Ref, "#/$defs/")
		if !ok || o.Type != jsonschema.TypeAny || o.OneOf != nil {
			return nil, fmt.Errorf("$defs/args/oneOf/%d must be only a $ref to a member of $defs", i)
		}
		if t := o.Target(); t == nil || t.Ref != "" {
			// a kind with a $ref would have keywords beside the $ref that
			// readKind, reading the target, does not see
			return nil, fmt.Errorf("$defs/%s must be an object, not a $ref", name)
		}
		k, err := readKind(name, o.Target(), enums)
		if err != nil {
			return nil, fmt.Errorf("$defs/%s: %w", name, err)
		}
		listed[name] = true
		kinds = append(kinds, k)
	}
	for _, d := range root.Defs {
		if strings.Contains(d.Name, ".") && !listed[d.Name] {
			return nil, fmt.Errorf("$defs/%s looks like a kind, but $defs/args does not list it", d.Name)
		}
	}
	slices.SortFunc(kinds, func(a, b kind) int { return strings.Compare(a.name, b.name) })
	return write(kinds, enums)
}

// readEnum reads d when it is an enumeration: a oneOf of consts, with the
// text of each in x-text.
func readEnum(name string, s *jsonschema.Schema) (enum, bool, error) {
	if len(s.OneOf) == 0 || s.OneOf[0].Const == nil {
		return enum{}, false, nil
	}
	var texts map[string]string
	if raw, ok := s.Annotations["x-text"]; !ok || json.Unmarshal(raw, &texts) != nil {
		return enum{}, false, fmt.Errorf("an enumeration needs x-text, the text of each value")
	}
	e := enum{goName: ident.GoName(name)}
	var goType string
	if raw, ok := s.Annotations["x-go-type"]; ok {
		if json.Unmarshal(raw, &goType) != nil || goTypes[findingsFile][goType] == "" {
			return enum{}, false, fmt.Errorf("x-go-type %s is not a known type", raw)
		}
		e = enum{goName: goType, pkg: goTypes[findingsFile][goType], fn: "text" + ident.GoName(name)}
	}
	seen := map[string]bool{}
	for _, c := range s.OneOf {
		var v string
		if json.Unmarshal(c.Const, &v) != nil {
			return enum{}, false, fmt.Errorf("an enumeration must be a oneOf of string consts")
		}
		t, ok := texts[v]
		if !ok || t == "" {
			return enum{}, false, fmt.Errorf("x-text has no text for %s", v)
		}
		seen[v] = true
		goName := e.goName + ident.GoName(v)
		if e.pkg != "" {
			goName = strconv.Quote(v)
		}
		e.texts = append(e.texts, struct{ goName, text string }{goName, t})
	}
	for v := range texts {
		if !seen[v] {
			return enum{}, false, fmt.Errorf("x-text has %s, which is not a value", v)
		}
	}
	return e, true, nil
}

func readKind(name string, s *jsonschema.Schema, enums map[*jsonschema.Schema]enum) (kind, error) {
	rule, part, ok := strings.Cut(name, ".")
	if !ok || !ident.IsKebab(rule) || !ident.IsKebab(part) || strings.Contains(part, ".") {
		return kind{}, fmt.Errorf("the name %s of a kind must be <rule>.<kind> in kebab-case", name)
	}
	k := kind{name: name, goName: ident.GoName(name), description: s.Description}
	if s.Type != jsonschema.TypeObject || !s.AdditionalFalse {
		return kind{}, fmt.Errorf("a kind must be an object with additionalProperties false")
	}
	if s.ShapesObject() {
		return kind{}, fmt.Errorf("a kind has unevaluatedProperties or a oneOf of objects, which change the shape of the object; the Go type of a kind has one field for each property")
	}
	kp, ok := s.Property("kind_id")
	if !ok || string(kp.Const) != fmt.Sprintf("%q", name) {
		return kind{}, fmt.Errorf("the property kind_id must be the const %q", name)
	}
	names := map[string]bool{}
	for _, r := range s.Required {
		if _, ok := s.Property(r); !ok {
			return kind{}, fmt.Errorf("required has %s, which is not a property", r)
		}
	}
	for _, p := range s.Properties {
		if !slices.Contains(s.Required, p.Name) {
			return kind{}, fmt.Errorf("the property %s must be required", p.Name)
		}
		if p.Name == "kind_id" {
			continue
		}
		if !ident.IsSnake(p.Name) {
			// the keys of the JSON are snake_case, and placeholder takes it
			return kind{}, fmt.Errorf("the argument %s must be snake_case", p.Name)
		}
		t, err := typeOf(p.Schema, enums, true)
		if err != nil {
			return kind{}, fmt.Errorf("the argument %s: %w", p.Name, err)
		}
		names[p.Name] = true
		k.args = append(k.args, arg{name: p.Name, goName: ident.GoName(p.Name), t: t, text: argText(p.Schema)})
	}
	if _, ok := s.Annotations["x-message"]; ok {
		return kind{}, fmt.Errorf("x-message is split into x-detected, x-consequence and x-remedy")
	}
	if json.Unmarshal(s.Annotations["x-detected"], &k.detected) != nil || k.detected == "" {
		return kind{}, fmt.Errorf("a kind needs an x-detected")
	}
	for _, m := range placeholder.FindAllStringSubmatch(k.detected, -1) {
		if !names[m[1]] {
			return kind{}, fmt.Errorf("x-detected has {%s}, which is not an argument", m[1])
		}
	}
	for _, f := range []struct {
		name string
		to   *string
	}{{"x-consequence", &k.impact}, {"x-remedy", &k.remedy}} {
		if json.Unmarshal(s.Annotations[f.name], f.to) != nil || *f.to == "" {
			return kind{}, fmt.Errorf("a kind needs an %s", f.name)
		}
		if m := placeholder.FindString(*f.to); m != "" {
			return kind{}, fmt.Errorf("%s has %s: it is the same for every finding of the kind, with no argument", f.name, m)
		}
	}
	for _, a := range k.args {
		if a.text == "" {
			return kind{}, fmt.Errorf("the argument %s has no description, nor has what it refers to", a.name)
		}
	}
	k.declared = declaredArgs(k, s.Required)
	return k, nil
}

// typeOf is the Go type of an argument whose schema is s. An array is of
// one of the others (orArray), not of arrays.
func typeOf(s *jsonschema.Schema, enums map[*jsonschema.Schema]enum, orArray bool) (argType, error) {
	str := func(v string) string { return v + ".String()" }
	switch {
	case s.Ref == "" && s.Type == jsonschema.TypeString:
		return argType{goType: "string", text: func(v string) string { return v }}, nil
	case s.Ref == "" && s.Type == jsonschema.TypeArray && s.Items != nil && orArray:
		e, err := typeOf(s.Items, enums, false)
		if err != nil {
			return argType{}, err
		}
		return argType{goType: "[]" + e.goType, pkg: e.pkg, array: true, text: func(v string) string {
			return fmt.Sprintf("joined(%s, func(x %s) string { return %s })", v, e.goType, e.text("x"))
		}}, nil
	case s.Ref != "":
		r := s.Resolve()
		if e, ok := enums[r]; ok {
			if e.pkg != "" {
				return argType{goType: e.goName, pkg: e.pkg, text: func(v string) string { return e.fn + "(" + v + ")" }}, nil
			}
			return argType{goType: e.goName, text: func(v string) string { return v + ".text()" }}, nil
		}
		var t string
		if raw, ok := r.Annotations["x-go-type"]; ok && json.Unmarshal(raw, &t) == nil {
			if pkg, ok := goTypes[r.File][t]; ok {
				if r.File == factsFile {
					t = "facts." + t
				}
				return argType{goType: t, pkg: pkg, text: str}, nil
			}
		}
	}
	return argType{}, fmt.Errorf("an argument must be a string, a member of $defs with a known x-go-type, an enumeration of $defs, or an array of one of these")
}

func write(kinds []kind, enums map[*jsonschema.Schema]enum) ([]byte, error) {
	var b bytes.Buffer
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	imports := map[string]bool{"github.com/sisaku-security/sisakulint/actions/lint": true}
	for _, e := range enums {
		if e.pkg != "" {
			imports["encoding/json"] = true
		}
	}
	for _, k := range kinds {
		for _, a := range k.args {
			if a.t.pkg != "" {
				imports[packages[a.t.pkg]] = true
			}
		}
	}
	p("// Code generated by findingsgen from schema/findings-v0.json; DO NOT EDIT.\n\n")
	p("package rules\n\nimport (\n")
	for _, i := range slices.Sorted(maps.Keys(imports)) {
		p("\t%q\n", i)
	}
	p(")\n\n")
	p("// allFindingKinds are the kinds of findings, in the order of their names.\n")
	p("var allFindingKinds = []lint.FindingKindID{")
	for _, k := range kinds {
		p("kind%s, ", k.goName)
	}
	p("}\n\n")
	p("// allFindingTexts are what the kinds say, in the order of their names.\n")
	p("var allFindingTexts = []lint.FindingText{")
	for _, k := range kinds {
		p("text%s, ", k.goName)
	}
	p("}\n\n")
	for _, k := range kinds {
		p("var kind%s = lint.MustFindingKindID(%q)\n\n", k.goName, k.name)
		p("// text%s is what the kind %s says, for its rule's Meta.\n", k.goName, k.name)
		p("var text%s = lint.FindingText{ID: kind%s, Detected: %q, Consequence: %q, Remedy: %q, Arguments: %s}\n\n", k.goName, k.goName, k.detected, k.impact, k.remedy, argumentsExpr(k))
		p("// %s is the finding %s: %s\n", k.goName, k.name, k.description)
		p("type %s struct {\n", k.goName)
		for _, a := range k.args {
			p("\t%s %s\n", a.goName, a.t.goType)
		}
		p("}\n\n")
		p("func (%s) KindID() lint.FindingKindID { return kind%s }\n\n", k.goName, k.goName)
		p("func (a %s) Detected() string {\n\treturn %s\n}\n\n", k.goName, detectedExpr(k))
		p("func (a %s) MarshalJSON() ([]byte, error) {\n\treturn marshalArgs(struct {\n\t\tKind string `json:\"kind_id\"`\n", k.goName)
		for _, a := range k.args {
			p("\t\t%s %s `json:%q`\n", a.goName, a.t.goType, a.name)
		}
		p("\t}{%q", k.name)
		for _, a := range k.args {
			if a.t.array {
				p(", orEmpty(a.%s)", a.goName)
			} else {
				p(", a.%s", a.goName)
			}
		}
		p("})\n}\n\n")
	}
	var es []enum
	for _, e := range enums {
		es = append(es, e)
	}
	slices.SortFunc(es, func(a, b enum) int { return strings.Compare(a.goName, b.goName) })
	for _, e := range es {
		if e.pkg != "" {
			p("// %s is v as the detected text writes it (x-text): by its JSON, as\n// %s is another package's.\n", e.fn, e.goName)
			p("func %s(v %s) string {\n\tb, _ := json.Marshal(v)\n\tswitch string(b) {\n", e.fn, e.goName)
			for _, t := range e.texts {
				p("\tcase %q:\n\t\treturn %q\n", t.goName, t.text)
			}
			p("\t}\n\treturn v.String()\n}\n\n")
			continue
		}
		p("// text is v as the detected text writes it (x-text).\n")
		p("func (v %s) text() string {\n\tswitch v {\n", e.goName)
		for _, t := range e.texts {
			p("\tcase %s:\n\t\treturn %q\n", t.goName, t.text)
		}
		p("\t}\n\treturn v.String()\n}\n\n")
	}
	return format.Source(b.Bytes())
}

// detectedExpr is the Go expression of what k detected: the text of x-detected,
// each {name} the text of the argument.
func detectedExpr(k kind) string {
	var parts []string
	rest := k.detected
	for {
		loc := placeholder.FindStringSubmatchIndex(rest)
		if loc == nil {
			break
		}
		if loc[0] > 0 {
			parts = append(parts, fmt.Sprintf("%q", rest[:loc[0]]))
		}
		name := rest[loc[2]:loc[3]]
		for _, a := range k.args {
			if a.name == name {
				parts = append(parts, a.t.text("a."+a.goName))
			}
		}
		rest = rest[loc[1]:]
	}
	if rest != "" {
		parts = append(parts, fmt.Sprintf("%q", rest))
	}
	return strings.Join(parts, " + ")
}

// argText is the description of the argument s nearest to it: its own,
// or else that of each schema on the way of $ref, or else, for an array,
// that of its items found the same way.
func argText(s *jsonschema.Schema) string {
	for ; s != nil; s = s.Target() {
		if s.Description != "" {
			return s.Description
		}
		if s.Target() == nil && s.Type == jsonschema.TypeArray && s.Items != nil {
			return argText(s.Items)
		}
	}
	return ""
}

// declaredArgs are the arguments of k as it declares them (kind.declared);
// required is the order of its required properties.
func declaredArgs(k kind, required []string) []declaredArg {
	byName := map[string]arg{}
	for _, a := range k.args {
		byName[a.name] = a
	}
	var out []declaredArg
	seen := map[string]bool{}
	for _, m := range placeholder.FindAllStringSubmatch(k.detected, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, declaredArg{byName[m[1]], true})
		}
	}
	for _, r := range required {
		if a, ok := byName[r]; ok && !seen[r] {
			seen[r] = true
			out = append(out, declaredArg{a, false})
		}
	}
	return out
}

// argumentsExpr is the Go expression of the arguments of k as it declares
// them.
func argumentsExpr(k kind) string {
	parts := make([]string, len(k.declared))
	for i, a := range k.declared {
		parts[i] = fmt.Sprintf("{Name: lint.MustKindArgumentName(%q), Text: %q, InDetected: %t}", a.name, a.text, a.inDetected)
	}
	return "[]lint.KindArgument{" + strings.Join(parts, ", ") + "}"
}
