// Command enumgen writes the values of the enumerations of the schemas of
// a package: go generate runs it in actions/lint and actions/facts.
//
//	enumgen -pkg lint -out enum_gen.go [-ref FILE]... [-only NAME]... [-skip NAME]... FILE...
//
// An enumeration is a member of $defs of a FILE whose oneOf has a const in
// it. Each item of its oneOf must then be a const and a description on one
// line, and nothing else, but for the x-name of an abbreviation: a const is
// kebab-case, snake_case (as the REST API of GitHub writes its values, such
// as local_only), or an abbreviation in capitals (as CVSS writes its values)
// with x-name, what the abbreviation stands for, in kebab-case. The Go
// type is the GoName of the member, and is declared by hand in the
// package, with its doc; its constants are the type's name and the GoName
// of each const, or of its x-name, in the order of the oneOf, with the
// description as their doc, and what each is (description) and every value
// (<type>Values), with the description of the member as <type>Description
// when it has one. The zero value is the type's name and
// Unset, which is not a value, unless the member names one of its consts in
// x-go-zero. The schemas of -ref are read only for the $ref of the others.
//
// A member of $defs with x-go-axes is the axes of the enumerations of its
// properties: an object with a description on one line, closed, of one
// property at least, that requires exactly its properties, each an array
// whose items $ref an enumeration of the same file, keyed by that
// enumeration's name in snake_case, with a description on one line of
// what the axis is; minItems and uniqueItems on an array change no Go
// type, and are taken, but the object has no unevaluatedProperties and no
// oneOf of objects, which change its members. Its Go type, the GoName of the member, is a struct of
// a field of each property, in their order; the axis type, the GoName of
// x-go-axes (kebab-case, not the type of an enumeration), is an
// enumeration of the names of those enumerations, declared by hand like
// the others, with the description of each property and Key, its key. Axes gives each axis of a value of the
// struct with the values it has, as the interface <axis>Value, and
// <member>All every value of each axis, so that no Go names an axis by
// hand. The enumerations of the axes have Description.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/gh-intel/sisakulint/actions/internal/enumsrc"
	"github.com/gh-intel/sisakulint/actions/internal/ident"
	"github.com/gh-intel/sisakulint/actions/internal/jsonschema"
)

type paths []string

func (p *paths) String() string     { return strings.Join(*p, " ") }
func (p *paths) Set(s string) error { *p = append(*p, s); return nil }

func main() {
	pkg := flag.String("pkg", "", "the package of the file")
	out := flag.String("out", "enum_gen.go", "the Go file to write")
	var refs paths
	flag.Var(&refs, "ref", "a schema the others refer to, which gives no types (may be repeated)")
	var only paths
	flag.Var(&only, "only", "the name of the one member of $defs to make (may be repeated); all when not given")
	var skip paths
	flag.Var(&skip, "skip", "the name of a member of $defs not to make, whose Go type another package declares (may be repeated)")
	flag.Parse()
	files, order, err := load(flag.Args(), refs)
	if err != nil {
		log.Fatal(err)
	}
	b, err := generate(*pkg, files, order, only, skip)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		log.Fatal(err)
	}
}

// load reads the schemas gen and refs, by the names their $ref use (the
// base names), and gives the names of gen in order.
func load(gen, refs []string) (map[string][]byte, []string, error) {
	files := map[string][]byte{}
	var order []string
	for i, p := range append(append([]string(nil), gen...), refs...) {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, nil, err
		}
		files[filepath.Base(p)] = b
		if i < len(gen) {
			order = append(order, filepath.Base(p))
		}
	}
	return files, order, nil
}

// Generate makes the file of package pkg from the enumerations of the
// schemas order, in that order; files are every schema, by the name their
// $ref use. With only, it makes those of the members of $defs so named,
// and no other.
func Generate(pkg string, files map[string][]byte, order []string, only ...string) ([]byte, error) {
	return generate(pkg, files, order, only, nil)
}

// GenerateExcept is Generate of every enumeration but those named skip:
// their Go types are another package's.
func GenerateExcept(pkg string, files map[string][]byte, order []string, skip []string) ([]byte, error) {
	return generate(pkg, files, order, nil, skip)
}

func generate(pkg string, files map[string][]byte, order []string, only, skip []string) ([]byte, error) {
	set, err := jsonschema.Load(files, jsonschema.Options{})
	if err != nil {
		return nil, err
	}
	var enums []enumsrc.Enum
	var axes []axesDef
	where := map[string]string{}
	for _, f := range order {
		for _, d := range set.Root(f).Defs {
			e, ok, err := read(set, f, d)
			if err != nil {
				return nil, fmt.Errorf("%s: $defs/%s: %v", f, d.Name, err)
			}
			if ok && slices.Contains(skip, d.Name) {
				where[d.Name] = f
				continue
			}
			if !ok || len(only) > 0 && !slices.Contains(only, d.Name) {
				continue
			}
			if w, dup := where[d.Name]; dup {
				return nil, fmt.Errorf("$defs/%s is an enumeration of %s and of %s: it is defined twice", d.Name, w, f)
			}
			where[d.Name] = f
			enums = append(enums, e)
		}
	}
	for _, f := range order {
		for _, d := range set.Root(f).Defs {
			if _, ok := d.Schema.Annotations["x-go-axes"]; !ok || len(only) > 0 && !slices.Contains(only, d.Name) {
				continue
			}
			a, axis, err := readAxes(d, enums)
			if err != nil {
				return nil, fmt.Errorf("%s: $defs/%s: %v", f, d.Name, err)
			}
			enums = append(enums, axis)
			axes = append(axes, a)
		}
	}
	for _, name := range only {
		if _, ok := where[name]; !ok {
			return nil, fmt.Errorf("-only %s: no schema has an enumeration of that name", name)
		}
	}
	for _, name := range skip {
		if _, ok := where[name]; !ok {
			return nil, fmt.Errorf("-skip %s: no schema has an enumeration of that name", name)
		}
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Code generated by enumgen from %s; DO NOT EDIT.\n\npackage %s\n\nimport (\n\t\"encoding/json\"\n\t\"fmt\"\n)\n", strings.Join(order, ", "), pkg)
	if err := enumsrc.Write(&b, enums); err != nil {
		return nil, err
	}
	for _, a := range axes {
		if err := axesTemplate.Execute(&b, a); err != nil {
			return nil, err
		}
	}
	return format.Source(b.Bytes())
}

// read reads d of file when it is an enumeration.
func read(set *jsonschema.Set, file string, d jsonschema.Named) (enumsrc.Enum, bool, error) {
	s := d.Schema
	zero, hasZero := s.Annotations["x-go-zero"]
	if !slices.ContainsFunc(s.OneOf, func(c *jsonschema.Schema) bool { return c.Const != nil }) {
		if hasZero {
			return enumsrc.Enum{}, false, fmt.Errorf("x-go-zero is only for an enumeration")
		}
		return enumsrc.Enum{}, false, nil
	}
	var values []enumsrc.Value
	for i, c := range s.OneOf {
		var v enumsrc.Value
		if c.Const == nil || !onlyConst(c) {
			return enumsrc.Enum{}, false, fmt.Errorf("the item %d must be a const and a description, and nothing else", i)
		}
		if json.Unmarshal(c.Const, &v.Name) != nil {
			return enumsrc.Enum{}, false, fmt.Errorf("the const of the item %d is not a string", i)
		}
		v.Doc = c.Description
		if strings.TrimSpace(v.Doc) == "" || strings.Contains(v.Doc, "\n") {
			return enumsrc.Enum{}, false, fmt.Errorf("%q needs a description on one line", v.Name)
		}
		var err error
		if v.GoName, err = constName(v.Name, c.Annotations); err != nil {
			return enumsrc.Enum{}, false, err
		}
		values = append(values, v)
	}
	var z string
	if hasZero && (json.Unmarshal(zero, &z) != nil || z == "") {
		return enumsrc.Enum{}, false, fmt.Errorf("x-go-zero %s is not one of the consts", zero)
	}
	doc := fmt.Sprintf("The values of $defs/%s, in the order of the schema.", d.Name)
	e, err := enumsrc.New(ident.GoName(d.Name), strings.ReplaceAll(d.Name, "-", " "), doc, values, z)
	if err != nil && hasZero && strings.Contains(err.Error(), "zero value") {
		err = fmt.Errorf("x-go-zero %s is not one of the consts", zero)
	}
	if err != nil {
		return enumsrc.Enum{}, false, err
	}
	e.Description = s.Description
	for _, c := range s.OneOf {
		if err := set.Validate(file, "#/$defs/"+d.Name, c.Const); err != nil {
			return enumsrc.Enum{}, false, fmt.Errorf("the schema does not take %s: %v", c.Const, err)
		}
	}
	return e, true, nil
}

var abbreviation = regexp.MustCompile(`^[A-Z][A-Z0-9]*$`)

// constName is the GoName of the constant of the value name: of name when
// it is kebab-case or snake_case (a value of the REST API), of its x-name
// when it is an abbreviation.
func constName(name string, ann map[string]json.RawMessage) (string, error) {
	raw, named := ann["x-name"]
	switch {
	case ident.IsKebab(name):
		if named {
			return "", fmt.Errorf("%q is a word: it takes no x-name", name)
		}
		return ident.GoName(name), nil
	case ident.IsSnake(name):
		// a value of the REST API of GitHub, such as local_only
		if named {
			return "", fmt.Errorf("%q is a word: it takes no x-name", name)
		}
		return ident.GoName(name), nil
	case abbreviation.MatchString(name):
		var x string
		if !named || json.Unmarshal(raw, &x) != nil || !ident.IsKebab(x) {
			return "", fmt.Errorf("%q is an abbreviation: it needs an x-name in kebab-case, what it stands for", name)
		}
		return ident.GoName(x), nil
	}
	return "", fmt.Errorf("%q is neither kebab-case, nor snake_case, nor an abbreviation in capitals", name)
}

// onlyConst is whether c has a const and a description, and nothing else
// that jsonschema keeps but an x-name.
func onlyConst(c *jsonschema.Schema) bool {
	for a := range c.Annotations {
		if a != "x-name" {
			return false
		}
	}
	return c.Ref == "" && c.Type == jsonschema.TypeAny && c.Enum == nil && c.Pattern == "" && c.MinLength == nil &&
		c.Properties == nil && c.Required == nil && !c.AdditionalFalse && c.Items == nil &&
		c.MinItems == nil && !c.UniqueItems && !c.UnevaluatedFalse &&
		c.OneOf == nil && c.Defs == nil && len(c.SchemaAnnotations) == 0
}

// axesDef is a member of $defs with x-go-axes, as axesTemplate writes it.
type axesDef struct {
	Name, Type, Doc string // the member, its Go type and its description
	Axis, AxisLower string // the axis type
	TypeLower       string
	Axes            []axisDef
}

// axisDef is a property of axesDef: its key, and the enumeration it is.
type axisDef struct{ Key, Field, Enum, ValuesFunc string }

// readAxes reads d, a member with x-go-axes, whose properties refer to
// enums, and makes the enumeration of its axes.
func readAxes(d jsonschema.Named, enums []enumsrc.Enum) (axesDef, enumsrc.Enum, error) {
	s := d.Schema
	var name string
	if json.Unmarshal(s.Annotations["x-go-axes"], &name) != nil || !ident.IsKebab(name) {
		return axesDef{}, enumsrc.Enum{}, fmt.Errorf("x-go-axes %s is not the name of the axis type in kebab-case", s.Annotations["x-go-axes"])
	}
	if s.Ref != "" {
		return axesDef{}, enumsrc.Enum{}, fmt.Errorf("the axes must be an object, not a $ref")
	}
	if s.Type != jsonschema.TypeObject || !s.AdditionalFalse {
		return axesDef{}, enumsrc.Enum{}, fmt.Errorf("the axes must be an object, closed (additionalProperties: false)")
	}
	if s.ShapesObject() {
		return axesDef{}, enumsrc.Enum{}, fmt.Errorf("the axes has unevaluatedProperties or a oneOf of objects, which change the shape of the object; the struct has one field for each property")
	}
	oneLine := func(t string) bool { return strings.TrimSpace(t) != "" && !strings.Contains(t, "\n") }
	if !oneLine(s.Description) {
		return axesDef{}, enumsrc.Enum{}, fmt.Errorf("the axes needs a description on one line")
	}
	var props []string
	for _, p := range s.Properties {
		props = append(props, p.Name)
	}
	if len(props) == 0 {
		return axesDef{}, enumsrc.Enum{}, fmt.Errorf("the axes needs one property at least")
	}
	if !slices.Equal(slices.Sorted(slices.Values(props)), slices.Sorted(slices.Values(s.Required))) {
		return axesDef{}, enumsrc.Enum{}, fmt.Errorf("the axes must require exactly its properties: it has %v and requires %v", props, s.Required)
	}
	typ, axis := ident.GoName(d.Name), ident.GoName(name)
	if slices.ContainsFunc(enums, func(e enumsrc.Enum) bool { return e.Type == axis || e.Type == typ }) {
		return axesDef{}, enumsrc.Enum{}, fmt.Errorf("x-go-axes %s: %s is the type of an enumeration, or the axes has its name", name, axis)
	}
	a := axesDef{Name: d.Name, Type: typ, Doc: s.Description, Axis: axis, AxisLower: lowerFirst(axis), TypeLower: lowerFirst(typ)}
	var values []enumsrc.Value
	for _, p := range s.Properties {
		ref := ""
		if p.Schema.Type == jsonschema.TypeArray && p.Schema.Items != nil {
			ref = strings.TrimPrefix(p.Schema.Items.Ref, "#/$defs/")
		}
		i := slices.IndexFunc(enums, func(e enumsrc.Enum) bool { return ref != "" && e.Type == ident.GoName(ref) })
		if i < 0 {
			return axesDef{}, enumsrc.Enum{}, fmt.Errorf("the property %s must be an array of an enumeration of the file", p.Name)
		}
		if key := strings.ReplaceAll(ref, "-", "_"); p.Name != key {
			return axesDef{}, enumsrc.Enum{}, fmt.Errorf("the property %s: the key of #/$defs/%s is %s", p.Name, ref, key)
		}
		if !oneLine(p.Schema.Description) {
			return axesDef{}, enumsrc.Enum{}, fmt.Errorf("the property %s needs a description on one line: what the axis is", p.Name)
		}
		e := enums[i]
		values = append(values, enumsrc.Value{Name: ref, GoName: e.Type, Doc: p.Schema.Description})
		a.Axes = append(a.Axes, axisDef{Key: p.Name, Field: e.Type, Enum: e.Type, ValuesFunc: e.ValuesFunc})
	}
	doc := fmt.Sprintf("The axes of $defs/%s: the enumerations of its properties, in the order of the schema.", d.Name)
	e, err := enumsrc.New(axis, strings.ReplaceAll(name, "-", " "), doc, values, "")
	if err != nil {
		return axesDef{}, enumsrc.Enum{}, err
	}
	return a, e, nil
}

func lowerFirst(s string) string { return strings.ToLower(s[:1]) + s[1:] }

var axesTemplate = template.Must(template.New("axes").Parse(`
// {{.Type}} is $defs/{{.Name}}: {{.Doc}}
type {{.Type}} struct {
{{range .Axes}}	{{.Field}} []{{.Enum}} ` + "`" + `json:"{{.Key}}"` + "`" + `
{{end}}}

var {{.AxisLower}}Keys = [...]string{"", {{range .Axes}}"{{.Key}}", {{end}}}

// Key is the key of the axis v in the JSON of {{.Type}}; empty for what is
// not an axis.
func (v {{.Axis}}) Key() string {
	if v.valid() {
		return {{.AxisLower}}Keys[v]
	}
	return ""
}

// Description is what the axis v is, as the schema says.
func (v {{.Axis}}) Description() string { return v.description() }
{{range .Axes}}
// Description is what v is, as the schema says.
func (v {{.Enum}}) Description() string { return v.description() }
{{end}}
// {{.Axis}}Value is a value of an axis of {{.Type}}.
type {{.Axis}}Value interface {
	fmt.Stringer
	json.Marshaler
	Description() string
	valid() bool
}

// {{.Axis}}Axis is an axis of {{.Type}} and values of it.
type {{.Axis}}Axis struct {
	{{.Axis}} {{.Axis}}
	Values []{{.Axis}}Value
}

// Axes are the axes of x, in the order of the schema, each with the values
// x has.
func (x {{.Type}}) Axes() []{{.Axis}}Axis {
	return []{{.Axis}}Axis{
{{range .Axes}}		{ {{$.Axis}}{{.Field}}, {{$.AxisLower}}ValuesOf(x.{{.Field}}) },
{{end}}	}
}

// {{.TypeLower}}All is {{.Type}} with every value of each axis.
func {{.TypeLower}}All() {{.Type}} {
	return {{.Type}}{ {{range $i, $a := .Axes}}{{if $i}}, {{end}}{{$a.Field}}: {{$a.ValuesFunc}}(){{end}} }
}

func {{.AxisLower}}ValuesOf[T {{.Axis}}Value](vs []T) []{{.Axis}}Value {
	out := make([]{{.Axis}}Value, 0, len(vs))
	for _, v := range vs {
		out = append(out, v)
	}
	return out
}
`))
