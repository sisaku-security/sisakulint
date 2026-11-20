// Package enumsrc writes the Go source of an enumeration: its constants,
// the names of its values and what each is, and String, MarshalJSON,
// UnmarshalJSON, Parse<Type>, valid, description and the function of every
// value. The generators that read the schemas use it
// (actions/internal/enumgen, and schemagen of actions/workflow), so that
// every enumeration of sisakulint has the same methods.
package enumsrc

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"text/template"
)

// Value is one value of an enumeration: its name, as the JSON writes it;
// the rest of the name of its constant after the name of the type (the
// constant of the value network of AttackVector is AttackVectorNetwork);
// and its doc, which may be empty.
type Value struct{ Name, GoName, Doc string }

// Enum is one enumeration, made by New.
type Enum struct {
	Type         string
	Names        string  // the variable of the names
	Descriptions string  // the variable of what each value is
	ValuesFunc   string  // the function of every value
	DescName     string  // the constant of Description
	What         string  // what a value is, with its article: a severity
	Zero         bool    // the zero value is Values[0], and a value
	Values       []Value // in the order of the constants
	List         string  // the names, in the order given to New, for errors
	Doc          string  // of the block of constants
	// Description is what the enumeration is, as its source says; the
	// constant DescName is written only when there is one.
	Description string
}

// New makes the enumeration of the Go type typ, whose values are
// what (a noun, such as severity), in the order of values. Its zero value
// is typ and Unset, which is not a value, unless zero names one of values.
// doc says, for the block of constants, where the values are from.
func New(typ, what, doc string, values []Value, zero string) (Enum, error) {
	lower := strings.ToLower(typ[:1]) + typ[1:]
	e := Enum{Type: typ, Names: lower + "Names", Descriptions: lower + "Descriptions", ValuesFunc: lower + "Values",
		DescName: lower + "Description", What: Article(what), Doc: doc}
	consts := map[string]string{typ + "Unset": "the zero value"}
	var names []string
	for _, v := range values {
		if slices.Contains(names, v.Name) {
			return Enum{}, fmt.Errorf("%q is written twice", v.Name)
		}
		c := typ + v.GoName
		if other, dup := consts[c]; dup {
			return Enum{}, fmt.Errorf("%q and %s are both the constant %s", v.Name, other, c)
		}
		consts[c] = fmt.Sprintf("%q", v.Name)
		names = append(names, v.Name)
		e.Values = append(e.Values, v)
	}
	e.List = strings.Join(names, ", ")
	if zero != "" {
		i := slices.Index(names, zero)
		if i < 0 {
			return Enum{}, fmt.Errorf("the zero value %q is not one of the values", zero)
		}
		e.Zero = true
		first := e.Values[i]
		e.Values = append([]Value{first}, slices.Delete(slices.Clone(e.Values), i, i+1)...)
	}
	return e, nil
}

// Article is noun with a or an before it.
func Article(noun string) string {
	if strings.ContainsAny(noun[:1], "aeio") {
		return "an " + noun
	}
	return "a " + noun
}

// Write writes the declarations of enums. The file they are in imports
// encoding/json and fmt.
func Write(w io.Writer, enums []Enum) error {
	return decls.Execute(w, enums)
}

var decls = template.Must(template.New("").Parse(`{{range .}}{{$e := .}}
// {{.Doc}}{{if .Zero}} The zero value is the first.{{end}}
const (
{{- if not .Zero}}
	{{.Type}}Unset {{.Type}} = iota
{{- end}}
{{- range $i, $v := .Values}}
{{- if .Doc}}
	// {{$e.Type}}{{.GoName}}: {{.Doc}}
{{- end}}
	{{$e.Type}}{{.GoName}}{{if and $e.Zero (eq $i 0)}} {{$e.Type}} = iota{{end}}
{{- end}}
)

var {{.Names}} = [...]string{ {{- if not .Zero}}"", {{end}}{{range $i, $v := .Values}}{{if $i}}, {{end}}{{printf "%q" .Name}}{{end -}} }

var {{.Descriptions}} = [...]string{ {{- if not .Zero}}"", {{end}}{{range $i, $v := .Values}}{{if $i}}, {{end}}{{printf "%q" .Doc}}{{end -}} }

// description is what v is, as the source of the enumeration says; empty
// for what is not a value.
func (v {{.Type}}) description() string {
	if v.valid() {
		return {{.Descriptions}}[v]
	}
	return ""
}

// {{.ValuesFunc}} are the values of {{.Type}}, in the order of the constants.
func {{.ValuesFunc}}() []{{.Type}} {
	var out []{{.Type}}
	for i := range {{.Names}} {
		if v := {{.Type}}(i); v.valid() {
			out = append(out, v)
		}
	}
	return out
}
{{- if .Description}}

// {{.DescName}} is what {{.What}} is, as the source of the enumeration says.
const {{.DescName}} = {{printf "%q" .Description}}
{{- end}}

func (v {{.Type}}) valid() bool { return {{if not .Zero}}v > 0 && {{end}}int(v) < len({{.Names}}) }

func (v {{.Type}}) String() string {
{{- if not .Zero}}
	if v == {{.Type}}Unset {
		return "{{.Type}}Unset"
	}
{{- end}}
	if v.valid() {
		return {{.Names}}[v]
	}
	return fmt.Sprintf("{{.Type}}(%d)", uint8(v))
}

func (v {{.Type}}) MarshalJSON() ([]byte, error) {
	if !v.valid() {
		return nil, fmt.Errorf("%v is not {{.What}}", v)
	}
	return json.Marshal({{.Names}}[v])
}

func (v *{{.Type}}) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	p, err := Parse{{.Type}}(s)
	if err != nil {
		return err
	}
	*v = p
	return nil
}

// Parse{{.Type}} reads the name of {{.What}}, as the JSON writes it.
func Parse{{.Type}}(s string) ({{.Type}}, error) {
	for i, n := range {{.Names}} {
		if v := {{.Type}}(i); n == s && v.valid() {
			return v, nil
		}
	}
	return {{if .Zero}}{{.Type}}(len({{.Names}})){{else}}{{.Type}}Unset{{end}}, fmt.Errorf("%q is not {{.What}} ({{.List}})", s)
}
{{end}}`))
