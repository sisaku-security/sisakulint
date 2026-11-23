package scalar_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/anchor"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/internal/suitetest"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/scalar"
)

const suiteRoot = "../../../yaml-test-suite/data-2022-01-17"

// jsonExclude lists the cases whose in.json this package does not
// reproduce, with the reason and the section of the YAML 1.2.2
// specification it concerns.
var jsonExclude = map[string]string{
	// the values excluded in suite_exclude_test.go
	"L24T/01": "8.1.1.2: a last content line at the end of the input keeps no line feed",
	"JEF9/02": "8.1.1.2: spaces at the end of the input are no l-empty line",
}

// toJSON builds the JSON value of n: a mapping is a map with string keys,
// a sequence a slice, a scalar the value of its resolved tag, and an alias
// the value of the node it refers to.
func toJSON(n cst.Node, d scalar.Directives, x anchor.Index, depth int) (any, error) {
	if depth > 100 {
		return nil, errors.New("alias cycle")
	}
	if n.Kind() == cst.NodeAlias {
		r, ok := x.Resolve(n)
		if !ok {
			return nil, fmt.Errorf("undefined alias %s", n.Bytes())
		}
		return toJSON(r, d, x, depth+1)
	}
	if m, ok := n.Mapping(); ok {
		obj := map[string]any{}
		for e := range m.Entries() {
			k, err := toJSON(e.Key, d, x, depth+1)
			if err != nil {
				return nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("key %q is %T", e.Key.Bytes(), k)
			}
			if obj[ks], err = toJSON(e.Value, d, x, depth+1); err != nil {
				return nil, err
			}
		}
		return obj, nil
	}
	if s, ok := n.Sequence(); ok {
		arr := []any{}
		for it := range s.Items() {
			v, err := toJSON(it, d, x, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		return arr, nil
	}
	v, ok := scalar.Decode(n)
	if !ok {
		return nil, fmt.Errorf("%v node", n.Kind())
	}
	s := v.String()
	switch tag := scalar.Resolve(n, d); tag {
	case scalar.TagNull:
		return nil, nil
	case scalar.TagBool:
		if b, ok := scalar.Bool(s); ok {
			return b, nil
		}
	case scalar.TagInt:
		if i, ok := scalar.Int(s); ok {
			return float64(i), nil
		}
	case scalar.TagFloat:
		if f, ok := scalar.Float(s); ok {
			return f, nil
		}
	default:
		return s, nil
	}
	return nil, fmt.Errorf("%q is no %s", s, scalar.Resolve(n, d))
}

// documents is the JSON value of each document of src.
func documents(src []byte) ([]any, error) {
	tr := cst.Parse(src)
	x := anchor.Build(tr)
	var vs []any
	for e := range tr.Root().Children() {
		doc, ok := e.Node()
		if !ok || doc.Kind() != cst.NodeDocument {
			continue
		}
		for de := range doc.Children() {
			n, ok := de.Node()
			if !ok || n.Kind() == cst.NodeDirective || n.Kind() == cst.NodeError {
				continue
			}
			v, err := toJSON(n, scalar.DirectivesOf(doc), x, 0)
			if err != nil {
				return nil, err
			}
			vs = append(vs, v)
		}
	}
	return vs, nil
}

// readJSON reads the JSON values of in.json, with numbers as float64.
func readJSON(b []byte) ([]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var vs []any
	for {
		var v any
		err := dec.Decode(&v)
		if err == io.EOF {
			return vs, nil
		}
		if err != nil {
			return nil, err
		}
		vs = append(vs, numbers(v))
	}
}

func numbers(v any) any {
	switch v := v.(type) {
	case json.Number:
		f, _ := v.Float64()
		return f
	case []any:
		for i := range v {
			v[i] = numbers(v[i])
		}
	case map[string]any:
		for k := range v {
			v[k] = numbers(v[k])
		}
	}
	return v
}

func TestSuiteJSON(t *testing.T) {
	cs, err := suitetest.LoadCached(suiteRoot)
	if err != nil {
		t.Fatal(err)
	}
	pass, total := 0, 0
	suitetest.Run(t, cs, "json", jsonExclude, new(suitetest.Tally), func(t *testing.T, c suitetest.Case) {
		b, err := os.ReadFile(filepath.Join(suiteRoot, c.ID, "in.json"))
		if err != nil {
			t.Skip("no in.json")
		}
		total++
		want, err := readJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		got, err := documents(c.In)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got  %s\nwant %s", show(got), show(want))
			return
		}
		pass++
	})
	t.Logf("json %d/%d", pass, total)
}

func show(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return strings.TrimSpace(string(b))
}
