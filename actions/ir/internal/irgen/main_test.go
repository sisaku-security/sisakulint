package main

import (
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "write the golden file")

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestGenerate: the Go of testdata/summaries.json and testdata/views.json
// is the golden file.
func TestGenerate(t *testing.T) {
	got, err := Generate(read(t, "testdata/summaries.json"), read(t, "testdata/views.json"))
	if err != nil {
		t.Fatal(err)
	}
	const golden = "testdata/summary_gen.go.golden"
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if string(got) != string(read(t, golden)) {
		t.Errorf("the generated code differs from %s; run go test -update and read the diff", golden)
	}
}

// TestGenerateRefuses: a definition the generator cannot make Go of is an
// error, not a reader with fewer accessors or Go that does not compile
func TestGenerateRefuses(t *testing.T) {
	const s = `{"summaries":[{"name":"A","list":"As","slug":"a","doc":"A.","fields":[{"name":"x","type":"string","doc":"x"}],"fixes":[{"name":"Do","params":"","result":"Outcome","doc":"d","reads":["a.x"]}]}]}`
	const v = `{"views":[{"name":"V","doc":"V is v.","fields":["a.x"],"fixes":[]}]}`
	for name, tc := range map[string][2]string{
		"no fields":        {`{"summaries":[{"name":"A","list":"As","slug":"a","doc":"A.","fields":[]}]}`, `{"views":[]}`},
		"field twice":      {`{"summaries":[{"name":"A","list":"As","slug":"a","doc":"A.","fields":[{"name":"x","type":"string","doc":"x"},{"name":"x","type":"bool","doc":"x"}]}]}`, `{"views":[]}`},
		"exported field":   {`{"summaries":[{"name":"A","list":"As","slug":"a","doc":"A.","fields":[{"name":"X","type":"string","doc":"x"}]}]}`, `{"views":[]}`},
		"unknown key":      {`{"summaries":[{"name":"A","list":"As","slug":"a","doc":"A.","fields":[{"name":"x","type":"string","doc":"x","disply":true}]}]}`, `{"views":[]}`},
		"view field":       {s, `{"views":[{"name":"V","doc":"V is v.","fields":["a.y"],"fixes":[]}]}`},
		"view op":          {s, `{"views":[{"name":"V","doc":"V is v.","fields":[],"fixes":["A.Undo"]}]}`},
		"view op summary":  {s, `{"views":[{"name":"V","doc":"V is v.","fields":[],"fixes":["B.Do"]}]}`},
		"op reads":         {`{"summaries":[{"name":"A","list":"As","slug":"a","doc":"A.","fields":[{"name":"x","type":"string","doc":"x"}],"fixes":[{"name":"Do","params":"","result":"Outcome","doc":"d","reads":["a.z"]}]}]}`, v},
		"op params":        {`{"summaries":[{"name":"A","list":"As","slug":"a","doc":"A.","fields":[{"name":"x","type":"string","doc":"x"}],"fixes":[{"name":"Do","params":"i int,,","result":"Outcome","doc":"d","reads":[]}]}]}`, v},
		"view field twice": {s, `{"views":[{"name":"V","doc":"V is v.","fields":["a.x","a.x"],"fixes":[]}]}`},
		"view twice":       {s, `{"views":[{"name":"V","doc":"V is v.","fields":["a.x"],"fixes":[]},{"name":"V","doc":"V is v.","fields":["a.x"],"fixes":[]}]}`},
		"view doc":         {s, `{"views":[{"name":"V","doc":"What V reads.","fields":["a.x"],"fixes":[]}]}`},
		// two types of one slug once gave the reader of one of them
		"slug twice": {`{"summaries":[{"name":"A","list":"As","slug":"s","doc":"A.","fields":[{"name":"x","type":"string","doc":"x"}]},{"name":"B","list":"Bs","slug":"s","doc":"B.","fields":[{"name":"x","type":"string","doc":"x"}]}]}`, `{"views":[{"name":"V","doc":"V is v.","fields":["s.x"],"fixes":[]}]}`},
		"list twice": {`{"summaries":[{"name":"A","list":"As","slug":"a","doc":"A.","fields":[{"name":"x","type":"string","doc":"x"}]},{"name":"B","list":"As","slug":"b","doc":"B.","fields":[{"name":"x","type":"string","doc":"x"}]}]}`, `{"views":[]}`},
	} {
		if _, err := Generate([]byte(tc[0]), []byte(tc[1])); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// TestUpToDate: summary_gen.go of actions/ir is what its definitions make
// (a view changed without go generate once kept its old reader).
func TestUpToDate(t *testing.T) {
	want, err := Generate(read(t, "../../summaries.json"), read(t, "../../views.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(read(t, "../../summary_gen.go")) != string(want) {
		t.Error("actions/ir/summary_gen.go is not up to date; run go generate ./actions/ir/")
	}
}
