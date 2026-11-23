package ir

import (
	"encoding/json"
	"os"
	"testing"
)

// TestDeclarationsSorted: the views, the value types and the summary types
// are declared in the order of their names, so that two works that add
// different ones change different lines.
func TestDeclarationsSorted(t *testing.T) {
	for file, arrays := range map[string][]string{"views.json": {"views"}, "summaries.json": {"values", "summaries"}} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		for _, a := range arrays {
			var decls []struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(m[a], &decls); err != nil || len(decls) == 0 {
				t.Fatalf("%s: %s: %d declarations, %v", file, a, len(decls), err)
			}
			for i := 1; i < len(decls); i++ {
				if decls[i-1].Name >= decls[i].Name {
					t.Errorf("%s: %s: %s before %s", file, a, decls[i-1].Name, decls[i].Name)
					break
				}
			}
		}
	}
}
