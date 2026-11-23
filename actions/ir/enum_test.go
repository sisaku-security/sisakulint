package ir

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/internal/enumtest"
	"github.com/sisaku-security/sisakulint/actions/internal/jsonschema"
)

// TestNoFixReason: the values of NoFixReason, the one type ir makes from
// the schema of the report (actions/lint and actions/rules use it), by
// enumtest.Check.
func TestNoFixReason(t *testing.T) {
	files := map[string][]byte{}
	for _, p := range []string{"../lint/schema/report-v0.json", "../lint/schema/registry-v0.json", "../facts/schema/facts-v0.json"} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		files[filepath.Base(p)] = b
	}
	s, err := jsonschema.Load(files, jsonschema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	enumtest.Check(t, len(noFixReasonNames), false, ParseNoFixReason, func(b []byte) error {
		return s.Validate("report-v0.json", "#/$defs/no-fix-reason", b)
	})
}
