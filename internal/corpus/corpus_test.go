package corpus

import (
	"path/filepath"
	"testing"
)

func TestLocate(t *testing.T) {
	there := t.TempDir()
	missing := filepath.Join(there, "missing")
	cases := []struct {
		name      string
		env       string // CORPUS_DIR
		def       string // the default directory
		full      string // the variable set to full, if any
		wantDir   string
		wantThere bool
		wantErr   bool
	}{
		{"CORPUS_DIR there", there, missing, "", there, true, false},
		{"CORPUS_DIR missing", missing, there, "", "", false, true},
		{"no default", "", missing, "", "", false, false},
		{"no default, the whole corpus asked", "", missing, "CST_CORPUS", "", false, true},
		{"default there", "", there, "", there, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("CORPUS_DIR", c.env)
			for _, v := range fullVariables {
				t.Setenv(v, "")
			}
			if c.full != "" {
				t.Setenv(c.full, "full")
			}
			dir, ok, err := locate(c.def)
			if (err != nil) != c.wantErr || ok != c.wantThere || (ok && dir != c.wantDir) {
				t.Errorf("locate(%q) = %q, %v, %v; want %q, %v, error %v", c.def, dir, ok, err, c.wantDir, c.wantThere, c.wantErr)
			}
		})
	}
}
