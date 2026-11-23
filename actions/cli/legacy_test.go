package cli

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeLegacy writes content as a legacy configuration file and gives its
// path.
func writeLegacy(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sisakulint.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func itemTexts(l legacyList) []string {
	var s []string
	for _, i := range l.items {
		s = append(s, i.text)
	}
	return s
}

func TestReadLegacyConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		check   func(t *testing.T, c legacyConfiguration)
	}{
		{"action-list", "action-list: [a/b@*, \"c/d@v1\"]\n", func(t *testing.T, c legacyConfiguration) {
			if got := itemTexts(c.actionList); !reflect.DeepEqual(got, []string{"a/b@*", "c/d@v1"}) {
				t.Errorf("items = %q", got)
			}
			for _, i := range c.actionList.items {
				if i.line != 1 {
					t.Errorf("line of %q = %d, want 1", i.text, i.line)
				}
			}
			if !c.actionList.present || c.actionList.null {
				t.Errorf("present, null = %v, %v", c.actionList.present, c.actionList.null)
			}
		}},
		{"null", "config-variables: null\n", func(t *testing.T, c legacyConfiguration) {
			if !c.configurationVariables.present || !c.configurationVariables.null {
				t.Errorf("present, null = %v, %v", c.configurationVariables.present, c.configurationVariables.null)
			}
		}},
		{"no key", "action-list: []\n", func(t *testing.T, c legacyConfiguration) {
			if c.configurationVariables.present {
				t.Error("config-variables is present")
			}
		}},
		{"empty list", "config-variables: []\n", func(t *testing.T, c legacyConfiguration) {
			v := c.configurationVariables
			if !v.present || v.null || len(v.items) != 0 {
				t.Errorf("present, null, items = %v, %v, %q", v.present, v.null, itemTexts(v))
			}
		}},
		{"scalars", "config-variables: [1, true, null, FOO]\n", func(t *testing.T, c legacyConfiguration) {
			if got := itemTexts(c.configurationVariables); !reflect.DeepEqual(got, []string{"1", "true", "", "FOO"}) {
				t.Errorf("items = %q", got)
			}
		}},
		{"nested", "self-hosted-runner: {labels: [x]}\nsecret-exfiltration:\n  allowed-hosts:\n    - api.example.com\n", func(t *testing.T, c legacyConfiguration) {
			if got := itemTexts(c.runnerLabels); !reflect.DeepEqual(got, []string{"x"}) {
				t.Errorf("labels = %q", got)
			}
			if got := itemTexts(c.allowedHosts); !reflect.DeepEqual(got, []string{"api.example.com"}) {
				t.Errorf("allowed-hosts = %q", got)
			}
			if c.allowedHosts.items[0].line != 4 {
				t.Errorf("line = %d, want 4", c.allowedHosts.items[0].line)
			}
		}},
		{"unknown keys", "no-such-key: 1\nsecret-exfiltration: {other: 1}\n", func(t *testing.T, c legacyConfiguration) {
			var got []string
			for _, k := range c.unknownKeys {
				got = append(got, k.text)
			}
			if !reflect.DeepEqual(got, []string{"no-such-key", "secret-exfiltration.other"}) {
				t.Errorf("unknown keys = %q", got)
			}
		}},
		{"later document", "config-variables: [FOO]\n---\naction-list: [x]\n", func(t *testing.T, c legacyConfiguration) {
			if c.actionList.present {
				t.Error("action-list of the second document is read")
			}
			if len(c.laterDocuments) != 1 || c.laterDocuments[0].line != 3 {
				t.Errorf("later documents = %+v", c.laterDocuments)
			}
		}},
		{"alias", "x: &a [FOO]\nconfig-variables: *a\n", func(t *testing.T, c legacyConfiguration) {
			if got := itemTexts(c.configurationVariables); !reflect.DeepEqual(got, []string{"FOO"}) {
				t.Errorf("items = %q", got)
			}
		}},
		{"alias item", "x: &a FOO\nconfig-variables:\n  - *a\n", func(t *testing.T, c legacyConfiguration) {
			if v := c.configurationVariables; len(v.items) != 1 || v.items[0].text != "FOO" || v.items[0].line != 3 {
				t.Errorf("items = %+v, want FOO on line 3, where the alias is", v.items)
			}
		}},
		{"crlf", "action-list:\r\n  - a/b@*\r\nconfig-variables: [FOO]\r\n", func(t *testing.T, c legacyConfiguration) {
			if got := itemTexts(c.actionList); !reflect.DeepEqual(got, []string{"a/b@*"}) {
				t.Errorf("items = %q", got)
			}
			if got := itemTexts(c.configurationVariables); !reflect.DeepEqual(got, []string{"FOO"}) || c.configurationVariables.items[0].line != 3 {
				t.Errorf("config-variables = %+v", c.configurationVariables)
			}
		}},
		{"empty file", "", func(t *testing.T, c legacyConfiguration) {
			if c.actionList.present || c.configurationVariables.present || c.allowedHosts.present || c.runnerLabels.present {
				t.Errorf("a key is present: %+v", c)
			}
		}},
		{"null file", "null\n", func(t *testing.T, c legacyConfiguration) {
			if c.actionList.present || c.configurationVariables.present {
				t.Errorf("a key is present: %+v", c)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := readLegacyConfiguration(writeLegacy(t, tc.content))
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, c)
		})
	}
}

func TestReadLegacyConfigurationErrors(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{"not YAML", "action-list: [\n"},
		{"not a mapping", "- a\n"},
		{"not a list", "action-list: actions/checkout@*\n"},
		{"mapping item", "config-variables: [{a: b}]\n"},
		{"list for a mapping", "secret-exfiltration: [a]\n"},
		{"key twice", "config-variables: [FOO]\nconfig-variables: [BAR]\n"},
		{"merge key", "x: &a {config-variables: []}\n<<: *a\n"},
		{"nested merge key", "x: &a {allowed-hosts: [a.example.com]}\nsecret-exfiltration:\n  <<: *a\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := writeLegacy(t, tc.content)
			_, err := readLegacyConfiguration(p)
			var c configurationError
			if !errors.As(err, &c) {
				t.Fatalf("err = %v, want a configurationError", err)
			}
			if !strings.HasPrefix(err.Error(), "--legacy-configuration "+p+": ") {
				t.Errorf("err = %q, does not name the file", err)
			}
		})
	}
	_, err := readLegacyConfiguration(filepath.Join(t.TempDir(), "none.yaml"))
	var c configurationError
	if !errors.As(err, &c) {
		t.Errorf("a file that is not there: err = %v, want a configurationError", err)
	}
}
