package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// additions are the schema additions (schema/additions.json): definitions
// and properties of mappings that the schema of languageservices lacks,
// each with what shows that GitHub takes it. An addition adds; it never
// changes a definition of languageservices.
type additions struct {
	Definitions map[string]addedDefinition `json:"definitions"`
	Properties  []addedProperty            `json:"properties"`
}

type addedDefinition struct {
	definition
	Basis []basis `json:"basis"`
}

type addedProperty struct {
	Definition string  `json:"definition"`
	Name       string  `json:"name"`
	Type       string  `json:"type"`
	Basis      []basis `json:"basis"`
}

// basis is what shows an addition: a document (a URL pinned to a commit and
// a line, the words quoted, their language, the day they were read) or an
// observation (what runs of a workflow on GitHub showed, the day, and the
// version of the runner, as lint.Observation).
type basis struct {
	URL       string `json:"url"`
	Quote     string `json:"quote"`
	Language  string `json:"language"`
	Retrieved string `json:"retrieved"`

	Date     string `json:"date"`
	Runner   string `json:"runner"`
	Observed string `json:"observed"`
}

// pinnedURL is a document's URL: https, a full commit SHA in its path, and
// a line.
var pinnedURL = regexp.MustCompile(`^https://[^#]*/[0-9a-f]{40}/[^#]+#L[0-9]+`)

var (
	day           = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	runnerVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

func (b basis) check() error {
	doc := b.URL != "" || b.Quote != "" || b.Language != "" || b.Retrieved != ""
	obs := b.Date != "" || b.Runner != "" || b.Observed != ""
	switch {
	case doc && obs:
		return fmt.Errorf("a basis is a document or an observation, not both")
	case doc:
		if !pinnedURL.MatchString(b.URL) || b.Quote == "" || b.Language == "" || b.Retrieved == "" {
			return fmt.Errorf("a document needs an https URL pinned to a commit with a line, a quote, its language and the day it was read")
		}
	case obs:
		if !day.MatchString(b.Date) || !runnerVersion.MatchString(b.Runner) || b.Observed == "" {
			return fmt.Errorf("an observation needs the day (YYYY-MM-DD), the version of the runner and what was observed")
		}
	default:
		return fmt.Errorf("a basis is empty")
	}
	return nil
}

func checkBasis(what string, bs []basis) error {
	if len(bs) == 0 {
		return fmt.Errorf("%s has no basis", what)
	}
	for _, b := range bs {
		if err := b.check(); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
	}
	return nil
}

func decodeAdditions(src []byte) (additions, error) {
	var a additions
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.DisallowUnknownFields()
	err := dec.Decode(&a)
	return a, err
}

// caughtUp is the error of an addition that defs already has: languageservices
// added it, so the addition is to go, after its definition is checked
// against the basis of the addition.
func caughtUp(what string) error {
	return fmt.Errorf("languageservices defines %s now: remove it from schema/additions.json and check its definition against the basis (the URL and the quotation) of the addition", what)
}

// add puts the additions a into defs, the definitions of languageservices
// with on-new merged. A built-in is no definition of languageservices, and
// one with action: is the action schema's, which addAction puts in later.
func add(defs map[string]definition, a additions) error {
	builtin := builtins()
	for _, n := range slices.Sorted(maps.Keys(a.Definitions)) {
		d := a.Definitions[n]
		what := fmt.Sprintf("the definition %q", n)
		if err := checkBasis(what, d.Basis); err != nil {
			return err
		}
		if _, ok := builtin[n]; ok {
			return fmt.Errorf("%s is a built-in", what)
		}
		if strings.HasPrefix(n, actionPrefix) {
			return fmt.Errorf("%s: a name with %s is the action schema's", what, actionPrefix)
		}
		if _, ok := defs[n]; ok {
			return caughtUp(what)
		}
		defs[n] = d.definition
	}
	for _, p := range a.Properties {
		what := fmt.Sprintf("the property %q of %q", p.Name, p.Definition)
		if err := checkBasis(what, p.Basis); err != nil {
			return err
		}
		if _, ok := builtin[p.Definition]; ok {
			return fmt.Errorf("%s: %q is a built-in", what, p.Definition)
		}
		d, ok := defs[p.Definition]
		if !ok || d.Mapping == nil {
			return fmt.Errorf("%s: %q is no mapping definition", what, p.Definition)
		}
		if _, ok := d.Mapping.Properties[p.Name]; ok {
			return caughtUp(what)
		}
		if _, ok := defs[p.Type]; !ok {
			return fmt.Errorf("%s: undefined type %q", what, p.Type)
		}
		if d.Mapping.Properties == nil {
			d.Mapping.Properties = map[string]property{}
		}
		d.Mapping.Properties[p.Name] = property{Type: p.Type}
	}
	return nil
}
