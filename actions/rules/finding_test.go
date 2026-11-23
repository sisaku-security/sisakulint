package rules

import (
	"regexp"
	"testing"
)

// argumentPronoun is a word of an argument's text that points back to
// something before it, which the text of an argument, read apart from the
// text of the kind, does not have.
var argumentPronoun = regexp.MustCompile(`(?i)\b(it|its|they|them|their|there|this)\b`)

// Every argument of every kind says what it holds, in a text that names
// what it speaks of rather than pointing back with a pronoun.
func TestArgumentTexts(t *testing.T) {
	for _, k := range allFindingTexts {
		for _, a := range k.Arguments {
			switch {
			case a.Text == "":
				t.Errorf("%s {%s}: no text", k.ID, a.Name)
			case argumentPronoun.MatchString(a.Text):
				t.Errorf("%s {%s}: %q has %q", k.ID, a.Name, a.Text, argumentPronoun.FindString(a.Text))
			}
		}
	}
}
