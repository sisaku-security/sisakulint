package analysis

import "testing"

func TestParseActionBoolean(t *testing.T) {
	for s, want := range map[string]ActionBoolean{
		"": ActionBooleanUnwritten, "  ": ActionBooleanUnwritten,
		"true": ActionBooleanTrue, "True": ActionBooleanTrue, "TRUE": ActionBooleanTrue, " true\n": ActionBooleanTrue,
		"false": ActionBooleanFalse, "False": ActionBooleanFalse, "FALSE": ActionBooleanFalse,
		"yes": ActionBooleanOther, "tRue": ActionBooleanOther, "disable": ActionBooleanOther, "1": ActionBooleanOther,
	} {
		if got := ParseActionBoolean(s); got != want {
			t.Errorf("%q: %v, want %v", s, got, want)
		}
	}
}
