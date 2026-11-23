package shell

import "testing"

// requestWords is the request roles of words, the known ones as text and
// the others ($X) not known, with prefix the literal before what is not
// known.
func requestWords(texts ...string) []CommandWord {
	var ws []CommandWord
	for _, t := range texts {
		switch {
		case t == "$X":
			ws = append(ws, CommandWord{MayBeOption: false})
		case len(t) > 2 && t[len(t)-2:] == "$X":
			ws = append(ws, CommandWord{Prefix: t[:len(t)-2]})
		default:
			ws = append(ws, CommandWord{Text: t, Known: true})
		}
	}
	return ws
}

func TestRequestRoles(t *testing.T) {
	for _, c := range []struct {
		words []string
		want  []RequestWord
	}{
		{
			[]string{"curl", "-fsSL", "-H", "Authorization: Bearer $X", "https://x/", "-o", "out"},
			[]RequestWord{{}, {}, {}, {Reading: RequestReadingCredential}, {Reading: RequestReadingDestination}, {}, {}},
		},
		{ // an option after the URL
			[]string{"curl", "https://x/", "-H", "A: b"},
			[]RequestWord{{}, {Reading: RequestReadingDestination}, {}, {Reading: RequestReadingCredential}},
		},
		{ // the value joined to the option
			[]string{"curl", "--url=$X", "-HAuthorization: $X"},
			[]RequestWord{{}, {Reading: RequestReadingDestination, ValueAt: 6}, {Reading: RequestReadingCredential, ValueAt: 2}},
		},
		{
			[]string{"gh", "api", "https://x/", "--hostname", "h"},
			[]RequestWord{{}, {}, {Reading: RequestReadingEndpoint}, {}, {Reading: RequestReadingHostname}},
		},
		{ // the table declares every option of curl that takes a value: one it does not declare takes none
			[]string{"curl", "-fsSL", "--not-declared", "$X"},
			[]RequestWord{{}, {}, {}, {Reading: RequestReadingDestination}},
		},
		{ // a value not known joined to a short option
			[]string{"curl", "-H$X", "https://x/"},
			[]RequestWord{{}, {Reading: RequestReadingCredential, ValueAt: 2}, {Reading: RequestReadingDestination}},
		},
		{ // curl's --expand- before a long option: the option, its value expanded
			[]string{"curl", "--expand-header", "A: $X", "--expand-url=https://x/"},
			[]RequestWord{{}, {}, {Reading: RequestReadingCredential}, {Reading: RequestReadingDestination, ValueAt: 13}},
		},
		{ // a command that sends no request
			[]string{"echo", "https://x/"},
			[]RequestWord{{}, {}},
		},
	} {
		ws := requestWords(c.words...)
		got := RequestRoles(ArgumentRoles(ws), ws)
		if len(got) != len(c.want) {
			t.Fatalf("%v: %d words, want %d", c.words, len(got), len(c.want))
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%v: word %d (%q) = %+v, want %+v", c.words, i, c.words[i], got[i], c.want[i])
			}
		}
	}
}
