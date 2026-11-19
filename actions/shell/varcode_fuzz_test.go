package shell

import "testing"

// FuzzVariableCodes: on any script VariableCodes does not panic, and each
// variable it gives spans its name in the script.
func FuzzVariableCodes(f *testing.F) {
	for _, c := range varCodeCases {
		f.Add(c.src)
	}
	for _, s := range unreadCases {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		for _, v := range VariableCodes(src, Parse(src)) {
			if v.Span.Start < 0 || v.Span.End > len(src) || v.Span.Start >= v.Span.End {
				t.Fatalf("%q: %v is outside the script", src, v)
			}
			text := src[v.Span.Start:v.Span.End]
			name := v.Name.String()
			var ok bool
			switch {
			case v.Bare:
				ok = text == name
			case len(text) > len(name)+2 && text[:3] == "${!":
				ok = text[3:3+len(name)] == name
			case len(text) > len(name)+1 && text[:2] == "${":
				ok = text[2:2+len(name)] == name
			default:
				ok = text == "$"+name
			}
			if !ok {
				t.Fatalf("%q: %v spans %q", src, v, text)
			}
		}
	})
}
