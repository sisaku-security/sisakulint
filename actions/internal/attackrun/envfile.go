package attackrun

import (
	"fmt"
	"strings"
)

// EnvPair is a name and its value, as the runner reads them from
// GITHUB_ENV or GITHUB_OUTPUT.
type EnvPair struct{ Name, Value string }

// readEnvFile reads text the way the runner reads GITHUB_ENV and
// GITHUB_OUTPUT on Linux (EnvFileKeyValuePairs): lines end at a line feed
// only; an empty line is skipped; name=value when = comes before <<, else
// name<<delimiter, whose value is the lines up to the first line that is
// the delimiter. The error is that of the first line it cannot read; the
// pairs before it are returned, since the runner has set them by then.
func readEnvFile(text string) ([]EnvPair, error) {
	var out []EnvPair
	i := 0
	line := func() (string, bool, bool) { // the line, whether it had a line feed, whether there was one
		if i >= len(text) {
			return "", false, false
		}
		j := strings.IndexByte(text[i:], '\n')
		if j < 0 {
			l := text[i:]
			i = len(text)
			return l, false, true
		}
		l := text[i : i+j]
		i += j + 1
		return l, true, true
	}
	for {
		l, _, ok := line()
		if !ok {
			return out, nil
		}
		if l == "" {
			continue
		}
		eq, hd := strings.Index(l, "="), strings.Index(l, "<<")
		switch {
		case eq >= 0 && (hd < 0 || eq < hd):
			out = append(out, EnvPair{l[:eq], l[eq+1:]})
		case hd >= 0:
			name, delim := l[:hd], l[hd+2:]
			if name == "" || delim == "" {
				return out, fmt.Errorf("invalid format %q: name must not be empty and delimiter must not be empty", l)
			}
			var vals []string
			for {
				v, lf, ok := line()
				if !ok {
					return out, fmt.Errorf("invalid value: matching delimiter not found %q", delim)
				}
				if v == delim {
					break
				}
				if !lf {
					return out, fmt.Errorf("invalid value: EOF marker missing new line")
				}
				vals = append(vals, v)
			}
			out = append(out, EnvPair{name, strings.Join(vals, "\n")})
		default:
			return out, fmt.Errorf("invalid format %q", l)
		}
	}
}

// readPathFile reads text the way the runner reads GITHUB_PATH
// (AddPathFileCommand: File.ReadAllLines, which ends a line at a carriage
// return, a line feed, or both): its lines that are not empty.
func readPathFile(text string) []string {
	var out []string
	for _, l := range strings.FieldsFunc(strings.ReplaceAll(text, "\r\n", "\n"), func(r rune) bool { return r == '\n' || r == '\r' }) {
		out = append(out, l)
	}
	return out
}
