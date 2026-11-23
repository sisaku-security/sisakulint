package repofile

// stripJSONC removes the comments (// to the end of the line, and /* */)
// and the commas before a ] or a } of b, out of strings, as Renovate reads
// JSONC: what remains is JSON when b was JSONC. An unclosed comment or
// string is left for the JSON reader to refuse.
func stripJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inString := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			out = append(out, c)
			switch c {
			case '\\':
				if i+1 < len(b) {
					i++
					out = append(out, b[i])
				}
			case '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			end := -1
			for j := i + 2; j+1 < len(b); j++ {
				if b[j] == '*' && b[j+1] == '/' {
					end = j + 1
					break
				}
			}
			if end < 0 {
				return append(out, b[i:]...)
			}
			out = append(out, ' ')
			i = end
		default:
			out = append(out, c)
		}
	}
	return dropTrailingCommas(out)
}

// dropTrailingCommas removes each comma of b, out of strings, that only
// white space separates from the next ] or }.
func dropTrailingCommas(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inString := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				i++
				out = append(out, b[i])
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
		}
		if c == ',' {
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\r' || b[j] == '\n') {
				j++
			}
			if j < len(b) && (b[j] == ']' || b[j] == '}') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}
