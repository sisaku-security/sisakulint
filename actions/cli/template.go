package cli

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// configurationTemplate is the configuration file --init writes: every key
// of configurationKeys with what the key does, as comments, and the
// values given with --init. A key with no value is a comment, so that the
// template with no value reads as no key. imported are the facts written
// from the legacy configuration file (--legacy-configuration), after the
// values of fact, and left the entries of that file not written, as
// comments after them.
func configurationTemplate(values []keyValue, imported []importedFact, left []legacyNote) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("# A configuration file of sisakulint: give it with --config FILE.\n")
	b.WriteString("# Each key does what the flag of the same name does. In the comments below,\n")
	b.WriteString("# --NAME also means the key NAME of this configuration file. A key with\n")
	b.WriteString("# nothing after the colon is the same as a key that is not written. A flag\n")
	b.WriteString("# given on the command line does not change this configuration file; how a\n")
	b.WriteString("# run uses the flag and the key of the same name together is in the usage\n")
	b.WriteString("# of --config (sisakulint -h).\n")
	for i := range configurationKeys {
		k := &configurationKeys[i]
		b.WriteString("\n")
		for _, l := range wrap(templateComment(*k), 76) {
			b.WriteString("# " + l + "\n")
		}
		var given []string
		for _, v := range values {
			if v.key != k {
				continue
			}
			if !utf8.ValidString(v.value) {
				return nil, usageError{fmt.Errorf("--init cannot write the value of --%s in the configuration file: the value is not UTF-8", k.name)}
			}
			given = append(given, v.value)
		}
		if k.name == "fact" && (len(imported) != 0 || len(left) != 0) {
			writeImported(&b, given, imported, left)
			continue
		}
		switch {
		case len(given) == 0:
			b.WriteString("# " + k.name + ":\n")
		case k.form == formBool:
			v, err := strconv.ParseBool(given[len(given)-1])
			if err != nil {
				return nil, usageError{fmt.Errorf("--%s: %w", k.name, err)}
			}
			b.WriteString(k.name + ": " + strconv.FormatBool(v) + "\n")
		case k.form == formList:
			b.WriteString(k.name + ":\n")
			for _, v := range given {
				b.WriteString("  - " + strconv.Quote(v) + "\n")
			}
		default:
			b.WriteString(k.name + ": " + strconv.Quote(given[len(given)-1]) + "\n")
		}
	}
	return b.Bytes(), nil
}

// writeImported writes the key fact with the values given, the facts
// imported from the legacy configuration file, each after the comments of
// its differences (when they are not those of the fact before), and the
// entries left, as comments. A list of more than one item is a folded
// block scalar with an item on each line: YAML joins the lines with a
// space, which JSON reads as white space between the items.
func writeImported(b *bytes.Buffer, given []string, imported []importedFact, left []legacyNote) {
	comment := func(s string) {
		for _, l := range wrap(printable(s), 74) {
			b.WriteString("  # " + l + "\n")
		}
	}
	if len(given) == 0 && len(imported) == 0 {
		b.WriteString("# fact:\n")
	} else {
		b.WriteString("fact:\n")
	}
	for _, v := range given {
		b.WriteString("  - " + strconv.Quote(v) + "\n")
	}
	var notes []string
	for _, f := range imported {
		if !slices.Equal(f.notes, notes) {
			for _, n := range f.notes {
				comment(n)
			}
			notes = f.notes
		}
		if f.value != "" || len(f.list) < 2 || slices.ContainsFunc(f.list, func(s string) bool { return printable(s) != s }) {
			b.WriteString("  - " + strconv.Quote(f.factText()) + "\n")
			continue
		}
		head := f.kind.String()
		if f.args != "" {
			head += "[" + f.args + "]"
		}
		b.WriteString("  - >-\n    " + head + "=[" + f.list[0] + ",\n")
		for _, item := range f.list[1 : len(f.list)-1] {
			b.WriteString("    " + item + ",\n")
		}
		b.WriteString("    " + f.list[len(f.list)-1] + "]\n")
	}
	if len(left) != 0 {
		comment("Not written from the legacy configuration file (--legacy-configuration):")
		for _, n := range left {
			for i, l := range wrap(printable(n.text), 72) {
				mark := "  "
				if i == 0 {
					mark = "- "
				}
				b.WriteString("  # " + mark + l + "\n")
			}
		}
	}
}

// printable is s with each byte that is not UTF-8 written as \xHH and
// each character that is not printable written as U+HHHH, so that YAML
// takes s in a comment or a block scalar as it is.
func printable(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, "\\x%02x", s[0])
		case r != ' ' && !unicode.IsPrint(r):
			fmt.Fprintf(&b, "%U", r)
		default:
			b.WriteRune(r)
		}
		s = s[size:]
	}
	return b.String()
}

// templateComment is what the template says of k: what the value decides,
// and how the value is written.
func templateComment(k configurationKey) string {
	s := k.help + "."
	switch k.form {
	case formList:
		s += " The value is a list of strings; every string in the list is used."
	case formBool:
		s += " The value is true or false; true is the same as giving the flag."
	default:
		s += " The value is a string."
	}
	if k.path {
		s += " A relative path is read from the directory of this configuration file."
	}
	return s + k.templateNote
}

// wrap breaks s into lines of at most width bytes at spaces; a word longer
// than width is a line by itself.
func wrap(s string, width int) []string {
	var lines []string
	line := ""
	for _, w := range strings.Fields(s) {
		switch {
		case line == "":
			line = w
		case len(line)+1+len(w) <= width:
			line += " " + w
		default:
			lines = append(lines, line)
			line = w
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// initUsage is the usage of --init.
func initUsage() string {
	path := func(k configurationKey) bool { return k.path }
	return fmt.Sprintf("write a configuration file for --config on stdout, and read nothing (with --legacy-configuration, read only the file of --legacy-configuration and the files under --root): every key with what the key does, and the value of each flag of a key given with --init. --init does not take %s: sisakulint reads a relative path in the key %s from the directory of the configuration file, and --init does not know that directory", flagNames("or", path), keyNames("or", path))
}
