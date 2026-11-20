package cli

import (
	"fmt"
	"os"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/anchor"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/scalar"
)

// legacyItem is a value of the legacy configuration file, and the line
// (from 1) of the file it is on.
type legacyItem struct {
	text string
	line int
}

// legacyList is the value of a key of the legacy configuration file whose
// value is a list of strings: present when the key is there, null when
// its value is null.
type legacyList struct {
	items   []legacyItem
	present bool
	null    bool
}

// legacyConfiguration is a configuration file of sisakulint before this
// linter, .github/sisakulint.yaml: the keys sisakulint 0.x reads, the keys
// it does not know (which sisakulint 0.x leaves out without an error), and
// the YAML documents after the first (which sisakulint 0.x does not read).
type legacyConfiguration struct {
	actionList, configurationVariables, allowedHosts, runnerLabels legacyList
	unknownKeys                                                    []legacyItem
	laterDocuments                                                 []legacyItem
}

// readLegacyConfiguration reads the legacy configuration file p as
// sisakulint 0.x reads it: a scalar of any type in a list is its text (a
// null is the empty string), an alias is followed, and a key given twice
// or a value of another type is an error. A merge key (<<), which
// sisakulint 0.x takes, is an error too, so that no key of the merged
// mapping is left out without a note. An error is a configurationError.
func readLegacyConfiguration(p string) (legacyConfiguration, error) {
	fail := func(err error) (legacyConfiguration, error) {
		return legacyConfiguration{}, configurationError{fmt.Errorf("--legacy-configuration %s: %w", p, err)}
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return fail(err)
	}
	t := cst.Parse(b)
	if len(t.Errors()) != 0 {
		return fail(fmt.Errorf("not YAML that can be read: %v", t.Errors()[0]))
	}
	r := legacyReader{tree: t, anchors: anchor.Build(t)}
	var c legacyConfiguration
	first := true
	for e := range t.Root().Children() {
		doc, ok := e.Node()
		if !ok || doc.Kind() != cst.NodeDocument {
			continue
		}
		top, ok := documentContent(doc)
		if !first {
			if ok {
				c.laterDocuments = append(c.laterDocuments, legacyItem{"---", r.line(top)})
			}
			continue
		}
		first = false
		if !ok {
			continue
		}
		if err := r.top(top, scalar.DirectivesOf(doc), &c); err != nil {
			return fail(err)
		}
	}
	return c, nil
}

// documentContent is the node of doc that is not a directive.
func documentContent(doc cst.Node) (cst.Node, bool) {
	for c := range doc.Children() {
		if n, ok := c.Node(); ok && n.Kind() != cst.NodeDirective {
			return n, true
		}
	}
	return cst.Node{}, false
}

// legacyReader reads the nodes of one legacy configuration file.
type legacyReader struct {
	tree    *cst.Tree
	anchors anchor.Index
	d       scalar.Directives
}

func (r *legacyReader) line(n cst.Node) int { return r.tree.Position(n.Span().Start).Line }

// value is n, or the node the alias n refers to.
func (r *legacyReader) value(n cst.Node) (cst.Node, error) {
	if n.Kind() != cst.NodeAlias {
		return n, nil
	}
	v, ok := r.anchors.Resolve(n)
	if !ok {
		return cst.Node{}, fmt.Errorf("line %d: an alias with no anchor", r.line(n))
	}
	return v, nil
}

// isNull is whether n is a YAML null.
func (r *legacyReader) isNull(n cst.Node) bool { return scalar.Resolve(n, r.d) == scalar.TagNull }

// entries reads the mapping n: each key once, by its name.
func (r *legacyReader) entries(n cst.Node, what string, each func(name string, key, value cst.Node) error) error {
	n, err := r.value(n)
	if err != nil || r.isNull(n) {
		return err
	}
	m, ok := n.Mapping()
	if !ok {
		return fmt.Errorf("line %d: %s is not a YAML mapping", r.line(n), what)
	}
	seen := map[string]bool{}
	for e := range m.Entries() {
		k, err := r.value(e.Key)
		if err != nil {
			return err
		}
		name, ok := scalar.Decode(k)
		if !ok {
			return fmt.Errorf("line %d: a key that is not a scalar", r.line(e.Key))
		}
		if name.String() == "<<" {
			return fmt.Errorf("line %d: a merge key (<<) is not supported: in the file, write the keys of the merged mapping in place of the merge key", r.line(e.Key))
		}
		if seen[name.String()] {
			return fmt.Errorf("line %d: the key %s is given twice", r.line(e.Key), name.String())
		}
		seen[name.String()] = true
		if err := each(name.String(), e.Key, e.Value); err != nil {
			return err
		}
	}
	return nil
}

// list reads n, the value of the key named key, as a list of strings.
func (r *legacyReader) list(key string, n cst.Node) (legacyList, error) {
	n, err := r.value(n)
	if err != nil {
		return legacyList{}, err
	}
	l := legacyList{present: true}
	if r.isNull(n) {
		l.null = true
		return l, nil
	}
	seq, ok := n.Sequence()
	if !ok {
		return legacyList{}, fmt.Errorf("line %d: %s is not a list of strings", r.line(n), key)
	}
	for item := range seq.Items() {
		v, err := r.value(item)
		if err != nil {
			return legacyList{}, err
		}
		if _, isMap := v.Mapping(); isMap {
			return legacyList{}, fmt.Errorf("line %d: %s is not a list of strings", r.line(v), key)
		}
		if _, isSeq := v.Sequence(); isSeq {
			return legacyList{}, fmt.Errorf("line %d: %s is not a list of strings", r.line(v), key)
		}
		text := ""
		if !r.isNull(v) {
			s, ok := scalar.Decode(v)
			if !ok {
				return legacyList{}, fmt.Errorf("line %d: %s is not a list of strings", r.line(v), key)
			}
			text = s.String()
		}
		l.items = append(l.items, legacyItem{text, r.line(item)})
	}
	return l, nil
}

// top reads the top level of the first document into c.
func (r *legacyReader) top(top cst.Node, d scalar.Directives, c *legacyConfiguration) error {
	r.d = d
	unknown := func(name string, key cst.Node) {
		c.unknownKeys = append(c.unknownKeys, legacyItem{name, r.line(key)})
	}
	nested := func(parent, child string, to *legacyList) func(string, cst.Node, cst.Node) error {
		return func(name string, key, value cst.Node) error {
			if name != child {
				unknown(parent+"."+name, key)
				return nil
			}
			l, err := r.list(parent+"."+name, value)
			*to = l
			return err
		}
	}
	return r.entries(top, "the top level of the file", func(name string, key, value cst.Node) error {
		var err error
		switch name {
		case "action-list":
			c.actionList, err = r.list(name, value)
		case "config-variables":
			c.configurationVariables, err = r.list(name, value)
		case "self-hosted-runner":
			err = r.entries(value, name, nested(name, "labels", &c.runnerLabels))
		case "secret-exfiltration":
			err = r.entries(value, name, nested(name, "allowed-hosts", &c.allowedHosts))
		default:
			unknown(name, key)
		}
		return err
	})
}
