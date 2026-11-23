package cli

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// legacyHost is an entry of secret-exfiltration.allowed-hosts of the
// legacy configuration file, or of a directive: a host (an IPv6 address in
// brackets, as a RequestDestination has it), or with subdomains the
// subdomains of the host but not the host itself.
type legacyHost struct {
	name       string
	subdomains bool
}

// parseLegacyHost reads an entry as sisakulint 0.x reads it: without the
// quotes and the white space around it, in lower case, with no scheme,
// path, port or white space, and with a * only as a leading "*.". An
// entry that sisakulint 0.x rejects is an error.
func parseLegacyHost(entry string) (legacyHost, error) {
	v := strings.TrimSpace(strings.Trim(entry, `"'`))
	switch {
	case v == "":
		return legacyHost{}, errors.New("the entry is empty")
	case strings.Contains(v, "://"):
		return legacyHost{}, errors.New("the entry has a scheme; an entry is a host, not a URL")
	case strings.ContainsAny(v, "/?#@ \t"):
		return legacyHost{}, errors.New("the entry has a path, a query, a fragment, user information or white space")
	}
	if strings.HasPrefix(v, "[") {
		end := strings.Index(v, "]")
		switch {
		case end < 0:
			return legacyHost{}, errors.New("the entry has a [ without a ]")
		case end != len(v)-1:
			return legacyHost{}, errors.New("the entry has characters after the ]; a port is not taken")
		}
		if ip := net.ParseIP(v[1:end]); ip == nil || ip.To4() != nil {
			return legacyHost{}, errors.New("the entry in brackets is not an IPv6 address")
		}
		return legacyHost{"[" + strings.ToLower(v[1:end]) + "]", false}, nil
	}
	if strings.Contains(v, "::") || strings.Count(v, ":") >= 2 {
		if ip := net.ParseIP(v); ip != nil && ip.To4() == nil {
			return legacyHost{"[" + strings.ToLower(v) + "]", false}, nil
		}
		return legacyHost{}, errors.New("the entry has a : but is not an IPv6 address")
	}
	if strings.Contains(v, ":") {
		return legacyHost{}, errors.New("the entry has a port; an entry is a host only")
	}
	v = strings.ToLower(v)
	if rest, ok := strings.CutPrefix(v, "*."); ok {
		switch {
		case rest == "":
			return legacyHost{}, errors.New("the entry has nothing after *.")
		case strings.Contains(rest, "*"):
			return legacyHost{}, errors.New("the entry has more than one *")
		}
		return legacyHost{rest, true}, nil
	}
	if strings.Contains(v, "*") {
		return legacyHost{}, errors.New("the entry has a * that is not a leading *.")
	}
	return legacyHost{v, false}, nil
}

// matches is whether the destination is a host that h matches as
// sisakulint 0.x matches it: the same host, or with subdomains a host that
// ends with a dot and the name of h. A destination that is the path of a
// value (${{ }}) matches no entry.
func (h legacyHost) matches(destination facts.RequestDestination) bool {
	d := destination.String()
	if strings.HasPrefix(d, "${{") {
		return false
	}
	d = strings.TrimSuffix(d, ".")
	if h.subdomains {
		return strings.HasSuffix(d, "."+h.name)
	}
	return d == h.name
}

// destinationPair is a pair of a secret and a destination that a workflow
// sends the secret to: the query of a finding of secret-exfiltration, and
// the name of the file of the finding.
type destinationPair struct {
	query facts.RequestDestinationTrusted
	file  facts.InputPath
}

// legacyDirective is an entry of a directive of a workflow: the comment
// "# sisakulint:secret-exfiltration.allowed-hosts: ..." with which
// sisakulint 0.x allows the hosts in the one workflow.
type legacyDirective struct {
	item legacyItem
	file facts.InputPath
}

// The differences between an allowed host of sisakulint 0.x and
// request.destination-trusted.
const (
	pairNote = "This linter has no fact that trusts a host with every secret: request.destination-trusted trusts the destination with this one secret only, and sisakulint 0.x allowed every secret to the host. When a workflow later sends another secret to the destination, this linter reports a Finding: write the fact of the new pair in the configuration file of this linter (the file that has this comment). --init with --legacy-configuration writes a new configuration file on stdout and does not change the file that has this comment."
	// directiveNote is of the files of the directives that matched the pair.
	directiveNote = "A directive of sisakulint 0.x in %s allowed the host only in the workflow that has the directive. request.destination-trusted trusts the destination with the secret in every workflow of the repository, so a workflow that has no directive and sends the secret to the destination is no longer reported."
)

// legacyAllowedHosts writes, for each pair whose destination a host
// matches, request.destination-trusted as true: a host of entries matches
// the pairs of every file, and a host of a directive the pairs of its own
// file. An entry that sisakulint 0.x rejects, or that matches no pair, is
// a note. Each pair is written once, in the order of the secret and then
// the destination.
func legacyAllowedHosts(entries []legacyItem, directives []legacyDirective, pairs []destinationPair) ([]importedFact, []legacyNote) {
	type source struct {
		label     string // what the note names the source by
		item      legacyItem
		host      legacyHost
		directive bool            // of a directive, which matches the pairs of file only
		file      facts.InputPath // the file of the directive
	}
	var notes []legacyNote
	var sources []source
	add := func(label string, i legacyItem, directive bool, file facts.InputPath) {
		h, err := parseLegacyHost(i.text)
		if err != nil {
			notes = append(notes, notWritten(label, i, "sisakulint 0.x did not read the entry either: "+err.Error()))
			return
		}
		sources = append(sources, source{label, i, h, directive, file})
	}
	for _, i := range entries {
		add("secret-exfiltration.allowed-hosts", i, false, facts.InputPath{})
	}
	for _, d := range directives {
		add("the directive in "+d.file.String(), d.item, true, d.file)
	}
	used := make([]bool, len(sources))
	written := map[facts.RequestDestinationTrusted]*importedFact{}
	global := map[facts.RequestDestinationTrusted]bool{}                      // a host of entries matches the pair
	directiveFiles := map[facts.RequestDestinationTrusted][]facts.InputPath{} // the files of the directives that match the pair
	for _, p := range pairs {
		for si, s := range sources {
			if s.directive && s.file != p.file || !s.host.matches(p.query.Destination) {
				continue
			}
			used[si] = true
			f := written[p.query]
			if f == nil {
				f = &importedFact{kind: facts.KindRequestDestinationTrusted, args: "secret=" + p.query.Secret.String() + ",destination=" + p.query.Destination.String(), value: "true"}
				written[p.query] = f
			}
			switch {
			case !s.directive:
				global[p.query] = true
			case !slices.Contains(directiveFiles[p.query], s.file):
				directiveFiles[p.query] = append(directiveFiles[p.query], s.file)
			}
		}
	}
	for si, s := range sources {
		switch {
		case used[si]:
		case s.directive:
			notes = append(notes, notWritten(s.label, s.item, "the workflow "+s.file.String()+", as the workflow is when --init runs, does not send a secret to a host that the entry matches, so there is no pair of a secret and a destination to write; when the workflow later sends a secret to such a host, write the fact request.destination-trusted of that pair in the configuration file of this linter"))
		default:
			notes = append(notes, notWritten(s.label, s.item, "no workflow or action metadata file under --root, as the files are when --init runs, sends a secret to a host that the entry matches, so there is no pair of a secret and a destination to write; when a file later sends a secret to such a host, write the fact request.destination-trusted of that pair in the configuration file of this linter"))
		}
	}
	var out []importedFact
	for q, f := range written {
		f.notes = []string{pairNote}
		if files := directiveFiles[q]; !global[q] && len(files) != 0 {
			var names []string
			for _, n := range files {
				names = append(names, n.String())
			}
			f.notes = append(f.notes, fmt.Sprintf(directiveNote, strings.Join(names, " and ")))
		}
		out = append(out, *f)
	}
	slices.SortFunc(out, func(x, y importedFact) int { return cmp.Compare(x.args, y.args) })
	return out, notes
}
