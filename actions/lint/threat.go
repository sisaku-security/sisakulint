package lint

//go:generate go run github.com/sisaku-security/sisakulint/actions/internal/enumgen -pkg lint -out enum_gen.go -skip no-fix-reason -skip side-effect -ref ../facts/schema/facts-v0.json schema/registry-v0.json schema/report-v0.json

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// Threat is who can do what, and what they get (the threat model): the
// actors, preconditions and incidents a rule's kinds refer to.
type Threat struct {
	Actors        []Actor // one at least, each Attacker once
	Preconditions []Precondition
	Incidents     []Incident
}

// Actor is an attacker, how they go about it (Via, for people to read), the
// events it takes when the threat depends on them, who starts the run of each
// of those events, and what they get.
type Actor struct {
	Attacker Attacker
	Via      string
	Events   []workflow.EventName
	// RunStarters are who starts the run of each of Events: one each, and
	// none of another event, by the runs the attack takes: RunStarterAttacker
	// when the attack can take a run the attacker starts, even when another
	// person starts other runs of the event.
	RunStarters map[workflow.EventName]RunStarter
	Gains       []Gain // one at least
}

// Attacker is who the attacker is. Its values and what they mean are the
// oneOf of $defs/attacker in schema/registry-v0.json (enum_gen.go).
type Attacker uint8

// RunStarter is who starts the run of an event an actor takes. Its values
// and what they mean are the oneOf of $defs/run-starter in
// schema/registry-v0.json (enum_gen.go).
type RunStarter uint8

// Gain is what the attacker gets. Its values and what they mean are the
// oneOf of $defs/gain in schema/registry-v0.json (enum_gen.go).
type Gain uint8

// Precondition is a statement that the threat rests on (about GitHub, the
// runner, an action or a program a job runs, an AI agent, or the
// repository), and what backs it: what was seen on GitHub, or documents. It
// rests on at least one of them. A rule checks some preconditions on the
// input or by a kind of facts and not others; a finding does not mean that each
// precondition of its kind holds.
type Precondition struct {
	ID       PreconditionID
	Text     string
	Observed []Observation
	Cites    []Citation
}

// Observation is something seen on GitHub: when, with which runner, and
// what. Runner is zero when no runner took part (the API, a refused push, the
// server's reading of a workflow), whose version is not known.
type Observation struct {
	Date   Date
	Runner Version
	What   string
}

// Incident is a reported attack of what the rule detects. How the attacker
// went about it is in Summary.
type Incident struct {
	ID          IncidentID
	Date        Date
	CVE         CVEID        // zero when there is none
	Advisory    Citation     // the first-hand report
	Compromised []facts.Repo // the repositories the attacker changed; one at least
	Downstream  []facts.Repo // not changed, but hit through one of Compromised they use
	Summary     string       // what happened
}

// Date is a day, as YYYY-MM-DD. The zero Date is none.
type Date struct{ s string }

// ParseDate checks s and makes the Date.
func ParseDate(s string) (Date, error) {
	if _, err := time.Parse(time.DateOnly, s); err != nil {
		return Date{}, fmt.Errorf("%q is not a day written YYYY-MM-DD", s)
	}
	return Date{s}, nil
}

// MustDate is ParseDate that panics on an error.
func MustDate(s string) Date { return must(ParseDate(s)) }

func (d Date) String() string               { return d.s }
func (d Date) IsZero() bool                 { return d.s == "" }
func (d Date) MarshalJSON() ([]byte, error) { return marshalID(d.s, "Date") }

// Version is a version of the runner, major.minor.patch. The zero Version
// is none.
type Version struct{ major, minor, patch int }

var version = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// ParseVersion checks s and makes the Version.
func ParseVersion(s string) (Version, error) {
	p := version.FindStringSubmatch(s)
	if p == nil {
		return Version{}, fmt.Errorf("%q is not a version major.minor.patch", s)
	}
	n := func(s string) int { i, _ := strconv.Atoi(s); return i }
	v := Version{n(p[1]), n(p[2]), n(p[3])}
	if v.IsZero() {
		return Version{}, errors.New("0.0.0 is not a version of the runner")
	}
	return v, nil
}

// MustVersion is ParseVersion that panics on an error.
func MustVersion(s string) Version { return must(ParseVersion(s)) }

func (v Version) IsZero() bool { return v == Version{} }

func (v Version) String() string {
	if v.IsZero() {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}

func (v Version) MarshalJSON() ([]byte, error) { return marshalID(v.String(), "Version") }

// CVEID is the ID of a CVE, CVE-YYYY-NNNN. The zero CVEID is none.
type CVEID struct{ s string }

var cve = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// ParseCVE checks s and makes the CVEID.
func ParseCVE(s string) (CVEID, error) {
	if !cve.MatchString(s) {
		return CVEID{}, fmt.Errorf("%q is not the ID of a CVE", s)
	}
	return CVEID{s}, nil
}

// MustCVE is ParseCVE that panics on an error.
func MustCVE(s string) CVEID { return must(ParseCVE(s)) }

func (c CVEID) String() string               { return c.s }
func (c CVEID) IsZero() bool                 { return c.s == "" }
func (c CVEID) MarshalJSON() ([]byte, error) { return marshalID(c.s, "CVEID") }

// checkThreat checks that there is an attacker, each once with what they
// get; that every precondition rests on something; that an incident has
// its reports; and that each precondition and incident has an ID of its
// own. The kinds check the metrics (checkCVSS).
func checkThreat(t Threat) error {
	if len(t.Actors) == 0 {
		return errors.New("no actor: say who the attacker is")
	}
	for i, a := range t.Actors {
		if !a.Attacker.valid() {
			return fmt.Errorf("the actor %d: the attacker %v is not in the schema", i, a.Attacker)
		}
		if slices.ContainsFunc(t.Actors[:i], func(b Actor) bool { return b.Attacker == a.Attacker }) {
			return fmt.Errorf("the actor %d: the attacker %v twice", i, a.Attacker)
		}
		if strings.TrimSpace(a.Via) == "" {
			return fmt.Errorf("the actor %d has no Via", i)
		}
		if slices.Contains(a.Events, workflow.EventNameUnset) {
			return fmt.Errorf("the actor %d has the zero event", i)
		}
		for _, e := range a.Events {
			if !a.RunStarters[e].valid() {
				return fmt.Errorf("the actor %d: the event %v has no run starter", i, e)
			}
		}
		for e := range a.RunStarters {
			if !slices.Contains(a.Events, e) {
				return fmt.Errorf("the actor %d: a run starter of %v, which is none of its events", i, e)
			}
		}
		if len(a.Gains) == 0 {
			return fmt.Errorf("the actor %d has no gain", i)
		}
		for j, g := range a.Gains {
			if !g.valid() {
				return fmt.Errorf("the actor %d: the gain %v is not in the schema", i, g)
			}
			if slices.Contains(a.Gains[:j], g) {
				return fmt.Errorf("the actor %d has the gain %v twice", i, g)
			}
		}
	}
	for i, p := range t.Preconditions {
		if strings.TrimSpace(p.Text) == "" || len(p.Observed)+len(p.Cites) == 0 {
			return fmt.Errorf("the precondition %d needs a Text, and an observation or a citation it rests on", i)
		}
		if slices.Contains(p.Cites, Citation{}) {
			return fmt.Errorf("the precondition %d cites the zero citation", i)
		}
		for j, o := range p.Observed {
			if o.Date.IsZero() || strings.TrimSpace(o.What) == "" {
				return fmt.Errorf("the observation %d of the precondition %d needs a Date and What", j, i)
			}
		}
		if p.ID.IsZero() {
			return fmt.Errorf("the precondition %d has no ID", i)
		}
		if slices.ContainsFunc(t.Preconditions[:i], func(q Precondition) bool { return q.ID == p.ID }) {
			return fmt.Errorf("the precondition %s is declared twice", p.ID)
		}
	}
	for i, x := range t.Incidents {
		zero := func(r facts.Repo) bool { return r == facts.Repo{} }
		if x.Date.IsZero() || x.Advisory.s == "" || len(x.Compromised) == 0 || strings.TrimSpace(x.Summary) == "" ||
			slices.ContainsFunc(x.Compromised, zero) || slices.ContainsFunc(x.Downstream, zero) {
			return fmt.Errorf("the incident %d needs a Date, an Advisory, a repository Compromised and a Summary, and no zero repository", i)
		}
		if x.ID.IsZero() {
			return fmt.Errorf("the incident %d has no ID", i)
		}
		if slices.ContainsFunc(t.Incidents[:i], func(y Incident) bool { return y.ID == x.ID }) {
			return fmt.Errorf("the incident %s is declared twice", x.ID)
		}
	}
	return nil
}

type observationJSON struct {
	Date   Date     `json:"date"`
	Runner *Version `json:"runner,omitempty"`
	What   string   `json:"what"`
}

type preconditionJSON struct {
	ID       PreconditionID    `json:"id"`
	Text     string            `json:"text"`
	Observed []observationJSON `json:"observed"`
	Cites    []Citation        `json:"cites"`
}

type incidentJSON struct {
	ID          IncidentID   `json:"id"`
	Date        Date         `json:"date"`
	CVE         *CVEID       `json:"cve,omitempty"`
	Advisory    Citation     `json:"advisory"`
	Compromised []facts.Repo `json:"compromised"`
	Downstream  []facts.Repo `json:"downstream"`
	Summary     string       `json:"summary"`
}

type actorJSON struct {
	Attacker    Attacker             `json:"attacker"`
	Via         string               `json:"via"`
	Events      []workflow.EventName `json:"events"`
	RunStarters []runStarterJSON     `json:"run_starters"`
	Gains       []Gain               `json:"gains"`
}

type runStarterJSON struct {
	Event      workflow.EventName `json:"event"`
	RunStarter RunStarter         `json:"run_starter"`
}

type threatJSON struct {
	Actors        []actorJSON        `json:"actors"`
	Preconditions []preconditionJSON `json:"preconditions"`
	Incidents     []incidentJSON     `json:"incidents"`
}

// json is t as the registry's JSON writes it: a zero Runner or CVE is left
// out.
func (t Threat) json() threatJSON {
	j := threatJSON{Actors: []actorJSON{}, Preconditions: []preconditionJSON{}, Incidents: []incidentJSON{}}
	for _, a := range t.Actors {
		rs := []runStarterJSON{}
		for _, e := range a.Events {
			rs = append(rs, runStarterJSON{e, a.RunStarters[e]})
		}
		j.Actors = append(j.Actors, actorJSON{a.Attacker, a.Via, nonNil(a.Events), rs, a.Gains})
	}
	for _, p := range t.Preconditions {
		pj := preconditionJSON{ID: p.ID, Text: p.Text, Observed: []observationJSON{}, Cites: nonNil(p.Cites)}
		for _, o := range p.Observed {
			oj := observationJSON{Date: o.Date, What: o.What}
			if !o.Runner.IsZero() {
				oj.Runner = &o.Runner
			}
			pj.Observed = append(pj.Observed, oj)
		}
		j.Preconditions = append(j.Preconditions, pj)
	}
	for _, x := range t.Incidents {
		ij := incidentJSON{ID: x.ID, Date: x.Date, Advisory: x.Advisory, Compromised: nonNil(x.Compromised), Downstream: nonNil(x.Downstream), Summary: x.Summary}
		if !x.CVE.IsZero() {
			ij.CVE = &x.CVE
		}
		j.Incidents = append(j.Incidents, ij)
	}
	return j
}
