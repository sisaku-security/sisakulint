package facts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// AllowedActionsPolicy is which actions and reusable workflows the setting
// of allowed actions of GitHub allows ($defs/allowed-actions-policy):
// allowed_actions of the REST API. The zero value is none.
type AllowedActionsPolicy uint8

// AllowedActionsPattern is a pattern of patterns_allowed of the setting of
// allowed actions of GitHub ($defs/allowed-actions-pattern), written as the
// setting writes it. Unlike an ActionPattern, it compares the whole uses
// without case, as GitHub does: a path and a ref too. The text is kept as
// written, since a Condition compares the answer with the value as JSON.
// The zero AllowedActionsPattern is none.
type AllowedActionsPattern struct {
	s  string
	re *regexp.Regexp // the pattern without its !, of the whole uses, without case
}

// ParseAllowedActionsPattern reads a pattern: no white space, no comma,
// and not empty, not ! alone and not !! at the start.
func ParseAllowedActionsPattern(s string) (AllowedActionsPattern, error) {
	if !actionPatternText.MatchString(s) {
		return AllowedActionsPattern{}, fmt.Errorf("%q is not a pattern of patterns_allowed: a pattern has the form of a value of uses, may have * for any characters and a ! at the start to block, and has no white space and no comma (write each pattern of the comma-separated list of the settings page of GitHub as a separate pattern)", s)
	}
	return AllowedActionsPattern{s, wholeUses(`(?is)`, strings.TrimPrefix(s, "!"))}, nil
}

// MustAllowedActionsPattern is ParseAllowedActionsPattern that panics on an
// error.
func MustAllowedActionsPattern(s string) AllowedActionsPattern {
	p, err := ParseAllowedActionsPattern(s)
	if err != nil {
		panic(err)
	}
	return p
}

func (p AllowedActionsPattern) String() string { return p.s }

func (p AllowedActionsPattern) blocks() bool { return strings.HasPrefix(p.s, "!") }

func (p AllowedActionsPattern) matches(uses string) bool {
	return p.re != nil && p.re.MatchString(uses)
}

func (p AllowedActionsPattern) MarshalJSON() ([]byte, error) {
	if p.s == "" {
		return nil, errors.New("the zero AllowedActionsPattern is no pattern")
	}
	return json.Marshal(p.s)
}

func (p *AllowedActionsPattern) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseAllowedActionsPattern(s)
	if err != nil {
		return err
	}
	*p = v
	return nil
}

// AllowedActionsSetting is the setting of allowed actions of GitHub that
// applies to the workflows of a repository ($defs/allowed-actions-setting),
// the value of repo.allowed-actions. GitHubOwned, Verified and the patterns
// are of the policy selected only. The zero AllowedActionsSetting is none.
type AllowedActionsSetting struct {
	policy      AllowedActionsPolicy
	githubOwned bool
	verified    bool
	patterns    []AllowedActionsPattern
	shaPinning  bool
}

// NewAllowedActionsSetting is the setting of the policy p: githubOwned,
// verified and patterns only with the policy selected, which needs
// patterns (empty, not nil, for none).
func NewAllowedActionsSetting(p AllowedActionsPolicy, githubOwned, verified bool, patterns []AllowedActionsPattern, shaPinning bool) (AllowedActionsSetting, error) {
	switch {
	case !p.valid():
		return AllowedActionsSetting{}, errors.New("a setting of allowed actions must have allowed_actions: all, local_only or selected")
	case p != AllowedActionsPolicySelected && (githubOwned || verified || patterns != nil):
		return AllowedActionsSetting{}, fmt.Errorf("a setting of allowed actions must not have any of github_owned_allowed, verified_allowed and patterns_allowed when allowed_actions is %v", p)
	case p == AllowedActionsPolicySelected && patterns == nil:
		return AllowedActionsSetting{}, errors.New("a setting of allowed actions must have patterns_allowed when allowed_actions is selected")
	case slices.ContainsFunc(patterns, func(x AllowedActionsPattern) bool { return x.s == "" }):
		return AllowedActionsSetting{}, errors.New("the zero AllowedActionsPattern is no pattern")
	}
	return AllowedActionsSetting{p, githubOwned, verified, slices.Clone(patterns), shaPinning}, nil
}

// PinningRequired is sha_pinning_required: a uses of an action must name a
// full commit SHA.
func (s AllowedActionsSetting) PinningRequired() bool { return s.shaPinning }

// AllowedActionsVerdict is whether a setting allows a uses.
type AllowedActionsVerdict uint8

const (
	AllowedActionsAllowed    AllowedActionsVerdict = iota // the setting allows the uses
	AllowedActionsNotAllowed                              // GitHub stops the run or the job of the uses
	// AllowedActionsUndecidedVerifiedCreator: only a verified creator of
	// GitHub Marketplace would allow the uses, which the workflow does not
	// tell.
	AllowedActionsUndecidedVerifiedCreator
)

var allowedActionsVerdictNames = [...]string{"allowed", "not allowed", "undecided (verified creator)"}

func (v AllowedActionsVerdict) String() string { return allowedActionsVerdictNames[v] }

// githubOwners are the organizations of the actions that GitHub creates.
var githubOwners = []string{"actions", "github"}

// Allows is whether s allows uses, a uses of another repository
// (owner/repo[/path]@ref, as GitHub reads it) or of a Docker image
// (docker://image), in the workflows of repo. When repo is zero (the name
// is not given), no uses is of the owner of the repository: a uses that
// only the owner would allow is not allowed. A uses of ./ or $/ is the
// caller's to leave out: the setting always allows it.
func (s AllowedActionsSetting) Allows(repo Repo, uses string) AllowedActionsVerdict {
	if s.policy == AllowedActionsPolicyAll {
		return AllowedActionsAllowed
	}
	image := strings.HasPrefix(uses, "docker://")
	owner, _, _ := strings.Cut(uses, "/")
	for _, p := range s.patterns {
		if p.blocks() && p.matches(uses) {
			return AllowedActionsNotAllowed
		}
	}
	switch {
	case !image && !repo.IsZero() && strings.EqualFold(owner, repo.owner):
		return AllowedActionsAllowed
	case s.policy == AllowedActionsPolicyLocalOnly:
		return AllowedActionsNotAllowed
	}
	if s.githubOwned && !image {
		for _, o := range githubOwners {
			if strings.EqualFold(owner, o) {
				return AllowedActionsAllowed
			}
		}
	}
	for _, p := range s.patterns {
		if !p.blocks() && p.matches(uses) {
			return AllowedActionsAllowed
		}
	}
	if s.verified {
		// whether verified_allowed covers a Docker image was not tried
		return AllowedActionsUndecidedVerifiedCreator
	}
	return AllowedActionsNotAllowed
}

type allowedActionsSettingJSON struct {
	Policy      AllowedActionsPolicy     `json:"allowed_actions"`
	GitHubOwned *bool                    `json:"github_owned_allowed,omitempty"`
	Verified    *bool                    `json:"verified_allowed,omitempty"`
	Patterns    *[]AllowedActionsPattern `json:"patterns_allowed,omitempty"`
	SHAPinning  *bool                    `json:"sha_pinning_required"`
}

func (s AllowedActionsSetting) MarshalJSON() ([]byte, error) {
	if !s.policy.valid() {
		return nil, errors.New("the zero AllowedActionsSetting is no setting")
	}
	j := allowedActionsSettingJSON{Policy: s.policy, SHAPinning: &s.shaPinning}
	if s.policy == AllowedActionsPolicySelected {
		patterns := s.patterns
		if patterns == nil {
			patterns = []AllowedActionsPattern{}
		}
		j.GitHubOwned, j.Verified, j.Patterns = &s.githubOwned, &s.verified, &patterns
	}
	return json.Marshal(j)
}

func (s *AllowedActionsSetting) UnmarshalJSON(b []byte) error {
	// a key is there or not, and a null is not a value of the key, as the
	// schema reads the object
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		return err
	}
	for k, v := range keys {
		if string(v) == "null" {
			return fmt.Errorf("a setting of allowed actions must not have null as the value of %s", k)
		}
	}
	var j allowedActionsSettingJSON
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&j); err != nil {
		return err
	}
	if j.SHAPinning == nil {
		return errors.New("a setting of allowed actions must have sha_pinning_required")
	}
	if j.Policy != AllowedActionsPolicySelected {
		if j.GitHubOwned != nil || j.Verified != nil || j.Patterns != nil {
			return fmt.Errorf("a setting of allowed actions must not have any of github_owned_allowed, verified_allowed and patterns_allowed when allowed_actions is %v", j.Policy)
		}
		v, err := NewAllowedActionsSetting(j.Policy, false, false, nil, *j.SHAPinning)
		if err != nil {
			return err
		}
		*s = v
		return nil
	}
	if j.GitHubOwned == nil || j.Verified == nil || j.Patterns == nil {
		return errors.New("a setting of allowed actions must have github_owned_allowed, verified_allowed and patterns_allowed when allowed_actions is selected")
	}
	patterns := *j.Patterns
	if patterns == nil {
		patterns = []AllowedActionsPattern{}
	}
	v, err := NewAllowedActionsSetting(j.Policy, *j.GitHubOwned, *j.Verified, patterns, *j.SHAPinning)
	if err != nil {
		return err
	}
	*s = v
	return nil
}
