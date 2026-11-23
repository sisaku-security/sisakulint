package boundary

import (
	"encoding/json"
	"fmt"
)

// Role is the attacker's role in the repository, as GitHub's repository
// roles name it, whatever gives it to them (an invitation, a team, the
// base permission of the organization).
type Role uint8

const (
	RoleUnset Role = iota
	RoleNone       // no access to the repository
	RoleRead
	RoleTriage
	RoleWrite
	RoleMaintain
	RoleAdmin
)

// PRHead is where the head of the pull request of an event is.
type PRHead uint8

const (
	PRHeadUnset      PRHead = iota
	PRHeadFork              // a fork of the repository
	PRHeadRepository        // a branch of the repository
	PRHeadNone              // the event is of no pull request
)

// Access is what the GITHUB_TOKEN of a run may do: the most of its
// scopes. It is the access of the permissions of a workflow (the glossary's
// access), as GitHub gives it to a run by default.
type Access uint8

const (
	AccessUnset Access = iota
	AccessNone
	AccessRead
	AccessWrite
)

// SecretsAccess is whether a run has the repository's secrets.
type SecretsAccess uint8

const (
	SecretsAccessUnset SecretsAccess = iota
	SecretsAccessNone
	SecretsAccessAll
)

// Basis is how sure a row is, the weakest first.
type Basis uint8

const (
	BasisUnset      Basis = iota
	BasisUnverified       // neither seen nor in GitHub's documents
	BasisDocumented       // in GitHub's documents
	BasisObserved         // seen on GitHub
)

// Crossing is what an Actor gains of one Gain beyond what the attacker
// held before any flaw of the workflow.
type Crossing uint8

const (
	CrossingUnset      Crossing = iota
	CrossingNone                // the run does not give it, and the attacker held it not
	CrossingByWorkflow          // the run gives it, and the attacker held it not
	CrossingByBaseline          // the attacker held it before any flaw of the workflow
	CrossingUnknown             // a fact or a row that decides it is not known
)

// Holding is what a run holds that a Gain needs: code in a job gets the
// gain where its run holds it. The tables compare whether the run of the
// flaw holds it with whether one of a role holds it in a run of their own.
type Holding uint8

const (
	HoldingUnset                    Holding = iota
	HoldingSecrets                          // the repository's secrets
	HoldingWriteToken                       // a GITHUB_TOKEN that may write
	HoldingWriteTokenOrSecrets              // either of the two
	HoldingSelfHostedRunner                 // a self-hosted runner of the repository: of the run of the flaw, the premise of the rule that reads it, so it is whether the run runs
	HoldingWriteCache                       // a cache of the default branch's scope it may save to
	HoldingWriteTokenSecretsOrCache         // a GITHUB_TOKEN that may write, the secrets or the cache: what code in the job gets
)

var (
	roleNames     = []string{"", "none", "read", "triage", "write", "maintain", "admin"}
	prHeadNames   = []string{"", "fork", "repository", "none"}
	accessNames   = []string{"", "none", "read", "write"}
	secretsNames  = []string{"", "none", "all"}
	basisNames    = []string{"", "unverified", "documented", "observed"}
	crossingNames = []string{"", "none", "by-workflow", "by-baseline", "unknown"}
	holdingNames  = []string{"", "secrets", "write-token", "write-token-or-secrets", "self-hosted-runner", "write-cache", "write-token-secrets-or-cache"}
	holdingTexts  = []string{"", "the repository's secrets", "a GITHUB_TOKEN that may write", "a GITHUB_TOKEN that may write, or the repository's secrets", "a self-hosted runner of the repository", "a cache of the default branch's scope it may save to", "a GITHUB_TOKEN that may write, the repository's secrets, or a cache of the default branch's scope it may save to"}
	crossingTexts = []string{"",
		"the run does not hold what the gain needs, and one of this role holds it in no run of their own. It speaks of what code gets in the run only: it does not say there is no harm through an artifact that another run reads.",
		"the run holds what the gain needs, and one of this role holds it in no run of their own: fixing the workflow takes it away.",
		"one of this role holds what the gain needs in a run of their own, whatever the workflow: fixing the workflow does not take it away, a setting of the repository does. Write and above hold what they hold with no branch protection, ruleset or environment reviewers; where they are, it may be by-workflow.",
		"a fact or a row that decides it is not known.",
	}
)

func nameOf(names []string, v uint8, what string) string {
	if v == 0 || int(v) >= len(names) {
		return fmt.Sprintf("%s(%d)", what, v)
	}
	return names[v]
}

func marshalName(names []string, v uint8, what string) ([]byte, error) {
	if v == 0 || int(v) >= len(names) {
		return nil, fmt.Errorf("%s(%d) is not a value", what, v)
	}
	return json.Marshal(names[v])
}

func (v Role) String() string                 { return nameOf(roleNames, uint8(v), "Role") }
func (v Role) MarshalJSON() ([]byte, error)   { return marshalName(roleNames, uint8(v), "Role") }
func (v PRHead) String() string               { return nameOf(prHeadNames, uint8(v), "PRHead") }
func (v PRHead) MarshalJSON() ([]byte, error) { return marshalName(prHeadNames, uint8(v), "PRHead") }
func (v Access) String() string               { return nameOf(accessNames, uint8(v), "Access") }
func (v Access) MarshalJSON() ([]byte, error) { return marshalName(accessNames, uint8(v), "Access") }
func (v SecretsAccess) String() string        { return nameOf(secretsNames, uint8(v), "SecretsAccess") }
func (v SecretsAccess) MarshalJSON() ([]byte, error) {
	return marshalName(secretsNames, uint8(v), "SecretsAccess")
}
func (v Basis) String() string               { return nameOf(basisNames, uint8(v), "Basis") }
func (v Basis) MarshalJSON() ([]byte, error) { return marshalName(basisNames, uint8(v), "Basis") }
func (v Crossing) String() string            { return nameOf(crossingNames, uint8(v), "Crossing") }
func (v Crossing) MarshalJSON() ([]byte, error) {
	return marshalName(crossingNames, uint8(v), "Crossing")
}

func (v Holding) String() string               { return nameOf(holdingNames, uint8(v), "Holding") }
func (v Holding) MarshalJSON() ([]byte, error) { return marshalName(holdingNames, uint8(v), "Holding") }

// Text is what v is, for people; empty for a value that is not one.
func (v Holding) Text() string { return textOf(holdingTexts, uint8(v)) }

// Text is what v means and what to do of it, for people; empty for a
// value that is not one.
func (v Crossing) Text() string { return textOf(crossingTexts, uint8(v)) }

func textOf(texts []string, v uint8) string {
	if int(v) >= len(texts) {
		return ""
	}
	return texts[v]
}

// Roles are the roles, the least first.
func Roles() []Role {
	return []Role{RoleNone, RoleRead, RoleTriage, RoleWrite, RoleMaintain, RoleAdmin}
}

// PRHeads are the heads.
func PRHeads() []PRHead { return []PRHead{PRHeadFork, PRHeadRepository, PRHeadNone} }

// Holdings are the holdings.
func Holdings() []Holding {
	return []Holding{HoldingSecrets, HoldingWriteToken, HoldingWriteTokenOrSecrets, HoldingSelfHostedRunner, HoldingWriteCache, HoldingWriteTokenSecretsOrCache}
}

// Crossings are the crossings.
func Crossings() []Crossing {
	return []Crossing{CrossingNone, CrossingByWorkflow, CrossingByBaseline, CrossingUnknown}
}
