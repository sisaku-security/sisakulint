package analysis

import "strings"

// Barrier is what keeps an attacker out of a run or of what a job does in
// it: an approval (a label, the required reviewers of an environment),
// the gate of an agent action, an if that compares author_association or
// the actor with names, and a context whose values the analysis reads as
// no attacker's (vars, secrets). A run that adds an attacker (lint's
// AddedAttacker) lets that attacker past some of them (BarrierPasses).
type Barrier uint8

const (
	BarrierUnset                   Barrier = iota
	BarrierAssociationOwner                // author_association is OWNER
	BarrierAssociationMember               // author_association is MEMBER
	BarrierAssociationCollaborator         // author_association is COLLABORATOR
	BarrierActorName                       // the actor may be any name the workflow writes, with [bot] or not
	BarrierLabelApproval                   // the approval by a label (ApprovalLabel): the attacker adds a label the repository has
	BarrierEnvironmentApproval             // the approval by the required reviewers of an environment (ApprovalEnvironment)
	BarrierAgentGate                       // the gate of an agent action left closed: it lets the actor start the agent
	BarrierVariableValue                   // the values of vars are the attacker's
	BarrierSecretValue                     // the values of secrets but GITHUB_TOKEN are the attacker's
)

var barrierNames = [...]string{"BarrierUnset", "association-owner", "association-member", "association-collaborator", "actor-name", "label-approval", "environment-approval", "agent-gate", "variable-value", "secret-value"}

func (g Barrier) String() string { return barrierNames[g] }

// Barriers are the barriers, in their order.
func Barriers() []Barrier {
	out := make([]Barrier, 0, len(barrierNames)-1)
	for g := BarrierUnset + 1; int(g) < len(barrierNames); g++ {
		out = append(out, g)
	}
	return out
}

// WrittenObject is what an attacker writes that starts a run, or that a
// run is of: an issue, a comment on an issue or on a pull request, a pull
// request, a review of a pull request (and a comment of a review), a
// discussion (and a comment on one). A credential of an added attacker may
// write only some (a token whose only write access is the Issues
// permission writes no comment on a pull request).
type WrittenObject uint8

const (
	WrittenUnset              WrittenObject = iota
	WrittenIssue                            // open or edit an issue
	WrittenIssueComment                     // a comment on an issue
	WrittenPullRequest                      // open or edit a pull request
	WrittenPullRequestComment               // a comment on a pull request (issue_comment)
	WrittenPullRequestReview                // a review of a pull request, or a comment of a review
	WrittenDiscussion                       // open a discussion, or comment on one
)

var writtenObjectNames = [...]string{"WrittenUnset", "issue", "issue-comment", "pull-request", "pull-request-comment", "pull-request-review", "discussion"}

func (o WrittenObject) String() string { return writtenObjectNames[o] }

// WrittenObjects are the objects, in their order.
func WrittenObjects() []WrittenObject {
	out := make([]WrittenObject, 0, len(writtenObjectNames)-1)
	for o := WrittenUnset + 1; int(o) < len(writtenObjectNames); o++ {
		out = append(out, o)
	}
	return out
}

// BarrierPasses are the barriers the attacker of a run gets past, and,
// when the attacker is limited to a credential that writes only some
// objects, those objects. The zero BarrierPasses passes no barrier and
// writes every object: the attacker of a run that adds none.
type BarrierPasses struct {
	set     uint16
	limited bool  // the attacker writes only written
	written uint8 // the objects, by bit
}

// Passes is whether the attacker gets past g.
func (p BarrierPasses) Passes(g Barrier) bool { return p.set&(1<<g) != 0 }

// With is p, which passes gs too.
func (p BarrierPasses) With(gs ...Barrier) BarrierPasses {
	for _, g := range gs {
		p.set |= 1 << g
	}
	return p
}

// Union is what p or q passes, and writes.
func (p BarrierPasses) Union(q BarrierPasses) BarrierPasses {
	u := BarrierPasses{set: p.set | q.set}
	if p.limited && q.limited {
		u.limited, u.written = true, p.written|q.written
	}
	return u
}

// Limited is p, whose attacker writes only os.
func (p BarrierPasses) Limited(os ...WrittenObject) BarrierPasses {
	p.limited, p.written = true, 0
	for _, o := range os {
		p.written |= 1 << o
	}
	return p
}

// Writes is whether the attacker writes o.
func (p BarrierPasses) Writes(o WrittenObject) bool { return !p.limited || p.written&(1<<o) != 0 }

// IsZero is whether p passes no barrier and writes every object: the
// attacker of a run that adds none.
func (p BarrierPasses) IsZero() bool { return p.set == 0 && !p.limited }

// String is the names of the barriers p passes, in their order, joined by
// commas.
func (p BarrierPasses) String() string {
	var names []string
	for _, g := range Barriers() {
		if p.Passes(g) {
			names = append(names, g.String())
		}
	}
	if p.limited {
		var ws []string
		for _, o := range WrittenObjects() {
			if p.Writes(o) {
				ws = append(ws, o.String())
			}
		}
		names = append(names, "writes "+strings.Join(ws, "+"))
	}
	return strings.Join(names, ",")
}
