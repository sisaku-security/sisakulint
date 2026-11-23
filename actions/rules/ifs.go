package rules

import "github.com/sisaku-security/sisakulint/actions/lint"

// The forms of an if that the attacker run reads as keeping an attacker
// out, which those it does not count as attackers pass: the rules whose
// events an if filters (the injection rules, the checkout rules,
// dangerous-triggers, artifact-poisoning) declare them.
var (
	insiderAssociationLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("insider-association"),
		Text:        "an if that lets in MEMBER or COLLABORATOR by the author_association of the issue, the pull request or the discussion the run is of, which the following pass: a member or a collaborator whose repository role is Read only, who gets, in the run, a token that writes and the secrets, more than what the Read role gives; the account of such a member or collaborator, taken over; and an outsider who becomes a MEMBER with the Read role, in an organization that lets anyone become a member (a bot that invites whoever asks). A member or a collaborator whose role is Triage or above holds a credential that can add a label or write to the repository, which the credential premise assumes no attacker holds. Who is a member, and with what role, is not in the workflow",
		Disposition: lint.Todo(lint.NeedFact)}
)

// ifLimits are the forms, for the UndetectedForms of those rules.
var ifLimits = []lint.UndetectedForm{insiderAssociationLimit}
