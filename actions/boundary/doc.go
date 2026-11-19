// Package boundary holds, as tables with their grounds, what GitHub gives
// a run of each event, what one of each role in the repository holds
// before any flaw of a workflow, which roles can write what an attacker
// writes (Channel), and which roles get at what a run holds with no event
// (Pathway); and works out from them, for an Actor of a rule, what
// it gains of each Gain beyond what the attacker held (the Crossing).
//
// Each row holds its own grounds: words of GitHub's documents or data at a
// pinned commit (Quote), what was seen on GitHub (lint.Observation), or what is
// not known. A row is checked when the tables are made.
//
// Where things are:
//
//	enum.go       Role, PRHead, Access, SecretsAccess, Basis, Crossing,
//	              Holding
//	row.go        Quote and its JSONPointer, RunRef, RunGrant, RoleBaseline,
//	              Channel, Pathway, and the check of a row
//	grants.go     the RunGrant rows
//	baselines.go  the RoleBaseline, Channel and Pathway rows
//	observed.go   the observations of 2026-10-30 that the rows of
//	              grants.go and baselines.go hold, and the uncertainty of
//	              the rows of wiki-editor of the roles read and triage
//	tables.go     the rows, checked once; Grants, Baselines, Channels,
//	              Pathways, BarrierRows
//	cross.go      what a run and a role hold, by Holding, whether a
//	              Channel is writable or a Pathway usable, the Crossing of
//	              a Gain, and the facts each reads
//	barriers.go   BarrierPass: which barriers an attacker that a run adds
//	              (lint's AddedAttacker) gets past, and BarrierPassesOf
//	groups.go     the runs put together where they hold alike what the
//	              gains of an actor need
package boundary
