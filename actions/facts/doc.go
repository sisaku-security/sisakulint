// Package facts is what a rule may know of the world outside a workflow:
// which commit a ref points to, whether a repository is public, and so on.
// A rule does not ask GitHub itself; it asks a Resolver about a Query and
// gets one of three answers: StateFound (with a value), StateAbsent
// (known not to exist) or StateUnknown (with a reason). Nothing that could
// not be found out reads as not being there, and nothing that no source
// answers is given a value: what no API tells (a setting of a repository)
// is Unknown unless a file of facts or an argument answers it. Each answer
// says where it comes from (Source: a file of facts, an argument, the
// GitHub API, or a file of the repository), and a report says so; a file
// of facts does not keep it.
//
// The kinds of facts are a closed set. schema/facts-v0.json (JSON Schema
// draft 2020-12) is where they are defined, for this package and for the
// systems that read what sisakulint writes; query_gen.go is made from
// it by go generate (internal/factsgen). The kinds of the domain test. are
// only for tests.
//
// This package does not depend on actions/workflow, actions/lint or yaml/.
// The code that holds a token is github/ (and actions/remote, which reads
// the repository of a run); both send through actions/internal/githubapi,
// and neither gives the token to a rule.
//
// Where things are:
//
//	facts.go      State, Source, Query, RawAnswer, Resolver, Answer, Kinds, DecodeQuery, EncodeQuery, QueryText, Checked
//	types.go      the arguments and values with a Go type of their own (each x-go-type),
//	              such as Repo, SHA, InputPath and Advisory, and VersionRange of an Advisory
//	actionpattern.go  ActionPattern, the value of repo.action-list, and ActionListAllows, how a
//	              list of patterns matches a uses
//	allowedactions.go  AllowedActionsSetting, the value of repo.allowed-actions (GitHub's
//	              setting of allowed actions), its AllowedActionsPolicy and AllowedActionsPattern,
//	              and Allows, how GitHub reads the setting for a uses
//	kind.go       Kind, Provider, Permission: what a kind is (the constants are in query_gen.go)
//	store.go      Store, LoadStore, Entry, EncodeFile: the file of facts
//	resolve.go    First, Recorder
//	arguments.go  Arguments: the facts given on the command line (--fact)
//	online.go     OnlineAnswer, OnlineAnswerOf: how the GitHub API source (package github)
//	              answers each kind
//	derive.go     what a file of facts answers from its other facts (git.commit-ref), and
//	              Store.AnsweredKinds and AnsweredKindsOf, the kinds a file and entries answer
//	query_gen.go  the kinds, made from schema/facts-v0.json
//	enum_gen.go   the values of State, Source, Provider, AdvisorySeverity, RunsUsing, PackageEcosystem, RenovateManager and AllowedActionsPolicy, made from schema/facts-v0.json by go
//	              generate (actions/internal/enumgen)
//	internal/factsgen  the program that makes query_gen.go
//	github/       the Resolver of the GitHub REST API (git.*, package.advisories, repo.* except repo.pull-request-target-allowed, repo.fork-pr-app-checks, repo.merge-commit-app-checks and repo.action-list, action.runs-using,
//	              action.definition, workflow.definition), where a token is
//
// The kinds of the provider repo-file (dependabot.version-updates,
// renovate.manager-enabled) are answered by package actions/repofile, out
// of this package: it reads YAML.
//
// Tests:
//
//	types_test.go    InputPath, PackageName, PackageVersion, GHSAID, Advisory, UsesPath
//	facts_test.go    Repo, SHA, the JSON of facts, the closed set, Ask, the dependencies
//	request_test.go  SecretName, ConfigurationVariableName and its answer in a file of facts,
//	                 RequestDestination, and the query of request.destination-trusted
//	actionpattern_test.go  ActionPattern, ActionListAllows, and repo.action-list in a file of facts
//	allowedactions_test.go  AllowedActionsPattern, AllowedActionsSetting and its JSON, Allows,
//	                 and repo.allowed-actions in a file of facts
//	steppath_parallel_test.go  StepPath of a step of a parallel group
//	kind_test.go     Kind, Provider, Permission
//	store_test.go    what a file of facts may hold, and how EncodeFile writes one
//	resolve_test.go  First, Recorder, and a file of facts that replays a run
//	arguments_test.go  Arguments
//	kindinfo_test.go  the x-assume values, KindInfo and the queries of the kinds that no API
//	                 answers or that --online does not ask
//	derive_test.go   RefName, git.commit-ref derived by a file of facts, and the kinds a file answers
//	source_test.go   where each answer comes from, kept through First and a Recorder
//	enum_test.go     every value of State and Provider; a file of facts of every state
//	internal/factsgen  query_gen.go is up to date; what the generator rejects
package facts
