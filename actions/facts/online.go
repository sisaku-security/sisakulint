package facts

// OnlineAnswer is how the GitHub API source (package github, which
// --online adds) answers the facts of a kind.
type OnlineAnswer uint8

const (
	// OnlineNone: the source asks the API nothing about the kind.
	OnlineNone OnlineAnswer = iota
	// OnlineAll: the source asks the API about every fact of the kind.
	OnlineAll
	// OnlineNamedRepository: the source asks only about a fact that names
	// a repository (repo, given by --repo), not about one of the
	// repository of the inputs without a name.
	OnlineNamedRepository
	// OnlineNamedRepositoryFalse: as OnlineNamedRepository, and the source
	// answers only when the answer is false (repo.wiki-open).
	OnlineNamedRepositoryFalse
)

var onlineAnswerNames = [...]string{"none", "all", "named-repository", "named-repository-false"}

func (a OnlineAnswer) String() string { return onlineAnswerNames[a] }

// OnlineAnswerOf is how the GitHub API source answers the facts of the
// kind k. It is the one list of those kinds: a test of package github
// checks it against what the source asks.
func OnlineAnswerOf(k Kind) OnlineAnswer {
	switch k {
	case KindGitRefCommit, KindGitCommitRef, KindGitCommitContains, KindGitCommitTags, KindPackageAdvisories,
		KindRepoArchived, KindActionRunsUsing, KindActionDefinition, KindWorkflowDefinition:
		return OnlineAll
	case KindRepoPublic, KindRepoDefaultTokenWrite, KindRepoEnvironmentProtected, KindRepoAllowForking, KindRepoAllowedActions,
		KindRepoForkPRRunWorkflows, KindRepoForkPRWriteTokens, KindRepoForkPRSecrets,
		KindRepoConfigurationVariables, KindRepoEnvironmentConfigurationVariables:
		return OnlineNamedRepository
	case KindRepoWikiOpen:
		return OnlineNamedRepositoryFalse
	}
	return OnlineNone
}
