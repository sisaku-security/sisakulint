package ir

// Every type a reader reads summaries as is a Summary.
var (
	_ Summary = CommitSHAOfUses{}
	_ Summary = ImpostorCommitOfUses{}
	_ Summary = UntrustedCheckoutOfCheckoutSite{}
	_ Summary = UntrustedCheckoutToctouOfCheckoutSite{}
	_ Summary = CodeInjectionOfSink{}
	_ Summary = CodeInjectionOfStepFix{}
	_ Summary = FileCommandOfSink{}
	_ Summary = FileCommandOfStepFix{}
	_ Summary = ArtipackedOfUpload{}
	_ Summary = SecretsInArtifactsOfUpload{}
	_ Summary = DangerousTriggersOfJob{}
	_ Summary = SelfHostedRunnerOfJob{}
)
