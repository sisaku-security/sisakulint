package core

// WorkflowKeyAvailability は、指定されたワークフローキーのコンテキストと特別な関数の可用性を返します。
// 最初の戻り値は、どのようなコンテキストが利用可能であるかを示します。 空のスライスは、任意のコンテキストが使用可能であることを意味します。
// 2番目の戻り値は、どのような特別な関数が使用できるかを示します。 空のスライスは、特別な機能が使用できないことを意味します。
// 'key' パラメータは、jobs.<job_id>.concurrencyのようなワークフローキーを表す必要があります。
//
// * https://docs.github.com/en/actions/learn-github-actions/contexts#context-availability.
func WorkflowKeyAvailability(key string) ([]string, []string) {
	switch key {
	case KeyPathJobOutputs:
		return []string{ContextEnv, ContextGithub, ContextInputs, ContextJob, ContextMatrix, ContextNeeds, ContextRunner, ContextSecrets, ContextSteps, ContextStrategy, ContextVars}, []string{}
	case KeyPathJobStepsContinueOnError, KeyPathJobStepsEnv, KeyPathJobStepsName, KeyPathJobStepsRun, KeyPathJobStepsTimeoutMinutes, KeyPathJobStepsWith, KeyPathJobStepsWorkingDirectory:
		return []string{ContextEnv, ContextGithub, ContextInputs, ContextJob, ContextMatrix, ContextNeeds, ContextRunner, ContextSecrets, ContextSteps, ContextStrategy, ContextVars}, []string{FunctionHashFiles}
	case KeyPathJobContainerEnv, KeyPathJobServicesEnv:
		return []string{ContextEnv, ContextGithub, ContextInputs, ContextJob, ContextMatrix, ContextNeeds, ContextRunner, ContextSecrets, ContextStrategy, ContextVars}, []string{}
	case KeyPathJobEnvironmentURL:
		return []string{ContextEnv, ContextGithub, ContextInputs, ContextJob, ContextMatrix, ContextNeeds, ContextRunner, ContextSteps, ContextStrategy, ContextVars}, []string{}
	case KeyPathJobStepsIf:
		return []string{ContextEnv, ContextGithub, ContextInputs, ContextJob, ContextMatrix, ContextNeeds, ContextRunner, ContextSteps, ContextStrategy, ContextVars}, []string{FunctionAlways, FunctionCanceled, FunctionCancelled, FunctionFailure, FunctionHashFiles, FunctionSuccess}
	case KeyPathJobContainerCredentials, KeyPathJobServicesCredentials:
		return []string{ContextEnv, ContextGithub, ContextInputs, ContextMatrix, ContextNeeds, ContextSecrets, ContextStrategy, ContextVars}, []string{}
	case KeyPathJobDefaultsRun:
		return []string{ContextEnv, ContextGithub, ContextInputs, ContextMatrix, ContextNeeds, ContextStrategy, ContextVars}, []string{}
	case KeyPathOnWorkflowCallOutputsValue:
		return []string{ContextGithub, ContextInputs, ContextJobs, ContextVars}, []string{}
	case KeyPathJobEnv, KeyPathJobSecrets:
		return []string{ContextGithub, ContextInputs, ContextMatrix, ContextNeeds, ContextSecrets, ContextStrategy, ContextVars}, []string{}
	case KeyPathJobConcurrency, KeyPathJobContainer, KeyPathJobContainerImage, KeyPathJobContinueOnError, KeyPathJobEnvironment, KeyPathJobName, KeyPathJobRunsOn, KeyPathJobServices, KeyPathJobTimeoutMinutes, KeyPathJobWith:
		return []string{ContextGithub, ContextInputs, ContextMatrix, ContextNeeds, ContextStrategy, ContextVars}, []string{}
	case KeyPathJobStrategy:
		return []string{ContextGithub, ContextInputs, ContextNeeds, ContextVars}, []string{}
	case KeyPathJobIf:
		return []string{ContextGithub, ContextInputs, ContextNeeds, ContextVars}, []string{FunctionAlways, FunctionCanceled, FunctionCancelled, FunctionFailure, FunctionSuccess}
	case AvailableEnv:
		return []string{ContextGithub, ContextInputs, ContextSecrets, ContextVars}, []string{}
	case AvailableConcurrency, KeyPathOnWorkflowCallInputsDefault, KeyPathRunName:
		return []string{ContextGithub, ContextInputs, ContextVars}, []string{}
	default:
		return nil, nil
	}
}
