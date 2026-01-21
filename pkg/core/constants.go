package core

// String constants for expression types
const (
	// Expression checker constants
	ExprNullValue  = "null"
	ExprTrueValue  = "true"
	ExprFalseValue = "false"

	// Parse SBOM constants
	SBOMDescription = "description"
	SBOMRequired    = "required"
	SBOMString      = "string"
	SBOMNumber      = "number"
	SBOMBoolean     = "boolean"
	SBOMShell       = "shell"
	SBOMUses        = "uses"
	SBOMWith        = "with"
	SBOMRun         = "run"
	SBOMPath        = "path"

	// GitHub event constants
	EventPullRequest       = "pull_request"
	EventPullRequestTarget = "pull_request_target"
	EventTypeSynchronize   = "synchronize"
	EventTypeLabeled       = "labeled"
	EventCategory          = "event"
	EventCategoryPR        = "PULLREQUEST"

	// Parse sub constants
	SubWorkflowDispatch   = "workflow_dispatch"
	SubRepositoryDispatch = "repository_dispatch"
	SubSchedule           = "schedule"
	SubWorkflowCall       = "workflow_call"

	// Available constants
	AvailableEnv         = "env"
	AvailableConcurrency = "concurrency"

	// Parse main constants
	MainName = "name"

	// File action constants
	FileFixDryRun = "dry-run"

	// Parse SBOM tag constants
	SBOMNullTag  = "!!null"
	SBOMStrTag   = "!!str"
	SBOMIntTag   = "!!int"
	SBOMFloatTag = "!!float"

	// Workflow key path constants
	KeyPathJobOutputs                  = "jobs.<job_id>.outputs.<output_id>"
	KeyPathJobStepsContinueOnError     = "jobs.<job_id>.steps.continue-on-error"
	KeyPathJobStepsEnv                 = "jobs.<job_id>.steps.env"
	KeyPathJobStepsName                = "jobs.<job_id>.steps.name"
	KeyPathJobStepsRun                 = "jobs.<job_id>.steps.run"
	KeyPathJobStepsTimeoutMinutes      = "jobs.<job_id>.steps.timeout-minutes"
	KeyPathJobStepsWith                = "jobs.<job_id>.steps.with"
	KeyPathJobStepsWorkingDirectory    = "jobs.<job_id>.steps.working-directory"
	KeyPathJobContainerEnv             = "jobs.<job_id>.container.env.<env_id>"
	KeyPathJobServicesEnv              = "jobs.<job_id>.services.<service_id>.env.<env_id>"
	KeyPathJobEnvironmentURL           = "jobs.<job_id>.environment.url"
	KeyPathJobStepsIf                  = "jobs.<job_id>.steps.if"
	KeyPathJobContainerCredentials     = "jobs.<job_id>.container.credentials"
	KeyPathJobServicesCredentials      = "jobs.<job_id>.services.<service_id>.credentials"
	KeyPathJobDefaultsRun              = "jobs.<job_id>.defaults.run"
	KeyPathOnWorkflowCallOutputsValue  = "on.workflow_call.outputs.<output_id>.value"
	KeyPathJobEnv                      = "jobs.<job_id>.env"
	KeyPathJobSecrets                  = "jobs.<job_id>.secrets.<secrets_id>"
	KeyPathJobConcurrency              = "jobs.<job_id>.concurrency"
	KeyPathJobContainer                = "jobs.<job_id>.container"
	KeyPathJobContainerImage           = "jobs.<job_id>.container.image"
	KeyPathJobContinueOnError          = "jobs.<job_id>.continue-on-error"
	KeyPathJobEnvironment              = "jobs.<job_id>.environment"
	KeyPathJobName                     = "jobs.<job_id>.name"
	KeyPathJobRunsOn                   = "jobs.<job_id>.runs-on"
	KeyPathJobServices                 = "jobs.<job_id>.services"
	KeyPathJobTimeoutMinutes           = "jobs.<job_id>.timeout-minutes"
	KeyPathJobWith                     = "jobs.<job_id>.with.<with_id>"
	KeyPathJobStrategy                 = "jobs.<job_id>.strategy"
	KeyPathJobIf                       = "jobs.<job_id>.if"
	KeyPathOnWorkflowCallInputsDefault = "on.workflow_call.inputs.<inputs_id>.default"
	KeyPathRunName                     = "run-name"

	// Context name constants for workflow key availability
	ContextEnv      = "env"
	ContextGithub   = "github"
	ContextInputs   = "inputs"
	ContextJob      = "job"
	ContextJobs     = "jobs"
	ContextMatrix   = "matrix"
	ContextNeeds    = "needs"
	ContextRunner   = "runner"
	ContextSecrets  = "secrets"
	ContextSteps    = "steps"
	ContextStrategy = "strategy"
	ContextVars     = "vars"

	// Special function name constants for workflow key availability
	FunctionAlways    = "always"
	FunctionCanceled  = "canceled"
	FunctionCancelled = "canceled" // British English alias for canceled
	FunctionFailure   = "failure"
	FunctionHashFiles = "hashfiles"
	FunctionSuccess   = "success"
)
