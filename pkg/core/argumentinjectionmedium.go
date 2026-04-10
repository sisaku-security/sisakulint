package core

func ArgumentInjectionMediumRule(wfTaintMap *WorkflowTaintMap) *ArgumentInjectionRule {
	return newArgumentInjectionRule("medium", false, wfTaintMap)
}
