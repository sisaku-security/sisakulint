package core

func ArgumentInjectionCriticalRule(wfTaintMap *WorkflowTaintMap) *ArgumentInjectionRule {
	return newArgumentInjectionRule("critical", true, wfTaintMap)
}
