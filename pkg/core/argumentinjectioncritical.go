package core

func ArgumentInjectionCriticalRule() *ArgumentInjectionRule {
	return newArgumentInjectionRule("critical", true)
}
