# pkg/expressions

- When changing the untrusted-input tree (anti_untrustedmap.go), verify the change reaches both BuiltinUntrustedInputs and the copy produced by CreateUntrustedInputsWithTaintedReusableWorkflowInputs (the reusable-workflow path goes through the latter).
- When adding a node, Children == nil makes it a leaf (always reported on its own) while non-nil makes it intermediate (reported only inside function arguments such as toJSON). The choice changes the detection condition itself, so pick leaf vs intermediate deliberately.
- The error message wording "potentially untrusted" in anti_untrustedchecker.go is string-matched by pkg/core/taint.go (mid-migration to IsUntrustedInput). Changing the wording silently breaks taint detection; migrate that caller first.
- Untrusted detection is active only when NewExprSemanticsChecker is constructed with checkUntrustedInput=true. A caller in pkg/core that forgets the flag gets no error — detection just silently disappears.
