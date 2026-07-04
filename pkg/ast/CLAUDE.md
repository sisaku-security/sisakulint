# pkg/ast

- Adding a node type is not complete within this package: the matching constructor in pkg/core/parse_*.go must fill Pos, and the compiler does not check this coupling. String nodes must be built through newString in pkg/core, or the Quoted / Literal YAML style flags and BaseNode are lost and downstream rules misbehave.
- The position field on RawYAMLValue implementations is named Posi to avoid colliding with the interface's Pos() method (not a typo).
