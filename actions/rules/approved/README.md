# Approved documents

Each directory here is a rule's review documents as a person approved
them: `meta.md`, the rule without its examples, and `<what>/<id>.md`, each
of its examples. A rule is reviewed when every document here is what
`rules.ReviewDocuments` writes now, and none is left over.

Only a review batch (`go run ./actions/internal/reviewpr`), merged by the
person who read it, writes them. `go test -update` does not.
