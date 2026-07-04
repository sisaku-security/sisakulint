# pkg/remote

- getToken in fetcher.go is the legacy path that probes gh auth token / git credential fill. It deliberately coexists with ResolveGitHubToken in pkg/core/github_token.go (probing removed there by #484). Check both paths when changing auth behavior. NewFetcher returns an anonymous client when no token is found (it does not error).
- Failure and rate-limit policy differs per layer: the Scanner logs a warning and continues, the resolver (pkg/core/metadata.go) returns the error immediately (no caching, no retry), and autofix aborts or skips the write. There is no single global policy — match the policy of the call site you are changing.
