# pkg/remote

- getToken in fetcher.go is the legacy path that probes gh auth token and git credential fill. It deliberately coexists with ResolveGitHubToken in pkg/core/github_token.go, where probing was removed by #484. Check both paths when changing auth behavior. NewFetcher returns an anonymous client instead of erroring when no token is found.
- Failure and rate-limit policy differs per layer: the Scanner logs a warning and continues, the resolver in pkg/core/metadata.go returns the error immediately with no caching and no retry, and autofix aborts or skips the write. There is no single global policy — match the policy of the call site you are changing.
