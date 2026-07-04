# pkg/remote

- fetcher.go の getToken は gh auth token / git credential fill をプローブする旧経路で、pkg/core/github_token.go の ResolveGitHubToken (#484 でプローブ廃止) とは意図的に別物として併存中。認証挙動の変更は両経路を確認する。
- fetch 失敗・rate limit 時の方針はレイヤーごとに異なる: Scanner は Warning ログで続行、resolver (pkg/core/metadata.go) は即エラー返却 (キャッシュも retry もしない)、autofix は中断または書き込みスキップ。単一のグローバル方針は存在しないので、変更は呼び出し先の方針に合わせる。
