// Package repofile answers the kinds of facts whose provider is repo-file:
// what files of the repository that are not inputs say. It reads them from
// an fs.FS, the root of the run (--root):
//
//   - dependabot.version-updates, from .github/dependabot.yml or
//     .github/dependabot.yaml (dependabot.go);
//   - renovate.manager-enabled, from the first configuration file of
//     Renovate (renovate.go).
//
// Each answer has the Source repo-file. What the files cannot tell (a glob
// whose meaning for the ecosystem is not known, a preset from outside the
// repository) is unknown, with the reason. The package reads YAML, which
// actions/facts does not, and holds no token.
//
// Where things are:
//
//	resolver.go    New, the Resolver
//	dependabot.go  dependabot.version-updates
//	renovate.go    renovate.manager-enabled, and the presets of Renovate it knows
//	jsonc.go       JSON with comments and trailing commas, as Renovate reads it
//	glob.go        the paths of ignorePaths and of the patterns of the managers
package repofile
