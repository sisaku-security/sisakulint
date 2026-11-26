# Cases of minimatch

`cases.json` holds the cases that `TestMinimatchFixtures` and `TestExpandBraces` (`../../minimatch_test.go`) compare `matchArtifactName` and `expandBraces` with. `gen.mjs` takes them out of the tests of minimatch (https://github.com/isaacs/minimatch), at two releases:

- v10.2.4, commit `c36addb94e33f14254b9ca9017e63ae9c9d80d1d` (actions/upload-artifact v7, whose `merge` reads the pattern). License: Blue Oak Model License 1.0.0, copied to `LICENSE-v10.2.4.md`.
- v9.0.3, commit `f8b46a317a7695c342402cde52c8b0f7a47add17` (actions/upload-artifact v4 and actions/download-artifact v4). License: ISC, copied to `LICENSE-v9.0.3`.

To make `cases.json` again, check out the two tags and run, with Node.js:

```
node gen.mjs <minimatch at v10.2.4>/test <minimatch at v9.0.3>/test > cases.json
```

`gen.mjs` imports `patterns.js` (which only builds its list) and reads the other test files as text. It writes the counts below to stderr.

## What is taken

A case is a pattern, a name, the match that each release's test expects, and `known`: whether `matchArtifactName` is to read the pattern. Only cases that a name of an artifact can meet are taken: the options are the defaults (the actions give none), and the name has no `/`. 1451 cases in all, 167 of which have a `/` in the pattern only; the two releases expect the same match for every case that both have.

| file | cases | not known | dropped, and why |
|---|---|---|---|
| `patterns.js` | 925 | 85 | the entries with an option other than `nonull` (794 checks of a file over the two releases), the files with a `/` (610), and, of an entry with `nonull`, the file that is the pattern itself |
| `escaping.js` | 444 | 0 | `/` and `\`, which the file leaves out |
| `tricky-negations.js` | 42 | 16 | the patterns that start with `!`: the file runs with `nonegate`, which changes only how a leading `!` is read |
| `extglob-unfinished.js` | 8 | 0 | the type `!`, for the same reason |
| `usurp.ts` (v10.2.4 only) | 8 | 6 | the same |
| `extglob-ending-with-state-char.js` | 2 | 0 | — |
| runs of the actions (`probe`) | 14 | 0 | — |
| from the source (`derived`) | 8 | 0 | — |

The runs of the actions are those of one run on a GitHub-hosted runner on 2026-11-26: `actions/upload-artifact/merge` v4 and v7 and `actions/download-artifact` v4, with the artifacts `part-1` and `x` in the run.

The cases from the source are forms that the tests do not have, whose match follows from `src/index.ts` and `src/ast.ts` of both releases: the quick tests of `parse` (`starDotExtTest`, `qmarksTestNoExt`), which compare the rest of the part as written, `\` included; an escaped `|`, which stays a `|` of the regular expression `^...$` and so binds `^` to the first alternative and `$` to the last; and `*` with a name that starts with `.` (the default pattern of `actions/upload-artifact/merge`).

A pattern is not known (`matchArtifactName` returns `known` false) when the rule does not read it:

- an extglob inside an extglob (10.2 parses extglobs only to a depth, `maxExtglobRecursion`, and flattens some nested ones);
- a `*` that has an extglob on one side and, on the other side, the start or the end of the part or another extglob, such as `@(foo)*` (9.0.3 reads that `*` as one or more characters, 10.2 as any);
- braces together with a `\` escape (the brace expansion that minimatch 10 bundles in the actions, brace-expansion 5.0.3 (in actions/upload-artifact v7) and @isaacs/brace-expansion 5.0.0 (in actions/download-artifact v8), turns a `\` and the character after it into `.`), and braces that expand to more than 100000 names (`EXPANSION_MAX` of brace-expansion 5);
- a POSIX class such as `[:alpha:]` in `[...]`, which both releases turn into a regular expression with the `u` flag (in the run above, `part-[[:digit:]]` failed the step of both actions, as `\-` is an error in that flag);
- a pattern whose match takes more steps than `matchBudget`.

The other tests of minimatch are not taken: `brace-expand.js` is taken into `braces` (11 patterns); `basic.js` runs `patterns.js`; `class-edge-cases.js` keeps its expectations in a snapshot; `negative-extglob-anchoring.js`, `win-path-sep.js`, `unc.ts`, `windows-no-magic-root.ts`, `consecutive-glob-stars.js`, `multiple-non-adjacent-globstars.ts`, `preserve-multiple-slashes.ts` and `partial` match paths with `/` or Windows paths; `defaults.js`, `nocase-magic.js`, `escape-has-magic.js` and `optimization-level-*.ts` test options, other functions or the regular expressions themselves; `nested-extglob.ts`, `redos.js` and `the-sky-is-full-of-stars-at-least-100.ts` test time.
