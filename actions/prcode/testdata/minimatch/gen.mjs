// Writes cases.json from the test fixtures of two releases of minimatch.
//
//	node gen.mjs <minimatch v10.2.4 test dir> <minimatch v9.0.3 test dir> > cases.json
//
// Each test dir is the test directory of a checkout of
// https://github.com/isaacs/minimatch at the tag. The fixtures are read as
// data: patterns.js is imported (it only builds its list), the other files
// are read as text and their cases taken out with the expressions below.
// Only cases that a name of an artifact can meet are kept: the options are
// the defaults (as actions/upload-artifact/merge and
// actions/download-artifact give none), and the name has no /. The counts
// of the cases kept and dropped, and why, go to stderr.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const releases = [
  ['v10.2.4', process.argv[2]],
  ['v9.0.3', process.argv[3]],
]

const counts = {}
function count(source, what) {
  counts[source] ??= {}
  counts[source][what] = (counts[source][what] ?? 0) + 1
}

// nested is whether p has an extglob inside an extglob; posix whether it
// has a POSIX class ([:alpha:] inside [...]). Both are read differently by
// the releases (an extglob deeper than maxExtglobRecursion is not parsed by
// 10.2; a POSIX class makes 9.0.3 build a regular expression with the u
// flag, which other escapes of the pattern break).
function nested(p) {
  let depth = 0
  for (let i = 0; i < p.length; i++) {
    const c = p[i]
    if (c === '\\') {
      i++
      continue
    }
    if ('@!?+*'.includes(c) && p[i + 1] === '(') {
      if (depth > 0) return true
      depth++
      i++
      continue
    }
    if (c === ')' && depth > 0) depth--
  }
  return false
}
// starBesideExtglob is whether a part between / has an extglob and, beside
// it, a part of only *: 9.0.3 reads that * as one or more characters,
// 10.2 as any (@(foo)* matches foo only in 10.2).
function starBesideExtglob(p) {
  for (const part of p.split('/')) {
    let depth = 0
    let chunk = ''
    let ext = false
    const chunks = []
    for (let i = 0; i < part.length; i++) {
      const c = part[i]
      if (c === '\\') {
        if (depth === 0) chunk += c + (part[i + 1] ?? '')
        i++
        continue
      }
      if ('@!?+*'.includes(c) && part[i + 1] === '(') {
        if (depth === 0) {
          chunks.push(chunk)
          chunk = ''
          ext = true
        }
        depth++
        i++
        continue
      }
      if (c === ')' && depth > 0) {
        depth--
        continue
      }
      if (depth === 0) chunk += c
    }
    chunks.push(chunk)
    if (ext && chunks.includes('*')) return true
  }
  return false
}
function posix(p) {
  return /\[[^\]]*\[:[a-z]+:\]/.test(p)
}

const cases = new Map() // key: pattern \0 name, value: case
function add(version, source, pattern, name, match) {
  if (name.includes('/')) {
    count(source, 'dropped: the name has a /')
    return
  }
  count(source, 'kept')
  const key = pattern + '\0' + name
  let c = cases.get(key)
  if (!c) {
    // minimatch takes the leading ! (and a # comment) before it reads the rest
    const body = pattern.startsWith('#') ? '' : pattern.replace(/^!+/, '')
    c = { source, pattern, name, versions: {}, known: !nested(body) && !posix(body) && !starBesideExtglob(body) }
    cases.set(key, c)
  }
  c.versions[version] = match
}

const braces = new Map()

for (const [version, dir] of releases) {
  // patterns.js: [pattern, matches, options, files]; a function changes
  // the files of the entries after it.
  const patterns = (await import(pathToFileURL(join(dir, 'patterns.js')).href)).default
  for (const c of patterns) {
    if (typeof c === 'function') {
      c()
      continue
    }
    if (typeof c === 'string') continue
    const [pattern, matches, options, files] = c
    const opts = Object.keys(options ?? {}).filter(k => options[k])
    const list = files ?? patterns.files
    if (opts.some(k => k !== 'nonull')) {
      for (const _ of list) count('patterns.js', 'dropped: options other than nonull')
      continue
    }
    for (const f of list) {
      if (opts.includes('nonull') && matches.length === 1 && matches[0] === pattern && f === pattern) {
        count('patterns.js', 'dropped: nonull puts the pattern in the matches')
        continue
      }
      add(version, 'patterns.js', pattern, f, matches.includes(f))
    }
  }

  // tricky-negations.js runs with nonegate, which changes only a leading !.
  const tricky = readFileSync(join(dir, 'tricky-negations.js'), 'utf8')
  const obj = new Function('return ' + tricky.match(/var cases = (\{[\s\S]*?\n\})\n/)[1])()
  for (const [file, ps] of Object.entries(obj)) {
    for (const [p, want] of Object.entries(ps)) {
      if (p.startsWith('!')) {
        count('tricky-negations.js', 'dropped: a leading ! that nonegate keeps')
        continue
      }
      add(version, 'tricky-negations.js', p, file, want)
    }
  }

  // extglob-ending-with-state-char.js: t.ok / t.notOk(minimatch(file, pattern)).
  const ending = readFileSync(join(dir, 'extglob-ending-with-state-char.js'), 'utf8')
  for (const m of ending.matchAll(/t\.(ok|notOk)\(minimatch\('([^']*)', '([^']*)'\)\)/g)) {
    add(version, 'extglob-ending-with-state-char.js', m[3], m[2], m[1] === 'ok')
  }

  // extglob-unfinished.js: for each type, mm(type+'(a|B', type+'(a|B') is
  // true and mm(type+'(a|B', 'B') false, with nonegate; the cases are
  // built here as the file builds them.
  const unfinished = readFileSync(join(dir, 'extglob-unfinished.js'), 'utf8')
  const types = unfinished.match(/var types = '([^']*)'\.split/)[1].split('')
  for (const ty of types) {
    const p = ty + '(a|B'
    if (ty === '!') {
      count('extglob-unfinished.js', 'dropped: a leading ! that nonegate keeps')
      count('extglob-unfinished.js', 'dropped: a leading ! that nonegate keeps')
      continue
    }
    add(version, 'extglob-unfinished.js', p, p, true)
    add(version, 'extglob-unfinished.js', p, 'B', false)
  }

  // escaping.js: for each character from mincc to maxcc but the
  // exceptions, pre+c+post matches '*\\'+c+'*' and '*[\\'+c+']*'; the cases
  // are built here as the file builds them, from its constants.
  const esc = readFileSync(join(dir, 'escaping.js'), 'utf8')
  const mincc = Number(esc.match(/var mincc = (0x[0-9a-f]+)/)[1])
  const maxcc = Number(esc.match(/var maxcc = (0x[0-9a-f]+)/)[1])
  const exceptions = new Function('return ' + esc.match(/var exceptions = (\[[^\]]*\])/)[1])()
  const pre = esc.match(/var pre = '([^']*)'/)[1]
  const post = esc.match(/var post = '([^']*)'/)[1]
  for (let cc = mincc; cc <= maxcc; ++cc) {
    const cp = String.fromCharCode(cc)
    if (exceptions.includes(cp)) continue
    add(version, 'escaping.js', '*\\' + cp + '*', pre + cp + post, true)
    add(version, 'escaping.js', '*[\\' + cp + ']*', pre + cp + post, true)
  }

  // brace-expand.js: [pattern, [expanded]].
  const be = readFileSync(join(dir, 'brace-expand.js'), 'utf8')
  const list = new Function('return ' + be.match(/(?:const|var) patterns = (\[[\s\S]*?\n  \])\n/)[1])()
  for (const [p, expanded] of list) {
    const b = braces.get(p) ?? { pattern: p, versions: {} }
    b.versions[version] = expanded
    braces.set(p, b)
  }
}

// usurp.ts (10.2 only) runs with nonegate: t.equal(minimatch(file, pattern, o), bool).
const usurp = readFileSync(join(releases[0][1], 'usurp.ts'), 'utf8')
for (const m of usurp.matchAll(/t\.equal\(minimatch\('([^']*)', '([^']*)', o\), (true|false)\)/g)) {
  if (m[2].startsWith('!')) {
    count('usurp.ts', 'dropped: a leading ! that nonegate keeps')
    continue
  }
  add('v10.2.4', 'usurp.ts', m[2], m[1], m[3] === 'true')
}

// The runs of actions/upload-artifact/merge and actions/download-artifact
// v4 (minimatch 9.0.3) and merge v7 (10.2.4) in the run 45824870034 of
// https://github.com/gh-intel/workflow-probe (branch
// probe/artifact-called-workflow), with the artifacts part-1 and x.
const probe = [
  ['part-@(x|y)', 'part-1', false, ['v10.2.4', 'v9.0.3']],
  ['part-@(1|2)', 'part-1', true, ['v10.2.4', 'v9.0.3']],
  ['part-+(x)', 'part-1', false, ['v9.0.3']],
  ['part-!(1)', 'part-1', false, ['v9.0.3']],
  ['#part-1', 'part-1', false, ['v9.0.3']],
  ['part-{1..3}', 'part-1', true, ['v9.0.3']],
  ['part-*', 'part-1', true, ['v9.0.3']],
  ['part-[!x]*', 'part-1', true, ['v9.0.3']],
  ['!other-*', 'part-1', true, ['v9.0.3']],
  ['!other-*', 'x', true, ['v9.0.3']],
  ['!(x)*', 'part-1', true, ['v9.0.3']],
  ['!(x)*', 'x', true, ['v9.0.3']],
  ['other-{a,b}', 'part-1', false, ['v9.0.3']],
  ['other-{a,b}', 'x', false, ['v9.0.3']],
]
for (const [p, name, match, versions] of probe) {
  for (const v of versions) add(v, 'probe', p, name, match)
}

const out = {
  match: [...cases.values()].sort((a, b) => (a.pattern + '\0' + a.name < b.pattern + '\0' + b.name ? -1 : 1)),
  braces: [...braces.values()],
}
process.stdout.write(JSON.stringify(out, null, 1) + '\n')

let differ = 0
for (const c of cases.values()) {
  const vs = Object.values(c.versions)
  if (vs.length === 2 && vs[0] !== vs[1]) {
    differ++
    console.error(`differ: ${JSON.stringify(c.pattern)} ${JSON.stringify(c.name)} ${JSON.stringify(c.versions)} known=${c.known}`)
  }
}
console.error(JSON.stringify({ counts, unique: cases.size, differ, braces: braces.size }, null, 1))
