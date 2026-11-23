// Loads the files of the reference calculator as they were fetched
// (testdata/reference), and gives its tables and its scoring.
const fs = require('fs'), vm = require('vm'), path = require('path');
for (const f of ['cvss_lookup.js', 'max_composed.js', 'max_severity.js', 'cvss_score.js']) {
  vm.runInThisContext(fs.readFileSync(path.join(__dirname, 'reference', f), 'utf8'), {filename: f});
}
// The calculator page selects every metric it does not show as X.
const notDefined = ['E', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA'];
function score(vector) {
  const sel = {};
  for (const m of notDefined) sel[m] = 'X';
  for (const p of vector.split('/').slice(1)) { const [k, v] = p.split(':'); sel[k] = v; }
  return cvss_score(sel, cvssLookup_global, maxSeverity, macroVector(sel));
}
module.exports = {score, lookup: cvssLookup_global, maxComposed, maxSeverity};
