// Writes "<vector> <score>" for every vector cvss4.ParseVector takes, in
// the order of TestAll (score_test.go): the Base metrics from AV to SA,
// each in the order of its values, then E: none, A, P, U.
const {score} = require('./load.js');
const metrics = [['AV', 'NALP'], ['AC', 'LH'], ['AT', 'NP'], ['PR', 'NLH'], ['UI', 'NPA'],
  ['VC', 'HLN'], ['VI', 'HLN'], ['VA', 'HLN'], ['SC', 'HLN'], ['SI', 'HLN'], ['SA', 'HLN']];
let out = [];
function walk(i, prefix) {
  if (i === metrics.length) {
    for (const e of ['', '/E:A', '/E:P', '/E:U']) out.push(prefix + e + ' ' + score(prefix + e).toFixed(1) + '\n');
    if (out.length >= 4096) { process.stdout.write(out.join('')); out = []; }
    return;
  }
  for (const v of metrics[i][1]) walk(i + 1, prefix + '/' + metrics[i][0] + ':' + v);
}
walk(0, 'CVSS:4.0');
process.stdout.write(out.join(''));
