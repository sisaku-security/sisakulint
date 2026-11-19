// Writes the tables of the calculator as JSON, for TestTables.
const {lookup, maxComposed, maxSeverity} = require('./load.js');
process.stdout.write(JSON.stringify({lookup, maxComposed, maxSeverity}, null, 1) + '\n');
