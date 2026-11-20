// Package cvss4 scores CVSS v4.0 vectors as the reference calculator of
// FIRST does (https://github.com/FIRSTdotorg/cvss-v4-calculator at
// c5b0d409ae9f57c44264c6ce5f27d89298e1d32a), to which the specification
// leaves the scores of its MacroVectors
// (https://www.first.org/cvss/v4.0/specification-document, section 8).
// It reads the eleven Base metrics and Exploit Maturity (E) only: a score
// of them is CVSS-B without E, CVSS-BT with it.
//
// Where things are:
//
//	vector.go  Vector, ParseVector: the metrics it reads, and what the calculator
//	           takes for those it does not (E:X is A, CR, IR and AR are H)
//	score.go   Vector.Score, Score: the steps of cvss_score.js
//	tables.go  the tables of cvss_lookup.js, max_composed.js and max_severity.js
//
// Tests:
//
//	vector_test.go  what ParseVector takes and refuses
//	score_test.go   every vector against the calculator (testdata/all.sha256), the
//	                tables against it (testdata/tables.json), and Score.String
//
// testdata/reference holds the files of the calculator as they were
// fetched; testdata/all.js and testdata/tables.js run them with node
// (through testdata/load.js), which only remaking the expected values
// needs.
package cvss4
