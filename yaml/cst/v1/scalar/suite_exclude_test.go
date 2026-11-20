package scalar

// suiteExclude lists, per check, the yaml-test-suite cases this package
// does not pass, with the reason and the section of the YAML 1.2.2
// specification it concerns.
var suiteExclude = map[string]map[string]string{
	// The suite treats the end of the input as a line break; libyaml,
	// YamlDotNet and GitHub do not, and neither does YAML 1.2.2: [165] b-chomped-last(t) at <end-of-input>
	// adds no line feed, and [70] l-empty needs a b-as-line-feed.
	"values": {
		"L24T/01": "8.1.1.2: a last content line at the end of the input keeps no line feed",
		"JEF9/02": "8.1.1.2: spaces at the end of the input are no l-empty line",
	},
}
