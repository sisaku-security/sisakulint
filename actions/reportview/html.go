package reportview

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"strings"
)

//go:embed assets/view.js
var script string

//go:embed assets/view.css
var style string

// policy is the Content-Security-Policy of the page: only its own script
// and style run, and nothing is fetched or sent.
var policy = "default-src 'none'; script-src 'sha256-" + digest(script) + "'; style-src 'sha256-" + digest(style) + "'; base-uri 'none'; form-action 'none'"

func digest(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.StdEncoding.EncodeToString(h[:])
}

const skeleton = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{{policy}}">
<title>{{title}}</title>
<style>{{style}}</style>
</head>
<body>
<script type="application/json" id="{{id}}">{{data}}</script>
<main id="app"></main>
<script>{{script}}</script>
</body>
</html>
`

// HTML is the page of p, whole in one file. json.Marshal writes <, > and
// & as \u003c and the like, so no text of a workflow closes the script of
// the data; the replacer does not read again what it puts in.
func (p Page) HTML() ([]byte, error) { return page("report-data", "sisakulint report", p) }

// HTML is the catalog's page, whole in one file, as Page.HTML.
func (c Catalog) HTML() ([]byte, error) { return page("catalog-data", "sisakulint examples", c) }

// page is the skeleton titled title, with v as the data of the script
// element id.
func page(id, title string, v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	r := strings.NewReplacer("{{policy}}", policy, "{{title}}", title, "{{style}}", style, "{{id}}", id, "{{data}}", string(data), "{{script}}", script)
	return []byte(r.Replace(skeleton)), nil
}
