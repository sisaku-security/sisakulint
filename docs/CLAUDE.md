+++
draft = true
+++

# docs

- This directory is Hugo site source. Every md uses TOML front matter (+++ ... +++) and shortcodes ({{< ref "x.md" >}} and similar). Plain relative Markdown links break the site build.
- The severity counts table in _index.md is manually tallied. Update the numbers when rules are added or downgraded.
- goat/, advisory/, and ghsl/ are detection-coverage reports against external threat catalogs, paired with fixtures in script/actions/. Runtime-class misses are explicitly marked out of scope by design — do not treat them as detection gaps.
- superpowers/specs/ holds finalized design records: large taint changes get a design doc here before implementation (design-first). superpowers/plans/ is gitignored — plans are discarded, only settled designs are kept.
