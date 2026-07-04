# script

- The roughly 150 fixtures in script/actions/ are not wired to automated tests. Only two Go tests read real files — pkg/core/cross_file_taint_integration_test.go and pkg/core/linter_optin_test.go — and both hardcode filenames, so renaming those YAMLs breaks them. Verify fixtures manually with sisakulint script/actions/<file>.yaml.
- When adding a fixture, record it in the table in script/README.md. The advisory/ and ghsl/ subdirectories and the goat-*.yml files pair with the detection-coverage reports under docs/advisory, docs/ghsl, and docs/goat; additions require manually updating the counts and detection rates on the report side too.
