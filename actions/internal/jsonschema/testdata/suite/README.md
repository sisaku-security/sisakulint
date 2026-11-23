# JSON Schema Test Suite (copy)

These files are copies of the tests for draft 2020-12 of the JSON Schema
Test Suite, at commit `ed0ebd31d0a83fd79e99a32aa0c884b966ada057`:

https://github.com/json-schema-org/JSON-Schema-Test-Suite/tree/ed0ebd31d0a83fd79e99a32aa0c884b966ada057/tests/draft2020-12

They were taken on 2026-11-04, one file for each keyword that the package
reads, with the LICENSE of the suite (MIT). The files are not changed.
`TestSuite` in `suite_test.go` runs each group whose schema `Load` accepts;
`../suite-loaded.golden.json` keeps how many groups of each file it runs.
