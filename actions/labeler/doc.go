// Package labeler reads the steps of a repository that run actions/labeler
// on the pull request of an attacker with a token other than the
// GITHUB_TOKEN, and the labels each step lets the attacker get. A label
// added with such a token starts the runs on labeled
// (https://github.com/github/docs/blob/481d4e35beb53953e277d0b11ba4a18f8c8ade4f/content/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow.md),
// so an approval by that label approves nothing that a person read.
//
// The configuration is read as the labeler reads it, release by release:
// https://github.com/actions/labeler/blob/bf12e9b00b37c5c0ca2b87b79b2daf7891dbda13/src/api/get-label-configs.ts
// (v7.0.0),
// https://github.com/actions/labeler/blob/ac9175f8a1f3625fd0d4fb234536d26811351594/src/labeler.ts
// (v4.3.0) and
// https://github.com/actions/labeler/blob/5f867a63be70efff62b767459b009290364495eb/src/main.ts
// (2.2.0).
package labeler
