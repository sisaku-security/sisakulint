// Package artifact is the analysis of the uploads of artifacts: which
// credentials the steps before an upload leave in files of the workspace
// or of RUNNER_TEMP, and whether the upload puts them in the artifact, where anyone who can
// read the repository takes them. It
// asks no fact: a pinned commit it cannot tell gives a prcode.MissingCommit, which the
// rules ask about.
//
// Where things are:
//
//	tables.go      the commits of the tags of actions/checkout and
//	               actions/upload-artifact, and the actions that leave a
//	               credential
//	version.go     what a ref of those two says: whether a checkout leaves
//	               its credential in .git/config (else in RUNNER_TEMP), whether an upload takes
//	               hidden files and can be downloaded while the run goes on
//	inputs.go      the actions the analysis reads, and their inputs
//	credential.go  the credentials a step leaves; InconclusiveUpload
//	glob.go        whether the lines of path, read once (globLines), take a
//	               file (@actions/glob); a file of RUNNER_TEMP only by a line
//	               under ${{ runner.temp }}
//	upload.go      Analyze: the uploads, the credentials they take, each
//	               once (LeftCredential), and which of them each upload puts
//	               in its artifact (TakenCredential)
package artifact
