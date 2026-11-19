package prcode

import (
	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// v1Refs are the refs of actions/checkout that run v1, the checkout
// plugin of the runner, whose action.yml has runs: plugin. v1 resolves
// path from runner.workspace and moves github.workspace to where it puts
// the tree, when it checks out the repository of the workflow
// (https://github.com/actions/runner/blob/310a370bf3605f5b092f8af63b3126627de2a210/src/Runner.Plugins/Repository/v1.1/RepositoryPlugin.cs).
// The commits are those whose action.yml says plugin, read one by one at
// https://api.github.com/repos/actions/checkout/contents/action.yml?ref=<sha>
// (2026-11-10): the history of the tag v1, the 14 commits from v1 to
// v2.0.0 (none of them), and the heads of the branches. The tags and the
// branches are those that point at such a commit.
var v1Refs = map[string]bool{
	"v1": true, "v1.0.0": true, "v1.1.0": true, "v1.2.0": true, "1.0.0": true,
	"releases/v1": true, "revert-56-users/tihuang/checkoutV1_1": true, "Update-description": true,

	"0963d3b35f4826b619c2436e1bdce37c147daeaf": true,
	"0b496e91ec7ae4428c3ed2eeb4c3a40df431f2cc": true,
	"3204e0bf8cc961de0423eafd557ab191aad42167": true,
	"3df79e0276f4013ea6ed57534f3478cd2b1ef8c0": true,
	"50fbc622fc4ef5163becd7fab6573eac35f8462e": true,
	"53bed0742eb3f0455187c7c7042d27f51b856f02": true,
	"6e6328ef28ba9c951379a07c83913e2acc8bc9a0": true,
	"7f0669ca1fd955c0e0fd85ee8d5b8d16978be97e": true,
	"94d077c24971944d312dd9197c1bdfba62b39878": true,
	"a14471d838f6a7ce15cab8740f25e337c51e7cad": true,
	"af513c7a016048ae468971c52ed77d9562c7c819": true,
	"b4b537b06a577732e04b29acc7294f645c135da0": true,
	"bf4af63534d79cb0712d8c86d8f2404844fa5a79": true,
	"cacfc4155de4db33162bcb6c82700751fda6bd91": true,
	"d8d55467a3a890e9c1a42ad0293d9800583e1975": true,
	"e8bd1dffb6451bb0d84dbcd3ed059daca1371180": true,
	"f6ce2afa7079cb075a124c93c79d61779d845782": true,
}

// mayBeV1 is whether u is actions/checkout at a ref of v1Refs. A ref in
// none is read as v2 on.
func mayBeV1(u workflow.Uses) bool {
	ref, ok := calls.CheckoutRef(u)
	return ok && v1Refs[ref]
}
