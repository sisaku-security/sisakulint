package artifact

import (
	"time"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// In the tables below, the commits are those the tags pointed to on 2026-09-30 (git ls-remote --tags,
// annotated tags peeled); v7.0.2 of actions/upload-artifact was added on
// 2026-10-07 (its src is that of v7.0.1). A commit in no table is asked
// about (prcode.MissingCommit).

// tablesOn is the day the tables below were taken: a release of
// actions/checkout or actions/upload-artifact published on it or later must
// be added (upstream.CheckTable).
var tablesOn = time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)

var (
	// UploadRepo is the repository of actions/upload-artifact.
	UploadRepo = mustRepo("actions/upload-artifact")

	pagesDeployRepo = mustRepo("JamesIves/github-pages-deploy-action")
	authRepo        = mustRepo("google-github-actions/auth")
	dotnetRepo      = mustRepo("actions/setup-dotnet")

	// checkoutTemp is the first commit of actions/checkout that keeps the
	// credential in RUNNER_TEMP, not .git/config (v6.0.0).
	checkoutTemp = mustSHA("1af3b93b6815bc44a9784bd300feb67ff0d1eeb3")
	// uploadExcludes are the first commits of actions/upload-artifact that
	// leave hidden files out by default: v4.4.0, and v3.2.0 of the
	// backport.
	uploadExcludes = []facts.SHA{mustSHA("50769540e7f4bd5e21e526ee35c689e35e0d6874"), mustSHA("9ee08a3b00e91a926cc9547dc79589c20872452f")}
)

// checkoutLeaves are the commits of the tags v1 to v5.1.0 of
// actions/checkout, which leave the credential in .git/config;
// checkoutKeeps those of v6 and v7, which do not.
var checkoutLeaves = shas(
	"50fbc622fc4ef5163becd7fab6573eac35f8462e", "af513c7a016048ae468971c52ed77d9562c7c819", "0b496e91ec7ae4428c3ed2eeb4c3a40df431f2cc",
	"0717577d45739eb3c851188b29f50ed6c0b2194e", "722adc63f1aa60a57ec37892e133b1d319cae598", "01aecccf739ca6ff86c0539fbc67a7a5007bbc81",
	"86f86b36ef15e6570752e7175f451a512eac206b", "aabbfeb2ce60b5bd82389903509092c4648a9713", "b4483adec309c0d01a5435c5e24eb40de5773ad9",
	"28c7f3d2b5162b5ddd3dfd9a45aa55eaf396478b", "2036a08e25fa78bbd946711a407b529a0a1204bf", "a81bbbf8298c0fa03ea29cdc473d45769f953675",
	"5a4ac9002d0be2fb38bd78e4b4dbde5606d7042f", "1e204e9a9253d643386038d443f96446fa156a97", "ec3a7ce113134d7a93b817d10a8272cb61118579",
	"f25a3a9f25bd5f4c5d77189cab02ff357b5aedeb", "7884fcad6b5d53d10323aee724dc68d8b9096a2e", "e2f20e631ae6d7dd3b768f56a5d2af784dd54791",
	"dc323e67f16fb5f7663d20ff7941f27f5809e9b6", "ee0669bd1cc54295c223e0bb666b733df41de1c5", "a37ce9120846195fa4ece8f58b268e6043cb2f26",
	"a12a3943b4bdde767164f792f33f40b04645d846", "dcd71f646680f2efd8db4afa5ad64fdcba30e748", "2541b1294d2704b0964813337f33b291d3f8596b",
	"93ea575cb5d8a053eaa0ac8fa3b40d7e05a33cc8", "755da8c3cf115ac066823e79a1e1788f8940201b", "ac593985615ec2ede58e132d2e21d2b1cbd6127c",
	"24cb9080177205b6e8c946b17badbe402adc938f", "8f4b7f84864484a7bf31766abe9204da3cbe65b3", "83b7061638ee4956cf7545a6f7efe594e5ad0247",
	"8e5e7e5ab8b370d6c329ec480221332ada57f0ab", "c85c95e3d7251135ab7dc9ce3241c5835cc595a9", "f43a0e5ff2bd294095638e18286ca9a3d1956744",
	"11d5960a326750d5838078e36cf38b85af677262", "1e31de5234b9f8995739874a8ce0492dc87873e2", "8ade135a41bc03ea155e62e844d188df1ea18608",
	"b4ffde65f46336ab88eb53be808477a3936bae11", "9bb56186c3b09b4f86b1c65136769dd318469633", "1d96c772d19495a3b5c517cd2bc0cb401ea0529f",
	"0ad4b8fadaa221de15dcec353f45205ec38ea70b", "44c2b7a8a4ea60a981eaca3cf939b5f4305c123b", "a5ac7e51b41094c92402da3b24376905380afc29",
	"692973e3d937129bcbf40652eb9f2f61becf3332", "d632683dd7b4114ad314bca15554477dd762a938", "eef61447b9ff4aafe5dcd4e0bbf5d482be7e7871",
	"11bd71901bbe5b1630ceea73d27597364c9af683", "08eba0b27e820071cde6df949e0beb9ba4906955", "34e114876b0b11c390a56381ad16ebd13914f8d5",
	"fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09", "08c6903cd8c0fde910a37f88322edcfb5dd907a8", "93cb6efe18208431cddfb8368fd83d5badbf9bfd",
)

var checkoutKeeps = shas(
	"d23441a48e516b6c34aea4fa41551a30e30af803", "1af3b93b6815bc44a9784bd300feb67ff0d1eeb3", "8e8c483db84b4bee98b60c0593521ed34d9990e8",
	"de0fac2e4500dabe0009e67214ff5f5447ce83dd", "df4cb1c069e1874edd31b4311f1884172cec0e10", "3d3c42e5aac5ba805825da76410c181273ba90b1",
	"9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
)

// uploadTakes are the commits of the tags of actions/upload-artifact that
// take hidden files whatever the input (v1 to v3.1.3, v4.0.0 to v4.3.6);
// uploadNever v3.2.0, whose input is not passed; uploadInput those that
// take them only with include-hidden-files true. uploadBefore4 are those
// of v1 to v3, whose artifacts are there only after the run.
var (
	uploadTakes = shas(
		"3446296876d12d4e3a0f3145a3c87e67bf0a16b5", "82c141cc518b40d92cc801eee768e7aafc9c2fa2", "97b7dace6c8d860ce9708aba808be6a2ee4cbc3a",
		"ebad382c0953e8c6b4039e8d30dfd19ee7b2a862", "5f948bc1f0a251f88bb4c9b1c3dfa6cbd1327dc5", "c8879bf5aef7bef66f9b82b197f34c4eeeb1731b",
		"268d7547644ab8a9d0c1163299e59a1f5d93f39b", "58740802ef971a2d71eff71e63d48ab68d1f5507", "27bce4eee761b5bc643f46a8dfb41b430c8d05f6",
		"726a6dcd0199f578459862705eed35cda05af50b", "e448a9b857ee2131e752b06002bf0e093c65e571", "ee69f02b3dfdecd58bb31b4d133da38ba6fe3700",
		"27121b0bdffd731efa15d66772be8dc71245d074", "da838ae9595ac94171fa2d4de5a2f117b3e7ac32", "6673cd052c4cd6fcf4b4e6e60ea986c889389535",
		"3cea5372237819ed00197afe530f5a7ea3e805c8", "83fd05a356d7e2593de66fc9913b3002723633cb", "0b7f8abb1508181956e8e162db84b466c27e18ce",
		"a8a3f3ad30e3422c9c7b888a15615d19a852ae32", "c7d193f32edcb7bfad88892161225aeda64e9392", "1eb3cb2b3e0f29609092a73eb033bb759a334595",
		"694cdabd8bdb0f10b2cea11669e1bf5453eed0a6", "26f96dfa697d77e81fd5907df203aa23a56210a8", "5d5d22a31266ced268874388b861e4b58bb5c2f3",
		"1746f4ab65b179e0ea60a494b83293b640dd5bba", "65462800fd760344b1a7b4382951275a0abb4808", "0b2256b8c012f0828dc542b3febcab082c67f72b",
		"89ef406dd8d7e03cfd12d9e0a4a378f454709029", "834a144ee995460fba8ed112a2fc961b36a5ec5a",
	)
	uploadNever = shas("9ee08a3b00e91a926cc9547dc79589c20872452f")
	uploadInput = shas(
		"ff15f0306b3f739f7b6fd43fb5d26cd321bd4de5", "c6a366c94c3e0affe28c06c8df20a878f24da3cf", "ea165f8d65b6e75b540449e92b4886f43607fa02",
		"50769540e7f4bd5e21e526ee35c689e35e0d6874", "604373da6381bf24206979c74d06a550515601b9", "84480863f228bb9747b473957fcc9e309aa96097",
		"b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882", "6f51ac03b9356f520e9adb1b1b7802705f340c2b", "65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08",
		"4cec3d8aa04e39d1a68397de0c4cd6fb9dce8ec1", "330a01c490aca151604b8cf639adc76d48f6c5d4", "b7c566a772e6b6bfb58ed0dc250532a479d7789f",
		"043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "bbbca2ddaa5d8feaa63e36b76fdaad77386f024f", "cf430e030ddbb5b0abf93d22962f4752f3646cd9",
	)
	uploadBefore4 = shas(
		"3446296876d12d4e3a0f3145a3c87e67bf0a16b5", "82c141cc518b40d92cc801eee768e7aafc9c2fa2", "97b7dace6c8d860ce9708aba808be6a2ee4cbc3a",
		"ebad382c0953e8c6b4039e8d30dfd19ee7b2a862", "5f948bc1f0a251f88bb4c9b1c3dfa6cbd1327dc5", "c8879bf5aef7bef66f9b82b197f34c4eeeb1731b",
		"268d7547644ab8a9d0c1163299e59a1f5d93f39b", "58740802ef971a2d71eff71e63d48ab68d1f5507", "27bce4eee761b5bc643f46a8dfb41b430c8d05f6",
		"726a6dcd0199f578459862705eed35cda05af50b", "e448a9b857ee2131e752b06002bf0e093c65e571", "ee69f02b3dfdecd58bb31b4d133da38ba6fe3700",
		"27121b0bdffd731efa15d66772be8dc71245d074", "da838ae9595ac94171fa2d4de5a2f117b3e7ac32", "6673cd052c4cd6fcf4b4e6e60ea986c889389535",
		"3cea5372237819ed00197afe530f5a7ea3e805c8", "83fd05a356d7e2593de66fc9913b3002723633cb", "0b7f8abb1508181956e8e162db84b466c27e18ce",
		"a8a3f3ad30e3422c9c7b888a15615d19a852ae32", "9ee08a3b00e91a926cc9547dc79589c20872452f", "ff15f0306b3f739f7b6fd43fb5d26cd321bd4de5",
		"c6a366c94c3e0affe28c06c8df20a878f24da3cf",
	)
)

func mustRepo(s string) facts.Repo {
	r, err := facts.ParseRepo(s)
	if err != nil {
		panic(err)
	}
	return r
}

func mustSHA(s string) facts.SHA {
	x, err := facts.ParseSHA(s)
	if err != nil {
		panic(err)
	}
	return x
}

func shas(xs ...string) map[string]bool {
	out := map[string]bool{}
	for _, x := range xs {
		out[mustSHA(x).String()] = true
	}
	return out
}
