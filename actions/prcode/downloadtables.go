package prcode

import (
	"time"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// In the tables below, the commits are those the tags of the two actions pointed to on
// 2026-10-04, annotated tags peeled; v8.0.2 of actions/download-artifact
// was added on 2026-10-07 (its src is that of v8.0.1), and v28 of
// dawidd6/action-download-artifact on 2026-11-01 (its action.yml and
// main.js are those of v27).

// downloadTablesOn is the day the tables below were taken: a release of
// either action published on it or later must be added
// (upstream.CheckTable).
var downloadTablesOn = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

// DownloadArtifactRepo and Dawidd6Repo are the repositories of the two
// actions whose downloads the analysis reads.
var (
	DownloadArtifactRepo = mustRepo("actions/download-artifact")
	Dawidd6Repo          = mustRepo("dawidd6/action-download-artifact")
)

func mustRepo(s string) facts.Repo {
	r, err := facts.ParseRepo(s)
	if err != nil {
		panic(err)
	}
	return r
}

// downloadFixed is the commit of v4.1.3 of actions/download-artifact, the
// fix of the zip-slip of 4.0.0 to 4.1.2 (GHSA-cxww-7g56-2vh6).
const downloadFixed = "87c55149d96e628cc2ef7e6fc2aab372015aec85"

// dawidd6NoForks is the commit that made allow_forks false by default
// (#290, the tag v4).
const dawidd6NoForks = "854e2de9396304899dbe03bf9995fd73533190d1"

// downloadBefore4 are the commits of v1 to v3 of actions/download-artifact,
// which download from the current run only: they have no github-token nor
// run-id (v3.1.0's action.yml has name and path).
var downloadBefore4 = map[string]bool{
	"158ca71f7c614ae705e79f25522ef4658df18253": true, // v2.0.9
	"18f0f591fbc635562c815484d73b6e8e3980482e": true, // 1.0.0, v1, v1.0.0
	"1ac47ba4b6af92e65d0438b64ce1ea49ce1cc48d": true, // v2.0.1
	"1de1dea89c32dcb1f37183c96fe85cfe067b682a": true, // v2.0
	"246d7188e736d3686f6d19628d253ede9697bd55": true, // v3-node20
	"381af06b4268a1e0ad7b7c7e5a09f1894977120f": true, // v2.0.2
	"3be87be14a055c47b01d3bd88f8fe02320a9bb60": true, // v2.0.10
	"4a7a711286f30c025902c28b541c10e147a9b843": true, // v2.0.8
	"80d2d4023c185001eacb50e37afd7dd667ba8044": true, // v2.0.3
	"9782bd6a9848b53b110e712e20e42d89988822b7": true, // v3.0.1
	"9bc31d5ccc31df68ecc42ccf4149144866c47d8a": true, // v3, v3.0.2
	"a9bc5e6ef2cb54c177f32aa5726adaa15e7e2d59": true, // v3.1.0
	"ad191675b41f6a5b46da9a048cb6893812da158b": true, // v3.1.0-node20
	"b3cedea9bed36890c824f4065163b667eeca272b": true, // v2.0.4
	"c3f5d00c8784369c43779f3d2611769594a61f7a": true, // v2.0.5
	"cbed621e49e4c01b044d60f6c80ea4ed6328b281": true, // v2, v2.1.1
	"f023be2c48cc18debc3bacd34cb396e0295e2869": true, // v2.1.0
	"f144d3c3916a86f4d6b11ff379d17a49d8f85dbc": true, // v2.0.7
	"f8e41fbffeebb48c0273438d220bb2387727471f": true, // v2.0.6
	"fb598a63ae348fa914e94cd0ff38f362e927b741": true, // v3.0.0
}

// downloadZipSlip are the commits of 4.0.0 to 4.1.2, which write where the
// paths of the zip say, .. too.
var downloadZipSlip = map[string]bool{
	"6b208ae046db98c579e8a3aa621ab581ff575935": true, // v4.1.1
	"7a1cd3216ca9260cd8022db641d960b1db4d1be4": true, // v4.0.0
	"eaceaf801fd36c7dee90939fad912460b18a1ffe": true, // v4.1.2
	"f44cd7b40bfd40b6aa1cc1b9b5b7bf03d3c67110": true, // v4.1.0
}

// downloadFixedOn are the commits of v4.1.3 on of actions/download-artifact.
var downloadFixedOn = map[string]bool{
	"018cc2cf5baa6db3ef3c5f8a56943fffe632ef53": true, // v6, v6.0.0
	"37930b1c2abaa49bbe596cd826c3c89aef350131": true, // v7, v7.0.0
	"3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c": true, // v8.0.1
	"634f93cb2916e3fdff6788551b99b062d0335ce0": true, // v5, v5.0.0
	"65a9edc5881444af0b9093a5e628f2fe47ea3b2e": true, // v4.1.7
	"70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3": true, // v8.0.0
	"87c55149d96e628cc2ef7e6fc2aab372015aec85": true, // v4.1.3
	"9000827ccba6bdab643e8b6fd33ac0654aef8333": true, // v8, v8.0.2
	"8caf195ad4b1dee92908e23f56eeb0696f1dd42d": true, // v4.1.5
	"95815c38cf2ff2164869cbab79da8d1f422bc89e": true, // v4.2.1
	"9c19ed7fe5d278cd354c7dfd5d3b88589c7e2395": true, // v4.1.6
	"b14cf4c92620c250e1c074ab0a5800e37df86765": true, // v4.2.0
	"c850b930e6ba138125429b7e5c93fc707a7f8427": true, // v4.1.4
	"cc203385981b70ca67e1cc392babf9cc229d5806": true, // v4.1.9
	"d3f86a106a0bac45b974a628896c90dbdf5c8093": true, // v4, v4.3.0
	"fa0a91b85d4f404e444e00e005971372dc801d16": true, // v4.1.8
}

// dawidd6Forks are the commits of dawidd6/action-download-artifact before v4,
// which search the runs of forks by default (before v2.28.0 always).
var dawidd6Forks = map[string]bool{
	"0171e8230d24e6c6aee9e922110f6d8ec0641e72": true, // v2.0.0
	"09385b76de790122f4da9c82b17bccf858b9557c": true, // v2.16.0
	"09f2f74827fd3a8607589e5ad7f9398816f540fe": true, // v3, v3.1.4
	"1188d6f9a7493945fde34b76f9d8a1dab7cedf96": true, // v2.6.2
	"1cf11afe3f1874cee82a8d5a2b45c0fd63f0fa22": true, // v2.18.0
	"246dbf436b23d7c49e21a7ab8204ca9ecd1fe615": true, // v2.27.0
	"268677152d06ba59fcec7a7f0b5d961b6ccd7e1e": true, // v2, v2.28.0
	"35e61b9c228e2067c3b87e49b79f0c2d8dd319e9": true, // v2.13.0
	"46b4ae883bf0726f5949d025d31cb62c7a5ac70c": true, // v2.24.0
	"4f461a318eb67dc01424d47b688d97c0460441bb": true, // v2.3.1
	"5004d5476e64af71d021e6c98993829d8820969d": true, // v2.24.4
	"575b1e4167df67acf7e692af784566618b23c71e": true, // v2.17.0
	"5b72739630efa11b8d81784b89adf5246a5fc475": true, // v2.10.0
	"5e780fc7bbd0cac69fc73271ed86edf5dcb72d67": true, // v2.26.0
	"61e4b4957cef033d9e2222297fd963a9460e6a3d": true, // v1.1.0
	"642b58eb4ce2ee9e22cbacf4e6b3490fe48cc0b8": true, // v2.6.1
	"6765a42d86407a3d532749069ac03705ad82ebc6": true, // v2.21.1
	"6f8f427fb41886a66b82ea11a5a15d1454c79415": true, // v2.14.1
	"71072fbb1229e1317f1a8de6b04206afb461bd67": true, // v3.1.2
	"7132ab516fba5f602fafae6fdd4822afa10db76f": true, // v2.26.1
	"72aaadce3bc708349fc665eee3785cbb1b6e51d0": true, // v3.1.1
	"7847792dd435a50521b8e3bd3576dae7459d1fa8": true, // v2.23.0
	"80fcec8114889f74eb442780f3c71bff4d42a98a": true, // v2.20.0
	"81490e4d8cd58430402b487b29025ad8712dfc4c": true, // v2.6.0
	"86f3002f4e95a0ad10fa8514fe27e1dbfdcd190c": true, // v2.9.0
	"891cccee4b25d3306cf5edafa174ddc1d969871f": true, // v2.11.0
	"8c4c695f12a8f22d86925f9807947cc2dc846e6b": true, // v2.6.3
	"8c96194455d424a24437ec57817e0aa1a1d72adb": true, // v2.12.0
	"9e4e8ea0c90c3613f2c7d31502c3f575ed4cfc6b": true, // v2.4.0
	"a2229d2b378483e84452b603c5613cb8ddf02f95": true, // v2.5.0
	"a430ac5786b39ad5869da25a98130624d2ce340c": true, // v3.1.3
	"af92a8455a59214b7b932932f2662fdefbd78126": true, // v2.15.0
	"b12b127cf24433d14b4f93cee62f5465076ba82a": true, // v2.24.1
	"b2abf1705491048a2d7074f7d90513044fd25d39": true, // v2.19.0
	"b59d8c6a6c5c6c6437954f470d963c0b20ea7415": true, // v2.25.0
	"b7337e51c4775d1f22357423ade50ee0a5f5779e": true, // v2.21.0
	"b9571484721e8187f1fd08147b497129f8972c74": true, // v2.14.0
	"bb4bdd30069fecb7806de59879d1e0614425e53d": true, // v2.11.1
	"bd10f381a96414ce2b13a11bfa89902ba7cea07f": true, // v2.24.3
	"c38e7434e6defad309cda10f41d9fb25ef68d023": true, // v2.2.0
	"c5a6a7120417fda051bda8e6d4188aded2810030": true, // v2.8.0
	"cf1843db5589044704279c7f1ef6694d3aedc495": true, // v2.3.0
	"dfc29ea68ea5e00440b7c15468968d4faa7f806f": true, // v1.0.0
	"e381d8177e8c1d14f16e61f1619bf6fe7fa86b3e": true, // v2.7.0
	"e52db4e07deb0cea64125f8bafa1fc431af7ee37": true, // v2.1.0
	"e6e25ac3a2b93187502a8be1ef9e9603afc34925": true, // v2.24.2
	"e7466d1a7587ed14867642c2ca74b5bcc1e19a2d": true, // v3.0.0
	"ea71f332a90fd52416b1629b933dcf7e0ccd421d": true, // v2.22.0
	"f040bd169acb8a1e0e6f8d30f53dd70e22f1af5c": true, // v2.8.1
	"f6b0bace624032e30a85a8fd9c1a7f8f611f5737": true, // v3.1.0
}

// dawidd6NoForksOn are the commits of v4 on, which keep forks out by default.
var dawidd6NoForksOn = map[string]bool{
	"07ab29fd4a977ae4d2b275087cf67563dfdf0295": true, // v9
	"09b07ec687d10771279a426c79925ee415c12906": true, // v17
	"0bd50d53a6d7fb5cb921e607957e9cc12b4ce392": true, // v12
	"1f8785ff7a5130826f848e7f72725c85d241860f": true, // v18
	"20319c5641d495c8a52e688b7dc5fada6c3a9fbc": true, // v8
	"2536c51d3d126276eb39f74d6bc9c72ac6ef30d3": true, // v16
	"27e4ae67c24b67d3b54bc6d6a45475be1e28031b": true, // v26
	"4c1e823582f43b179e2cbb49c3eade4e41f992e2": true, // v10
	"57aa996fc1713cc1579039614f4645a7f4841fd4": true, // v23
	"5c98f0b039f36ef966fdb7dfa9779262785ecb05": true, // v14
	"634d83b91986fcec9be314054943fa5c976aeb0e": true, // v25
	"7f871e041ed7fe12467d2d4196da8a466c5311ff": true, // v22
	"80620a5d27ce0ae443b965134db88467fc607b43": true, // v7
	"8305c0f1062bb0d184d09ef4493ecb9288447732": true, // v20
	"854e2de9396304899dbe03bf9995fd73533190d1": true, // v4
	"883bc3da0e2f55ddd0a8fc8e99378551c1991a55": true, // v13
	"8a338493df3d275e4a7a63bcff3b8fe97e51a927": true, // v19
	"a92c7ae74cf1df8810783758581e485ac3aaa309": true, // v28
	"ac66b43f0e6a346234dd65d4d0c8fbb31cb316e5": true, // v11
	"b6e2e70617bc3265edd6dab6c906732b2f1ae151": true, // v21
	"bf251b5aa9c2f7eeb574a96ee720e24f801b7c11": true, // v6
	"d63b86af1b34672e53c440b1b83979861906bad7": true, // v24
	"deb3bb83256a78589fef6a7b942e5f2573ad7c13": true, // v5
	"eab87c9830c39eff17e5a6eadb20bfb4bc880477": true, // v27
	"fe9d59ce33ce92db8a6ac90b2c8be6b6d90417c8": true, // v15
}

// dawidd6NoAllowForks are the commits before v2.28.0 (268677152d06), which
// have no allow_forks and search the runs of forks whatever it says.
var dawidd6NoAllowForks = map[string]bool{
	"0171e8230d24e6c6aee9e922110f6d8ec0641e72": true, // v2.0.0
	"09385b76de790122f4da9c82b17bccf858b9557c": true, // v2.16.0
	"1188d6f9a7493945fde34b76f9d8a1dab7cedf96": true, // v2.6.2
	"1cf11afe3f1874cee82a8d5a2b45c0fd63f0fa22": true, // v2.18.0
	"246dbf436b23d7c49e21a7ab8204ca9ecd1fe615": true, // v2.27.0
	"35e61b9c228e2067c3b87e49b79f0c2d8dd319e9": true, // v2.13.0
	"46b4ae883bf0726f5949d025d31cb62c7a5ac70c": true, // v2.24.0
	"4f461a318eb67dc01424d47b688d97c0460441bb": true, // v2.3.1
	"5004d5476e64af71d021e6c98993829d8820969d": true, // v2.24.4
	"575b1e4167df67acf7e692af784566618b23c71e": true, // v2.17.0
	"5b72739630efa11b8d81784b89adf5246a5fc475": true, // v2.10.0
	"5e780fc7bbd0cac69fc73271ed86edf5dcb72d67": true, // v2.26.0
	"61e4b4957cef033d9e2222297fd963a9460e6a3d": true, // v1.1.0
	"642b58eb4ce2ee9e22cbacf4e6b3490fe48cc0b8": true, // v2.6.1
	"6765a42d86407a3d532749069ac03705ad82ebc6": true, // v2.21.1
	"6f8f427fb41886a66b82ea11a5a15d1454c79415": true, // v2.14.1
	"7132ab516fba5f602fafae6fdd4822afa10db76f": true, // v2.26.1
	"7847792dd435a50521b8e3bd3576dae7459d1fa8": true, // v2.23.0
	"80fcec8114889f74eb442780f3c71bff4d42a98a": true, // v2.20.0
	"81490e4d8cd58430402b487b29025ad8712dfc4c": true, // v2.6.0
	"86f3002f4e95a0ad10fa8514fe27e1dbfdcd190c": true, // v2.9.0
	"891cccee4b25d3306cf5edafa174ddc1d969871f": true, // v2.11.0
	"8c4c695f12a8f22d86925f9807947cc2dc846e6b": true, // v2.6.3
	"8c96194455d424a24437ec57817e0aa1a1d72adb": true, // v2.12.0
	"9e4e8ea0c90c3613f2c7d31502c3f575ed4cfc6b": true, // v2.4.0
	"a2229d2b378483e84452b603c5613cb8ddf02f95": true, // v2.5.0
	"af92a8455a59214b7b932932f2662fdefbd78126": true, // v2.15.0
	"b12b127cf24433d14b4f93cee62f5465076ba82a": true, // v2.24.1
	"b2abf1705491048a2d7074f7d90513044fd25d39": true, // v2.19.0
	"b59d8c6a6c5c6c6437954f470d963c0b20ea7415": true, // v2.25.0
	"b7337e51c4775d1f22357423ade50ee0a5f5779e": true, // v2.21.0
	"b9571484721e8187f1fd08147b497129f8972c74": true, // v2.14.0
	"bb4bdd30069fecb7806de59879d1e0614425e53d": true, // v2.11.1
	"bd10f381a96414ce2b13a11bfa89902ba7cea07f": true, // v2.24.3
	"c38e7434e6defad309cda10f41d9fb25ef68d023": true, // v2.2.0
	"c5a6a7120417fda051bda8e6d4188aded2810030": true, // v2.8.0
	"cf1843db5589044704279c7f1ef6694d3aedc495": true, // v2.3.0
	"dfc29ea68ea5e00440b7c15468968d4faa7f806f": true, // v1.0.0
	"e381d8177e8c1d14f16e61f1619bf6fe7fa86b3e": true, // v2.7.0
	"e52db4e07deb0cea64125f8bafa1fc431af7ee37": true, // v2.1.0
	"e6e25ac3a2b93187502a8be1ef9e9603afc34925": true, // v2.24.2
	"ea71f332a90fd52416b1629b933dcf7e0ccd421d": true, // v2.22.0
	"f040bd169acb8a1e0e6f8d30f53dd70e22f1af5c": true, // v2.8.1
}
