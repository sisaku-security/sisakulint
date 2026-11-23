# YAML の仕様書

YAML 1.2 の仕様書（revision 1.2.2、2021-10-01）の写し。取得したバイトをそのまま置いている。仕様書の表記は "This document may be freely copied, provided it is not modified." なので、このディレクトリのファイルは手で直さない。注記はこの README に書く。

取得は 2026-09-23T08:12Z。

## 置いたもの

| パス | 取得元 | sha256 |
|---|---|---|
| `1.2.2/yaml-spec-1.2.2.html` | https://yaml.org/spec/1.2.2/ （公開版） | `2fe1bf40792df22ef8b8a5972a34c48e639969222e0bbae605aa9bb2ca85e9ab` |
| `1.2.2/img/*.svg`（7 枚） | https://yaml.org/spec/1.2.2/img/ （公開版の図） | 下表 |
| `1.2.2/source/spec.md` | `yaml/yaml-spec` @ `1b1a1be43bd6e0cfec45caf0e40af3b5d2bb7f8a` の `spec/1.2.2/spec.md` | `9e198856ec83b4ad659598c223b9df8ef4b6333923ee48d65e7f3f0ad1e7e1af` |
| `1.2.2/source/links.yaml` | 同 `spec/1.2.2/links.yaml`（spec.md の内部リンクの定義） | `3b73f12b8179406b68c19e70e52309715b0f6c792263864e13e75d9ebe643868` |
| `1.2.2/source/ReadMe.md` | 同 `spec/1.2.2/ReadMe.md` | `3982ac597dd1ea2a9ad7662a93bf345be478e5505a352f7d69ed4a82a18a0b7a` |
| `1.2.2/source/repo-ReadMe.md` | 同 `ReadMe.md`（リポジトリの説明） | `36fe77226df334e8f8bdf004bf34dc94008a79768e0f67ff5e00fb4f76ee6fd6` |
| `1.2.2/source/ext/changes.md` | 同 `spec/1.2.2/ext/changes.md`（変更点） | `725f736f26e7c92c43bc709116613f9fe8e531bc982fc832d7ef868c72930e82` |
| `1.2.2/source/ext/errata.md` | 同 `spec/1.2.2/ext/errata.md`（正誤表。中身は "None yet reported"） | `0712087768318de57f395526ac28711022264f1cdfe656318f6f2eb82b6e6e7a` |
| `1.2.2/source/ext/glossary.md` | 同 `spec/1.2.2/ext/glossary.md`（用語集） | `7e626d375816562055560ddecfed788ddbcb58c6f24b9147f97b5fc451555007` |
| `1.2.2/source/ext/resources.md` | 同 `spec/1.2.2/ext/resources.md` | `29bb328209ca285f46aea6759df91cdfcf6c16d2749c3ae865577d687ad9a9de` |
| `1.2.2/source/ext/team.md` | 同 `spec/1.2.2/ext/team.md` | `014f64ba4ff461f43fe140ba1409e40818230d1e3e29b7c09dce16294569252b` |

| 図 | sha256 |
|---|---|
| `img/overview2.svg` | `310bc2af78cc76b0c30abb2351753de8cba58e03c7529911889182bb5395d375` |
| `img/model2.svg` | `743a2d13401bae24199cb99be37105a22df240a8744fbfe4953a1b0ae1687515` |
| `img/represent2.svg` | `654b298f315a4574fa05dac03f06905ec7a45aeab807c885a168bcabe5fba33e` |
| `img/serialize2.svg` | `e35eecbfcb6f2917df604142cc14eeddc70446520189d9e34b4d4e222351d53d` |
| `img/present2.svg` | `9f9a10cf7806529d9abeeec884cc843de1b42ffcc1f6970d01108d226eadd23d` |
| `img/styles2.svg` | `df8f47fbc3eb031c9ab6ee75915130bacc47f0c99352da2c5d17f3ccba051773` |
| `img/validity2.svg` | `442f9391f6bebb0da790b6209f2f0ffd0127af8a71c6b68aacc087cd58c4c013` |

公開版の HTML は図を `/spec/1.2.2/img/` の絶対パスで参照するので、手元で HTML を開いても図は出ない。図は `img/` を直接開く。

期待値付きのテスト集 yaml-test-suite は `yaml-test-suite/` に置いた。出所と中身はそこの README に書いてある。

## 公開版と原稿の差

原稿の `spec/1.2.2/ReadMe.md` は、`spec.md` を「現在開発中の原稿」と書いている。公開日の 2021-10-01 までの最後の commit は `80c6bde4` で、そのあとに `spec.md` へ 2 件の commit が入っている。

| commit | 日付 | 内容 |
|---|---|---|
| `0718ca92` | 2023-05-23 | Fix typos in examples (#262)。例の期待値（JSON 側）の URL を `http` から `https` へ直し、YAML 側と揃えた。2 つの例で 3 行 |
| `1b1a1be4` | 2023-05-23 | Fix repeated 'by' in YAML history section (#288) |

公開版の HTML は #262 の前の版である。たとえば `{ "unquoted": "separate", ... }` の例では、YAML 側が `https://foo.com`、期待値の JSON 側が `http://foo.com` のまま食い違っている。**例をパーサーのテストに使うときは、`source/spec.md` の側を使う。**

## 置いていないもの

- YAML 1.1 と 1.2（2009）の仕様書。GitHub Actions の YAML がどちらの版の解釈に近いかは、使っているパーサー（runner は YamlDotNet 5.3.0、languageservices は npm `yaml`）次第で、ここでは確かめていない。
- 原稿の図の LaTeX ソース（`spec/1.2.2/src/`）。
