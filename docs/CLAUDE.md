+++
draft = true
+++

# docs

- Hugo サイトのソース。各 md は TOML フロントマター (+++ ... +++) と shortcode ({{< ref "x.md" >}} 等) を使う。素の相対 Markdown リンクはサイトビルドで壊れる。
- _index.md の Severity 別件数表は手動集計。ルールの追加・降格時に数を更新する。
- goat/ advisory/ ghsl/ は外部脅威カタログへの検出カバレッジレポートで、script/actions/ の対応 fixture とペア。runtime 系の未検出は out of scope by design と明記済みで、検出漏れとして扱わない。
- superpowers/specs/ は確定した設計記録。大きな taint 変更は実装前にここへ設計書を書く (design-first)。superpowers/plans/ は gitignore 済みで、計画は残さず確定設計だけを残す。
