# script

- script/actions/ の fixture (~150 ファイル) は自動テストに接続されていない。Go テストが実ファイルを読むのは pkg/core/cross_file_taint_integration_test.go だけで、ファイル名がハードコードされている (リネームでテストが割れる)。fixture の検証は手動で sisakulint script/actions/<file>.yaml を実行する。
- fixture を追加したら script/README.md の表に記載する。advisory/ と ghsl/ サブディレクトリおよび goat-*.yml は docs/ 配下の検出カバレッジレポートと対になっており、追加時はレポート側の件数・検出率も手動更新する。
