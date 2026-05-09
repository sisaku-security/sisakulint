package core

import "fmt"

// applyOptInRules は makeRules() の戻り値からデフォルト無効 (opt-in) ルールを
// フィルタする。enabled に名前が含まれない opt-in ルールは結果から除外される。
//
// enabled に含まれる名前のうち、どのルールにも対応しないものはエラーで返す
// (CLI typo / 削除済みルール名の検出)。
//
// enabled に含まれる名前が既知だが opt-in でない場合は no-op として黙って受け入れる。
// これにより将来 opt-in から default-on に降格したルール名が CLI 側に残っていても
// 既存ユーザーの CI が壊れない。
func applyOptInRules(rules []Rule, enabled []string) ([]Rule, error) {
	enabledSet := make(map[string]struct{}, len(enabled))
	for _, n := range enabled {
		enabledSet[n] = struct{}{}
	}

	knownNames := make(map[string]struct{}, len(rules))
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		knownNames[r.RuleNames()] = struct{}{}
		if r.IsOptIn() {
			if _, ok := enabledSet[r.RuleNames()]; !ok {
				continue
			}
		}
		out = append(out, r)
	}

	for name := range enabledSet {
		if _, ok := knownNames[name]; !ok {
			return nil, fmt.Errorf("unknown rule name passed to -enable-rule: %q", name)
		}
	}
	return out, nil
}
