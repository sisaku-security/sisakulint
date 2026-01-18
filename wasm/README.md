# sisakulint WASM Browser Demo

sisakulintをWebAssemblyにコンパイルしてブラウザで実行するデモ。

## ビルド方法

### 1. WASMファイルの生成

```bash
# js/wasm ターゲットでコンパイル
GOOS=js GOARCH=wasm go build -ldflags "-s -w" -o wasm/htdocs/sisakulint.wasm ./cmd/sisakulint

# Go WASM ランタイムをコピー
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" wasm/htdocs/
```

### 2. ローカルサーバーで確認

```bash
cd wasm/htdocs
python3 -m http.server 8080
# ブラウザで http://localhost:8080 を開く
```

## JavaScript API

WASMロード後、以下のグローバル関数が利用可能になります：

```javascript
// YAML文字列を解析
const resultJson = sisakulintAnalyze(yamlContent, filename);
const result = JSON.parse(resultJson);

// 結果の構造
// {
//   "success": true/false,
//   "errors": [
//     {
//       "line": 10,
//       "column": 5,
//       "message": "エラーメッセージ",
//       "rule": "ルール名"
//     }
//   ]
// }
```

## ファイル構成

```
wasm/
├── README.md           # このファイル
└── htdocs/
    └── index.html      # ブラウザUI
```

ビルド後:
```
wasm/htdocs/
├── index.html          # ブラウザUI
├── sisakulint.wasm     # WASMバイナリ（ビルド生成物）
└── wasm_exec.js        # Go WASMランタイム（コピー）
```
