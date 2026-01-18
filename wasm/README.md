# sisakulint WASM Browser Demo

sisakulintをWebAssemblyにコンパイルしてブラウザで実行するデモ。

## ビルド方法

### 1. WASMファイルの生成

```bash
# js/wasm ターゲットでコンパイル
GOOS=js GOARCH=wasm go build -ldflags "-s -w" -o wasm/htdocs/sisakulint-js.wasm ./cmd/sisakulint

# Go WASM ランタイムをコピー
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" wasm/htdocs/
```

### 2. ローカルサーバーで確認

```bash
cd wasm/htdocs
python3 -m http.server 8080
# ブラウザで http://localhost:8080 を開く
```

## ファイル構成

```
wasm/
├── Dockerfile.wasm     # Docker用ビルドファイル（参考）
├── README.md           # このファイル
└── htdocs/
    └── index.html      # ブラウザUI
```

## 注意事項

- Go js/wasm ターゲットではファイルシステムアクセスが制限される
- ブラウザで完全に動作させるにはコード修正が必要
- Node.js環境では動作確認済み

## Node.jsでの動作確認

```bash
cd wasm/htdocs
node -e "
require('./wasm_exec.js');
const fs = require('fs');
const wasmBuffer = fs.readFileSync('sisakulint-js.wasm');
const go = new Go();
go.argv = ['sisakulint', '--help'];
WebAssembly.instantiate(wasmBuffer, go.importObject).then(r => go.run(r.instance));
"
```
