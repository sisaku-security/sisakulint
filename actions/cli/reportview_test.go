package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pageData is the JSON in a report view.
func pageData(t *testing.T, page []byte) []byte {
	t.Helper()
	_, rest, ok := bytes.Cut(page, []byte(`<script type="application/json" id="report-data">`))
	if !ok {
		t.Fatal("no data in the page")
	}
	data, _, ok := bytes.Cut(rest, []byte("</script>"))
	if !ok {
		t.Fatal("the data is not closed")
	}
	return data
}

func TestHTMLUsage(t *testing.T) {
	dir := example(t)
	out := filepath.Join(t.TempDir(), "view.html")
	for _, a := range [][]string{
		{"--root", dir, "--html", out, "--fix"},
		{"--root", dir, "--serve", "--fix=review", "--dry-run"},
		{"--root", dir, "--serve=0.0.0.0:0"},
		{"--root", dir, "--serve=localhost:0"},
		{"--root", dir, "--html="},
		{"--html", out, "--explain=all"},
	} {
		if got := run(t, raw(a...)); got.code != ExitUsage {
			t.Errorf("%v: %d, want %d\n%s", a, got.code, ExitUsage, got.stderr)
		}
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a usage error wrote the page")
	}
}

func TestHTMLGolden(t *testing.T) {
	dir := example(t)
	facts := filepath.Join(dir, "facts.json")
	a, b := filepath.Join(t.TempDir(), "a.html"), filepath.Join(t.TempDir(), "b.html")
	plain := run(t, raw("--root", dir, "--facts", facts))
	for _, p := range []string{a, b} {
		got := run(t, raw("--root", dir, "--facts", facts, "--html", p))
		if got.code != plain.code || got.stdout != plain.stdout {
			t.Fatalf("--html changed the run: %d %q", got.code, got.stderr)
		}
	}
	pa, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pa, pb) {
		t.Error("two runs wrote different pages")
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, pageData(t, pa), "", "  "); err != nil {
		t.Fatal(err)
	}
	golden(t, "reportview-all-rules.golden.json", buf.String()+"\n")
}

func TestHTMLStdin(t *testing.T) {
	out := filepath.Join(t.TempDir(), "view.html")
	src := "on: issues\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Greet\n        run: echo \"${{ github.event.issue.title }}\"\n"
	e := raw("--stdin-name", ".github/workflows/w.yml", "--html", out)
	e.Stdin = strings.NewReader(src)
	run(t, e)
	page, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if d := pageData(t, page); !bytes.Contains(d, []byte(`"job":"build","step":"Greet"`)) {
		t.Errorf("no job and step in %s", d)
	}
}

// interrupter cancels a run once it says it serves, as an interrupt would.
type interrupter struct {
	bytes.Buffer
	cancel func()
}

func (w *interrupter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if strings.Contains(w.String(), "serving the report view at") {
		w.cancel()
	}
	return n, err
}

func TestServeStops(t *testing.T) {
	dir := example(t)
	facts := filepath.Join(dir, "facts.json")
	plain := run(t, raw("--root", dir, "--facts", facts))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	errOut := &interrupter{cancel: cancel}
	code := Main(ctx, Env{Args: []string{"--root", dir, "--facts", facts, "--serve"}, Getenv: func(string) string { return "" }, Stdin: strings.NewReader(""), Stdout: &out, Stderr: errOut})
	if code != plain.code || out.String() != plain.stdout {
		t.Errorf("code %d, want %d\n%s", code, plain.code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "serving the report view at http://127.0.0.1:") {
		t.Errorf("stderr %q", errOut.String())
	}
}

func TestServePortInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := run(t, raw("--root", example(t), "--serve="+ln.Addr().String()))
	if got.code != ExitIO || !strings.Contains(got.stderr, "--serve:") {
		t.Errorf("%d %q", got.code, got.stderr)
	}
}
