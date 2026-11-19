package workflow

import "testing"

// TestContainer: the string form and the mapping, of a
// job's container and of its services.
func TestContainer(t *testing.T) {
	w, _, _ := parse(t, `on: push
jobs:
  a:
    runs-on: x
    container:
      image: ghcr.io/o/build:1
      credentials:
        username: u
        password: hunter2
    services:
      redis: redis
      db:
        image: postgres:16
        credentials: {username: u, password: '${{ secrets.DB }}'}
    steps:
      - run: echo
  b:
    runs-on: x
    container: node:18
    steps:
      - run: echo
  c:
    runs-on: x
    container: ${{ matrix.image }}
    strategy:
      matrix: {image: [a, b]}
    steps:
      - run: echo
`)
	a, b, c := w.Jobs.Value.Entries[0].Value.Value, w.Jobs.Value.Entries[1].Value.Value, w.Jobs.Value.Entries[2].Value.Value
	if a.Container.Status != Present || a.Container.Value.Image.Value.Text() != "ghcr.io/o/build:1" ||
		a.Container.Value.Username.Value.Text() != "u" || a.Container.Value.Password.Value.Text() != "hunter2" {
		t.Errorf("a: %+v", a.Container)
	}
	if a.Services.Status != Present || len(a.Services.Value.Entries) != 2 {
		t.Fatalf("a's services: %+v", a.Services)
	}
	redis, db := a.Services.Value.Entries[0].Value.Value, a.Services.Value.Entries[1].Value.Value
	if redis.Image.Value.Text() != "redis" || redis.Password.Status != Absent {
		t.Errorf("redis: %+v", redis)
	}
	if db.Image.Value.Text() != "postgres:16" || db.Password.Value.Parts == nil {
		t.Errorf("db: %+v", db)
	}
	if b.Container.Status != Present || b.Container.Value.Image.Value.Text() != "node:18" || b.Services.Status != Absent {
		t.Errorf("b: %+v", b.Container)
	}
	if c.Container.Status != Present || c.Container.Value.Image.Value.Parts == nil {
		t.Errorf("c: %+v", c.Container)
	}
}

// TestContainerUnknownKey: a key the schema does not have in a container
// is reported now that the model reads it.
func TestContainerUnknownKey(t *testing.T) {
	_, diags, _ := parse(t, "on: push\njobs:\n  a:\n    runs-on: x\n    container:\n      image: a\n      imagee: b\n    steps:\n      - run: echo\n")
	if len(diags) != 1 || diags[0].Code != UnknownKey {
		t.Errorf("%+v", diags)
	}
}

// TestContainerEnv: the env of a job's container and of a service, which
// env-var reads.
func TestContainerEnv(t *testing.T) {
	w, _, _ := parse(t, `on: push
jobs:
  a:
    runs-on: x
    container:
      image: alpine
      env:
        "A=B": x
    services:
      db:
        image: postgres:16
        env: {GITHUB_SHA: y}
    steps:
      - run: echo
`)
	a := w.Jobs.Value.Entries[0].Value.Value
	env := a.Container.Value.Env
	if env.Status != Present || len(env.Value.Entries) != 1 || env.Value.Entries[0].Key.AsString() != "A=B" {
		t.Errorf("the container's env: %+v", env)
	}
	db := a.Services.Value.Entries[0].Value.Value
	if db.Env.Status != Present || db.Env.Value.Entries[0].Key.AsString() != "GITHUB_SHA" {
		t.Errorf("the service's env: %+v", db.Env)
	}
}
