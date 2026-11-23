package workflow

import "testing"

func TestPermissions(t *testing.T) {
	for _, tt := range []struct {
		perm   string
		all    string
		scopes int
		want   []Code
	}{
		{"read-all", "read-all", 0, nil},
		{"write-all", "write-all", 0, nil},
		{"{}", "", 0, nil},
		{"{contents: read, id-token: write}", "", 2, nil},
		{"{models: read, vulnerability-alerts: none, copilot-requests: write}", "", 3, nil},
		// id-token is write or none only.
		{"{id-token: read}", "", 1, []Code{InvalidValue}},
		{"{contents: admin}", "", 1, []Code{InvalidValue}},
		{"{content: read}", "", 0, []Code{UnknownKey}},
		{"read", "", 0, []Code{InvalidValue}},
		// permissions has no context.
		{"${{ x }}", "", 0, []Code{ExprNotAllowed}},
	} {
		for _, at := range []string{"workflow", "job"} {
			src := "on: push\npermissions: " + tt.perm + "\n" + jobsOK
			if at == "job" {
				src = "on: push\njobs:\n  a:\n    runs-on: x\n    permissions: " + tt.perm + "\n"
			}
			w, diags, _ := parse(t, src)
			wantCodes(t, src, diags, tt.want...)
			f := w.Permissions
			if at == "job" {
				f = w.Jobs.Value.Entries[0].Value.Value.Permissions
			}
			if f.Value.All.Text() != tt.all || len(f.Value.Scopes) != tt.scopes {
				t.Errorf("%s %s: all %q, %d scopes", at, tt.perm, f.Value.All.Text(), len(f.Value.Scopes))
			}
		}
	}
}

func TestPermissionScope(t *testing.T) {
	src := "on: push\npermissions:\n  pull-requests: write\n" + jobsOK
	w, _, _ := parse(t, src)
	s := w.Permissions.Value.Scopes[0]
	if s.Name.Text() != "pull-requests" || s.Access.Text() != "write" || text(src, s.Access.Node.ContentSpan()) != "write" {
		t.Errorf("scope = %+v", s)
	}
}
