package shell

import "strings"

// RemoteKind is where the program of an option of git that runs on the
// remote side (--upload-pack) runs, by the repository the command names.
// git's documentation says the program runs on the remote host for an
// SSH remote
// (https://github.com/git/git/blob/c44beea485f0f2feaf460e2ac87fdd5608d63cf0/Documentation/git-ls-remote.adoc);
// on a runner, the program ran on the runner for a repository on a local
// path, and git did not use the program for an HTTPS remote.
type RemoteKind uint8

const (
	RemoteKindUnknown RemoteKind = iota // not a literal, the name of a remote (origin), or another protocol (http://, git://)
	RemoteKindLocal                     // a path: /, ./, ../, ~, file://, . or ..
	RemoteKindHTTPS                     // https://
	RemoteKindSSH                       // ssh://, git+ssh://, ssh+git://, or [user@]host:path
)

var remoteKindNames = [...]string{"RemoteKindUnknown", "RemoteKindLocal", "RemoteKindHTTPS", "RemoteKindSSH"}

func (k RemoteKind) String() string { return remoteKindNames[k] }

// RemoteKindOf is the RemoteKind of text, a repository git names: a path
// is local, and a : before the first / makes the scp-like form of SSH.
func RemoteKindOf(text string) RemoteKind {
	switch {
	case len(text) >= 3 && isDriveLetter(text[0]) && text[1] == ':' && (text[2] == '/' || text[2] == '\\'):
		return RemoteKindLocal // a path of a Windows runner: C:/r
	case text == "." || text == "..", strings.HasPrefix(text, "/"), strings.HasPrefix(text, "./"), strings.HasPrefix(text, "../"), strings.HasPrefix(text, "~"), strings.HasPrefix(text, "file://"):
		return RemoteKindLocal
	case strings.HasPrefix(text, "https://"):
		return RemoteKindHTTPS
	case strings.HasPrefix(text, "ssh://"), strings.HasPrefix(text, "git+ssh://"), strings.HasPrefix(text, "ssh+git://"):
		return RemoteKindSSH
	case strings.Contains(text, "://"), strings.Contains(text, "::"):
		return RemoteKindUnknown // another protocol, or a remote helper (ext::)
	}
	if c := strings.IndexByte(text, ':'); c > 0 && (strings.IndexByte(text, '/') < 0 || c < strings.IndexByte(text, '/')) {
		return RemoteKindSSH
	}
	return RemoteKindUnknown
}

func isDriveLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// FirstOperand is the index of the word that may be the first operand of
// the command of words, after its name and subcommands: a word read as an
// operand, or a word at the place of options whose text does not begin
// with - or is not known, but not a word skip says is an option (an
// attacker's value in one word, which begins with - to do harm). It is
// false when there is none, or when a word after an option the table does
// not declare comes first.
func (r CommandRoles) FirstOperand(words []CommandWord, skip func(int) bool) (int, bool) {
	for i, w := range words {
		switch r.Roles[i] {
		case ArgumentRoleCommand, ArgumentRoleOptionValue:
			continue
		case ArgumentRoleOperand:
			return i, true
		case ArgumentRoleOption:
			if skip(i) || w.Known && strings.HasPrefix(w.Text, "-") && w.Text != "-" {
				continue
			}
			return i, true
		default: // undecided or unread
			return 0, false
		}
	}
	return 0, false
}
