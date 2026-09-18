package main

import (
	"strings"
	"testing"
)

// mingo's TestAutoRunAllowlist at 138a313, verbatim. Every entry in no was
// a hole a review found; the list must stay adversarial. Proven is the only
// tier that runs with nobody looking, so it is the one held to this.
func TestProvenIsExactlyTheAllowlist(t *testing.T) {
	yes := []string{
		"ls -la", "cat a.go | grep foo", "git status && git diff --stat", "go build ./... ; go vet ./...",
		"find . -name '*.go' | wc -l", "FOO=1 grep -r x .", "git log --oneline -5", "docker ps",
		"go vet ./... 2>&1", "go build ./... 2>/dev/null", "git branch --show-current", "git branch -a",
		"git tag", "git remote -v", "hostname -f", "date -u", "rg -n foo", "find . -type f -newer x",
		"cat a.go\ncat b.go", "grep -o pattern file", "sort -r file", "tree -L 2",
		"grep 'foo|bar' a.go", `grep -E "a b" x`, "find . -name '*.go' -newer x", "grep 'end$' f", `echo "it's"`,
		"uniq input", "date '+%Y'", "sort -k2 -n file", "grep -e '-delete' log",
	}
	no := []string{
		"", "rm -rf x", "cat a > b", "git commit -m x", "go test ./...", "ls $(echo x)", "echo `id`",
		"find . | xargs rm", "sudo ls", "git push", "npm install", "python3 x.py", "go run .", "sed -i s/a/b/ f",
		"ls; make", "git status | tee out", "eval ls", "exec ls", "su -c ls", "doas ls",
		"find . -name victim -delete", "find . -exec rm {} \\;", "go fmt ./...", "git branch -D victim",
		"git branch -m old new", "sort -o victim input", "./cat", "/bin/ls", "echo safe\ntouch marker",
		"echo safe & touch marker", "cat a.go &", "PATH=/tmp/evil cat x", "LD_PRELOAD=x.so ls",
		"GOFLAGS=-toolexec=evil go build ./...", "go env -w GOFLAGS=x", "go build -o /usr/local/bin/x .",
		"git tag v1", "git tag -d v1", "git remote add x url", "hostname evil", "date -s now",
		"tree -o out.txt", "rg --pre evil x", "fd -x rm", "git log --output=f",
		"ls >&2 && touch x", "cat a 2>&1 > b", "(cd x && rm y)", "ls | cat > out",
		"find . -name victim '-delete'", `find . -name victim "-delete"`, "find . -name victim -del\\ete",
		"sort -oout input", "sort -ro out input", "uniq input output", "go build -ox .",
		"X=-delete find . $X", "find . ${F}", "find . -dele*", "date 0913120026", "grep 'unterminated",
	}
	for _, c := range yes {
		if tier, why := Classify(c); tier != Proven {
			t.Errorf("%q should be proven, got %s: %s", c, tier, why)
		}
	}
	for _, c := range no {
		if tier, _ := Classify(c); tier == Proven {
			t.Errorf("%q must NOT be proven", c)
		}
	}
}

// What code can prove is refused in code. The model is never asked about
// these, so nothing it says, and nothing the command says to it, matters.
func TestRefusedNeverReachesTheModel(t *testing.T) {
	cases := map[string]string{
		"cat a > b":                         "shell feature",
		"ls $(echo x)":                      "shell feature",
		"echo `id`":                         "shell feature",
		"find . | xargs rm":                 "shell feature",
		"sudo ls":                           "shell feature",
		"./cat":                             "path-qualified",
		"/bin/ls":                           "path-qualified",
		"PATH=/tmp/evil cat x":              "assignment PATH",
		"LD_PRELOAD=x.so ls":                "assignment LD_PRELOAD",
		"find . -name victim -delete":       "writes or launches",
		"rg --pre evil x":                   "writes or launches",
		"git -c core.fsmonitor=evil status": "writes or launches",
		"git --exec-path=/tmp/evil status":  "shell feature exec", // the word alone is enough
		"find . -dele*":                     "glob in a flag",
		"grep 'unterminated":                "unterminated",
		"cat a.go &":                        "empty simple command",
		"(cd x && rm y)":                    "empty simple command",
		"env rm x":                          "env runs",
		"timeout 5 rm x":                    "timeout runs",
		"nohup make":                        "nohup runs",
		"bash -c 'rm x'":                    "bash runs",
		"ssh host ls":                       "ssh runs",
		"rm -rf x":                          "by design",
		"kill 370105; echo killed":          "by design",
		"curl -s https://example.com":       "by design",
		"ls && cp a b":                      "by design",
		"python3 - <<EOF\nprint(1)\nEOF":    "here-document",
		"ls рm":                             "non-ASCII", // Cyrillic er
		"echo hi\x1b[2K":                    "control character",
		strings.Repeat("ls ", 900):          "too long",
	}
	for cmd, want := range cases {
		tier, why := Classify(cmd)
		if tier != Refused || !strings.Contains(why, want) {
			t.Errorf("%q: want refused (%s), got %s: %s", oneLine(cmd, 40), want, tier, why)
		}
	}
}

// Unknown is the only tier the model sees: nothing wrong with the command
// except a verb the list has never heard of.
func TestUnknownIsOnlyAnUnlistedVerb(t *testing.T) {
	for cmd, want := range map[string]string{
		"git stash list":             "git stash",
		"ps aux":                     "ps",
		"awk '{print $1}' log":       "awk",
		"python3 --version":          "python3",
		"make":                       "make",
		"go test ./...":              "go test",
		"cd x && npm install":        "npm install",
		"sed -i s/a/b/ f":            "sed",
		"ls | less +'!rm f' f":       "less",
		"git -C sub status":          "git sub",
		"sqlite3 db 'select 1'":      "sqlite3",
		"ls; make; git push":         "make, git push",
		"tar -tf release.tar | head": "tar",
	} {
		tier, why := Classify(cmd)
		if tier != Unknown || why != "unlisted: "+want {
			t.Errorf("%q: want unknown (%s), got %s: %s", cmd, want, tier, why)
		}
	}
}

// The three additions to mingo's list, and the ways each could be abused.
func TestAdditionsToTheAllowlist(t *testing.T) {
	proven := []string{
		"cd /tmp && ls -la | head", "cd a/b && git status && git diff --stat", "sleep 5; tail -3 build.log",
		"sed -n '10,20p' main.go", "sed -n 5p a b", "cd x && sed -n 1,80p f | grep -n foo",
	}
	notProven := []string{
		"sed '1,5p' f",          // no -n
		"sed -n '1,5p;w out' f", // w writes
		"sed -n '1e rm x' f",    // e executes
		"sed -n -i 1p f",        // in place
		"sed -ni 1p f",          // clustered in place
		"sed -n -f script f",    // script from a file
		"sed -n --in-place 1p f",
		"sed 1p -n f", // -n must lead: keep the shape one thing
		// The expansion check reads text, not quoting, so a quoted $p is
		// refused too. That costs a prompt; knowing sh's quoting rules
		// well enough to be sure would cost more than it saves.
		"sed -n '$p' f",
		"cd x && rm y",
		"cd $HOME",
	}
	for _, c := range proven {
		if tier, why := Classify(c); tier != Proven {
			t.Errorf("%q should be proven, got %s: %s", c, tier, why)
		}
	}
	for _, c := range notProven {
		if tier, _ := Classify(c); tier == Proven {
			t.Errorf("%q must NOT be proven", c)
		}
	}
}

// A command that may carry a secret is never sent to a third party. It is
// refused in code, which costs one prompt and leaks nothing.
func TestCredentialsStayHome(t *testing.T) {
	leaky := []string{
		"gh api -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123' /user",
		"API_KEY=sk-live-abcdefghijklmnop python3 run.py",
		"mytool --token=abcdefgh12345678",
		"mytool login --password: hunter2hunter2",
		"psql postgres://admin:hunter2@db.internal/app -c 'select 1'",
		"mytool push gh" + "p_abcdefghijklmnopqrstuvwxyz0123456789", // split so no scanner mistakes the fixture for a leak
		"mytool --key AK" + "IAIOSFODNN7EXAMPLEKEY",
		"mytool verify 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
	}
	for _, c := range leaky {
		if tier, why := Classify(c); tier != Refused || !strings.Contains(why, "credential") {
			t.Errorf("%q must be refused as a credential, got %s: %s", c, tier, why)
		}
	}
	// Talking about secrets is not carrying one, and a long path is not a key.
	fine := []string{
		"ps aux | grep -c token",
		"awk '/secret/{print FILENAME}' notes.md",
		"pgrep -af password-manager",
		"python3 /Users/someone/work/src/github.com/an-organisation/a-repository/tools/count_tokens.py --help",
	}
	for _, c := range fine {
		if tier, why := Classify(c); tier != Unknown {
			t.Errorf("%q should reach the model, got %s: %s", c, tier, why)
		}
	}
}

func TestShellSplit(t *testing.T) {
	segs, ok := shellSplit(`a 'b c' "d \"e" f\ g | h && i; j`)
	if !ok || len(segs) != 4 {
		t.Fatalf("got %v %v", segs, ok)
	}
	if got := strings.Join(segs[0], ","); got != `a,b c,d "e,f g` {
		t.Fatalf("first segment: %q", got)
	}
	for _, bad := range []string{`a 'b`, `a "b`, `a \`} {
		if _, ok := shellSplit(bad); ok {
			t.Errorf("%q must not split", bad)
		}
	}
}

func BenchmarkClassify(b *testing.B) {
	cmds := []string{"ls -la", "cd a && git status && git diff --stat | head -40", "find . -name victim -delete", "ps aux | grep foo"}
	for i := 0; i < b.N; i++ {
		Classify(cmds[i%len(cmds)])
	}
}
