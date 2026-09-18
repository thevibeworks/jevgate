package main

import (
	"regexp"
	"strings"
)

// The policy is the half of the gate that needs no model. It sorts a shell
// command into one of three tiers:
//
//	Proven   every simple command is a listed read-only verb with none of
//	         its writing flags. Runs without asking, no network call.
//	Refused  code can prove a reason to ask: a redirect, an expansion, a
//	         path-qualified verb, a writing flag, a wrapper, a known writer
//	         (rm, kill, curl), a credential.
//	         The model is never consulted; nothing it says could help.
//	Unknown  the only objection is a verb or subcommand the list has never
//	         heard of. This is the residue a judgment can settle.
//
// The allowlist is mingo's (github.com/lroolle/mingo, autoRun), hardened by
// two reviews; every hole they found is a test here. A missing entry costs
// one prompt, a wrong entry costs trust, so every doubt is a refusal.

type Tier int

const (
	Refused Tier = iota
	Unknown
	Proven
)

func (t Tier) String() string { return [...]string{"refused", "unknown", "proven"}[t] }

var autoRunVerbs = map[string]bool{
	"ls": true, "cat": true, "head": true, "tail": true, "grep": true, "rg": true, "find": true, "fd": true,
	"wc": true, "echo": true, "printf": true, "pwd": true, "which": true, "file": true, "stat": true, "du": true, "df": true,
	"tree": true, "date": true, "uname": true, "sort": true, "uniq": true, "cut": true, "tr": true, "jq": true,
	"diff": true, "true": true, "false": true, "test": true, "basename": true, "dirname": true, "realpath": true, "readlink": true,
	"type": true, "id": true, "whoami": true, "hostname": true, "nl": true, "column": true,
	// Not in mingo's list, added because real agent traffic is made of them
	// (see EVAL.md): cd only moves a subshell, and a path-qualified verb is
	// refused whatever the directory; sleep waits. sed is below.
	"cd": true, "sleep": true,
}

// sedPrint is the one sed script provably read-only: print a line range
// under -n. Everything else in sed's language can write (w), execute (e)
// or edit in place, and goes to the model like any unlisted verb.
var sedPrint = regexp.MustCompile(`^(\d+|\$)(,(\d+|\$))?p$`)

func sedIsPrint(args []string) bool {
	script := false
	for _, a := range args {
		switch {
		case a == "-n":
		case strings.HasPrefix(a, "-"):
			return false
		case !script:
			if !sedPrint.MatchString(a) {
				return false
			}
			script = true
		}
	}
	return script && len(args) > 0 && args[0] == "-n"
}

var autoRunSub = map[string]map[string]bool{
	"git": {"status": true, "log": true, "diff": true, "show": true, "branch": true, "blame": true, "ls-files": true,
		"rev-parse": true, "remote": true, "tag": true, "describe": true, "shortlog": true, "grep": true, "cat-file": true},
	"go":     {"version": true, "env": true, "list": true, "vet": true, "build": true, "doc": true},
	"cargo":  {"check": true, "metadata": true, "tree": true},
	"npm":    {"ls": true, "view": true, "outdated": true},
	"docker": {"ps": true, "images": true, "logs": true, "inspect": true},
}

// autoRunDeny lists the flags that turn a listed verb into a writer or a
// launcher: find -delete, sort -o, go env -w, go build -o, git --output.
// git -c and --exec-path run configured programs (core.fsmonitor, pagers);
// they are here, not left to the model, because it is flag lore and flag
// lore is where the model measured weakest.
var autoRunDeny = map[string][]string{
	"find": {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls", "-fprint0"},
	"fd":   {"-x", "--exec", "-X", "--exec-batch"},
	"rg":   {"--pre"},
	"sort": {"-o", "--output"},
	"tree": {"-o"},
	"date": {"-s", "--set"},
	"git":  {"--output", "-c", "--exec-path", "--config-env"},
	"go":   {"-o", "-w", "-exec", "-toolexec"},
}

// autoRunNoArgs are subcommands that list when bare and create, delete or
// rename when given a name.
var autoRunNoArgs = map[string]bool{"git branch": true, "git tag": true, "git remote": true, "hostname": true}

// autoRunMaxFiles caps the operands of verbs whose second operand is an
// output file: uniq in out.
var autoRunMaxFiles = map[string]int{"uniq": 1}

// wrappers run the command named by their operands. What follows them is
// the real verb, so an unknown-verb judgment about "env" or "timeout"
// would be a judgment about the wrong word.
var wrappers = map[string]bool{
	"env": true, "nice": true, "ionice": true, "timeout": true, "nohup": true, "stdbuf": true, "watch": true,
	"time": true, "command": true, "builtin": true, "busybox": true, "setsid": true, "chroot": true, "unshare": true,
	"parallel": true, "flock": true, "script": true, "strace": true, "ltrace": true, "sh": true, "bash": true, "zsh": true,
	"dash": true, "ksh": true, "fish": true, "ssh": true,
}

// writers change the machine or talk to the network by design. Whether
// "kill" mutates is not a judgment, so the model is never given a vote: on
// real traffic it scored `kill 370105` at 0.25, a hair over the line.
var writers = map[string]bool{
	"rm": true, "rmdir": true, "mv": true, "cp": true, "ln": true, "mkdir": true, "touch": true, "chmod": true, "chown": true,
	"chgrp": true, "tee": true, "dd": true, "truncate": true, "shred": true, "install": true, "mkfifo": true, "mktemp": true,
	"kill": true, "pkill": true, "killall": true, "reboot": true, "shutdown": true, "systemctl": true, "service": true,
	"mount": true, "umount": true, "crontab": true, "at": true,
	"curl": true, "wget": true, "nc": true, "ncat": true, "scp": true, "sftp": true, "rsync": true, "ftp": true, "telnet": true,
}

var (
	shellOps         = regexp.MustCompile("\\$[A-Za-z_{(]|`|<\\(|>\\(|>|\\bxargs\\b|\\bsudo\\b|\\bdoas\\b|\\bsu\\b|\\beval\\b|\\bexec\\b")
	harmlessRedirect = regexp.MustCompile(`\d*>&\d|\d*>\s*/dev/null`)
	assignmentRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	assignDeny       = regexp.MustCompile(`^(PATH|LD_[A-Z_]*|DYLD_[A-Z_]*|GIT_[A-Z_]*|GO[A-Z]*|BASH_ENV|ENV|IFS)=`)

	// credential matches text that names or looks like a secret. Such a
	// command is never sent anywhere: the gate steps aside and the user is
	// asked, exactly as if jevgate were not installed.
	credential = regexp.MustCompile(`(?i)(api[_-]?key|secret|passw(or)?d|token|credential|private[_-]?key)[A-Za-z0-9_]*["']?\s*[=:]\s*["']?[^\s"']{8,}|` +
		`(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}|` +
		`\b(ghp|gho|ghs|ghu|github_pat|sk|pk|rk|xox[abpr]|glpat|npm|hf|AKIA|ASIA)[_-]?[A-Za-z0-9_-]{16,}|` +
		`-----BEGIN [A-Z ]*PRIVATE KEY|\b[A-Za-z0-9+=_]{48,}\b|://[^/\s:@]+:[^/\s@]+@`)
)

// maxCommand bounds what is judged at all. A longer command is a program,
// and a program deserves a reader.
const maxCommand = 2000

// Classify sorts cmd into a tier and says why, in words a person can read
// in a permission log.
func Classify(cmd string) (Tier, string) {
	cmd = strings.TrimSpace(cmd)
	switch {
	case cmd == "":
		return Refused, "empty command"
	case len(cmd) > maxCommand:
		return Refused, "too long to judge"
	case strings.ContainsRune(cmd, 0):
		return Refused, "NUL byte"
	}
	for _, r := range cmd {
		if r > 0x7e || (r < 0x20 && r != '\n' && r != '\t') {
			return Refused, "non-ASCII or control character: a lookalike can hide a verb"
		}
	}
	cmd = harmlessRedirect.ReplaceAllString(cmd, " ")
	if m := shellOps.FindString(cmd); m != "" {
		return Refused, "shell feature " + strings.TrimSpace(m) + ": what runs cannot be read from the text"
	}
	if strings.Contains(cmd, "<<") {
		return Refused, "here-document: the body is a program"
	}
	segments, ok := shellSplit(cmd)
	if !ok {
		return Refused, "unterminated quote or trailing backslash"
	}
	var unknown []string
	for _, fields := range segments {
		for len(fields) > 0 && assignmentRe.MatchString(fields[0]) {
			if assignDeny.MatchString(fields[0]) {
				return Refused, "assignment " + strings.SplitN(fields[0], "=", 2)[0] + " changes what a verb resolves to"
			}
			fields = fields[1:]
		}
		if len(fields) == 0 {
			return Refused, "empty simple command (a stray & ; or |)"
		}
		verb, args := fields[0], fields[1:]
		if strings.Contains(verb, "/") {
			return Refused, "path-qualified verb " + verb + " is not provably the system tool"
		}
		if wrappers[verb] {
			return Refused, verb + " runs whatever its operands name"
		}
		if writers[verb] {
			return Refused, verb + " writes, kills or uses the network by design"
		}
		for _, f := range args {
			if strings.HasPrefix(f, "-") && strings.ContainsAny(f, "*?[") {
				return Refused, "glob in a flag can expand to a writing flag"
			}
			if deniedFlag(f, autoRunDeny[verb]) {
				return Refused, verb + " " + f + " writes or launches"
			}
		}
		key, rest := verb, args
		if subs, ok := autoRunSub[verb]; ok {
			sub, at := "", -1
			for i, f := range args {
				if !strings.HasPrefix(f, "-") {
					sub, at = f, i
					break
				}
			}
			if !subs[sub] {
				unknown = append(unknown, strings.TrimSpace(verb+" "+sub))
				continue
			}
			key, rest = verb+" "+sub, args[at+1:]
		} else if verb == "sed" && sedIsPrint(args) {
			continue
		} else if !autoRunVerbs[verb] {
			unknown = append(unknown, verb)
			continue
		}
		files := 0
		for _, f := range rest {
			if !strings.HasPrefix(f, "-") {
				files++
			}
		}
		if autoRunNoArgs[key] && files > 0 {
			return Refused, key + " with a name creates, deletes or renames"
		}
		if n, ok := autoRunMaxFiles[verb]; ok && files > n {
			return Refused, verb + " with a second operand writes it"
		}
		if verb == "date" && files > 0 && !strings.HasPrefix(rest[0], "+") {
			return Refused, "date with an operand sets the clock"
		}
	}
	if len(unknown) > 0 {
		if credential.MatchString(cmd) {
			return Refused, "may carry a credential: not sent anywhere"
		}
		return Unknown, "unlisted: " + strings.Join(unknown, ", ")
	}
	return Proven, "every verb is a listed read-only tool"
}

// shellSplit cuts a command into simple commands and each of those into
// words the way sh would, honouring single quotes, double quotes and
// backslashes, and nothing more: expansions were refused before this runs,
// so what the shell would execute is exactly what is returned. ok is false
// on an unterminated quote or a trailing backslash.
func shellSplit(cmd string) (segments [][]string, ok bool) {
	var seg []string
	var cur []rune
	inWord := false
	flush := func() {
		if inWord {
			seg = append(seg, string(cur))
			cur, inWord = nil, false
		}
	}
	rs := []rune(cmd)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '\\':
			if i+1 >= len(rs) {
				return nil, false
			}
			i++
			cur = append(cur, rs[i])
			inWord = true
		case c == '\'':
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				j++
			}
			if j >= len(rs) {
				return nil, false
			}
			cur = append(cur, rs[i+1:j]...)
			i, inWord = j, true
		case c == '"':
			j := i + 1
			for ; j < len(rs) && rs[j] != '"'; j++ {
				if rs[j] == '\\' && j+1 < len(rs) && strings.ContainsRune("\"\\$`", rs[j+1]) {
					j++
				}
				cur = append(cur, rs[j])
			}
			if j >= len(rs) {
				return nil, false
			}
			i, inWord = j, true
		case c == '|' || c == '&' || c == ';' || c == '\n' || c == '(' || c == ')':
			flush()
			segments = append(segments, seg)
			seg = nil
			if i+1 < len(rs) && (c == '|' || c == '&') && rs[i+1] == c {
				i++
			}
		case c == ' ' || c == '\t' || c == '\r':
			flush()
		default:
			cur = append(cur, c)
			inWord = true
		}
	}
	flush()
	return append(segments, seg), true
}

// deniedFlag reports whether a word is one of a verb's writing flags,
// after quoting was removed: the flag itself, --flag=value, a short flag
// with its value attached (-oout), or a short flag inside a cluster (-ro).
func deniedFlag(word string, deny []string) bool {
	for _, d := range deny {
		if word == d || strings.HasPrefix(word, d+"=") {
			return true
		}
		if len(d) == 2 && strings.HasPrefix(word, "-") && !strings.HasPrefix(word, "--") && strings.ContainsRune(word[1:], rune(d[1])) {
			return true
		}
	}
	return false
}
