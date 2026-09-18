// jevgate decides which shell commands an AI agent may run without asking.
//
//	jevgate check 'git stash list'     verdict and reason; exit 0 allow, 1 ask
//	jevgate hook                       Claude Code PreToolUse hook (stdin/stdout)
//	jevgate log [-n 20]                what it let through, and why
//	jevgate eval [-report]             reproduce the published measurement
//
// An allowlist proves what it can. Code refuses what it can prove unsafe to
// guess at. Only the rest, commands whose one fault is an unfamiliar verb,
// goes to Jev, a model that cannot generate text and answers five yes/no
// questions with probabilities. The gate can allow or step aside. It cannot
// block: your agent's own permission prompt does that.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var version = "dev"

// budget is the longest the gate may hold a terminal. Past it, step aside.
const budget = 4 * time.Second

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "check":
		os.Exit(check(os.Args[2:]))
	case "hook":
		hook(os.Stdin, os.Stdout)
	case "log":
		os.Exit(showLog(os.Args[2:]))
	case "eval":
		os.Exit(eval(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("jevgate", version, defaultModel, "t="+fmt.Sprint(Threshold))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `jevgate: which shell commands may an agent run without asking?

  jevgate check [-json] 'command'   exit 0 allow, 1 ask
  jevgate hook                      Claude Code PreToolUse hook
  jevgate log [-n 20]               recent decisions
  jevgate eval [-report] [-runs n]  reproduce the measurement (spends ~$0.005 a run)
  jevgate version

  TYPESAFE_API_KEY   without it only the allowlist tier works
  JEVGATE_LOG        decision log path, or "off" (default: state dir)
`)
}

// judgeFromEnv returns nil when there is no key: the gate then works as a
// plain allowlist and says so.
func judgeFromEnv() Judge {
	key := os.Getenv("TYPESAFE_API_KEY")
	if key == "" {
		return nil
	}
	c := &Client{
		Key:      key,
		Endpoint: envOr("JEVGATE_ENDPOINT", defaultEndpoint),
		Model:    envOr("JEVGATE_MODEL", defaultModel),
		HTTP:     &http.Client{Timeout: budget},
	}
	return c.Judge
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func check(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the verdict as JSON")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: jevgate check [-json] 'command'")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	v := Decide(ctx, fs.Arg(0), judgeFromEnv())
	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(v)
	} else {
		word := "ask  "
		if v.Allow {
			word = "allow"
		}
		fmt.Printf("%s  %s: %s\n", word, v.Tier, v.Reason)
		if v.Judgment != nil {
			for _, id := range []string{"mutates", "launches", "network", "opaque", "elevated"} {
				fmt.Printf("       %-9s %.2f\n", id, v.Judgment.Nouls[id])
			}
		}
	}
	if v.Allow {
		return 0
	}
	return 1
}

// hook speaks Claude Code's PreToolUse protocol. On allow it prints the
// decision. On anything else it prints nothing and exits 0, which Claude
// Code documents as "no decision; normal flow applies": the user's own
// rules and prompt run exactly as if jevgate were not installed. It never
// exits non-zero, because exit 2 would block the tool.
func hook(in io.Reader, out io.Writer) {
	var ev struct {
		Tool  string `json:"tool_name"`
		Cwd   string `json:"cwd"`
		Input struct {
			Command string `json:"command"`
		} `json:"tool_input"`
	}
	raw, err := io.ReadAll(io.LimitReader(in, 1<<20))
	if err != nil || json.Unmarshal(raw, &ev) != nil || ev.Tool != "Bash" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	v := Decide(ctx, ev.Input.Command, judgeFromEnv())
	record(ev.Input.Command, ev.Cwd, v)
	if !v.Allow {
		return
	}
	json.NewEncoder(out).Encode(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "allow",
			"permissionDecisionReason": "jevgate: " + v.Reason,
		},
	})
}

// --- the decision log: an auto-approver without a record is a rumour

func logPath() string {
	if p := os.Getenv("JEVGATE_LOG"); p != "" {
		if p == "off" {
			return ""
		}
		return p
	}
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "jevgate", "decisions.jsonl")
}

type entry struct {
	Time    string  `json:"time"`
	Allow   bool    `json:"allow"`
	Tier    string  `json:"tier"`
	Risk    float64 `json:"risk,omitempty"`
	Reason  string  `json:"reason"`
	Cwd     string  `json:"cwd,omitempty"`
	Command string  `json:"command"`
}

// record appends one line. The log stays on this machine, is mode 0600,
// and failing to write it never changes a decision.
func record(cmd, cwd string, v Verdict) {
	p := logPath()
	if p == "" {
		return
	}
	if os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	line, _ := json.Marshal(entry{time.Now().UTC().Format(time.RFC3339), v.Allow, v.Tier, v.Risk, v.Reason, cwd, cmd})
	f.Write(append(line, '\n'))
}

func showLog(args []string) int {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	n := fs.Int("n", 20, "how many recent decisions")
	fs.Parse(args)
	p := logPath()
	f, err := os.Open(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, "no decisions yet at", p)
		return 1
	}
	defer f.Close()
	var lines []entry
	allowed, asked := 0, 0
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var e entry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		if e.Allow {
			allowed++
		} else {
			asked++
		}
		lines = append(lines, e)
	}
	if len(lines) > *n {
		lines = lines[len(lines)-*n:]
	}
	for _, e := range lines {
		word := "ask  "
		if e.Allow {
			word = "allow"
		}
		fmt.Printf("%s %s %-7s %s\n      %s\n", e.Time, word, e.Tier, oneLine(e.Command, 100), e.Reason)
	}
	fmt.Printf("\n%d allowed, %d left to you, in %s\n", allowed, asked, p)
	return 0
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n-3] + "..."
	}
	return s
}
