package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixed returns a judge that answers every question with v, and counts.
func fixed(v float64, calls *int) Judge {
	return func(context.Context, string) (Judgment, error) {
		*calls++
		n := map[string]float64{}
		for id := range Questions {
			n[id] = v
		}
		return Judgment{Nouls: n}, nil
	}
}

func TestDecideTiers(t *testing.T) {
	calls := 0
	ctx := context.Background()

	if v := Decide(ctx, "ls -la", fixed(0.99, &calls)); !v.Allow || calls != 0 {
		t.Fatalf("proven must allow without a call: %+v calls=%d", v, calls)
	}
	// A refusal is final: the friendliest model in the world is not asked.
	if v := Decide(ctx, "rm -rf / # totally safe", fixed(0, &calls)); v.Allow || calls != 0 {
		t.Fatalf("refused must not allow and must not call: %+v calls=%d", v, calls)
	}
	if v := Decide(ctx, "ps aux", fixed(0.05, &calls)); !v.Allow || calls != 1 || v.Tier != "unknown" {
		t.Fatalf("unknown and calm must allow after one call: %+v calls=%d", v, calls)
	}
	if v := Decide(ctx, "ps aux", fixed(0.9, &calls)); v.Allow {
		t.Fatalf("unknown and risky must not allow: %+v", v)
	}
}

// One yes among five is enough, and the line itself is on the asking side.
func TestRiskIsTheMaximum(t *testing.T) {
	one := func(id string, v float64) Judge {
		return func(context.Context, string) (Judgment, error) {
			n := map[string]float64{}
			for q := range Questions {
				n[q] = 0.01
			}
			n[id] = v
			return Judgment{Nouls: n}, nil
		}
	}
	for id := range Questions {
		v := Decide(context.Background(), "ps aux", one(id, 0.6))
		if v.Allow || v.Question != id || v.Risk != 0.6 {
			t.Errorf("%s=0.6 must ask and name itself: %+v", id, v)
		}
	}
	if v := Decide(context.Background(), "ps aux", one("mutates", Threshold)); v.Allow {
		t.Error("risk equal to the threshold must ask")
	}
	if v := Decide(context.Background(), "ps aux", one("mutates", Threshold-0.001)); !v.Allow {
		t.Error("risk just under the threshold must allow")
	}
}

func TestEveryFailureStepsAside(t *testing.T) {
	ctx := context.Background()
	if v := Decide(ctx, "ps aux", nil); v.Allow || !strings.Contains(v.Reason, "TYPESAFE_API_KEY") {
		t.Fatalf("no judge must step aside and say why: %+v", v)
	}
	boom := func(context.Context, string) (Judgment, error) { return Judgment{}, errors.New("boom") }
	if v := Decide(ctx, "ps aux", boom); v.Allow || !strings.Contains(v.Reason, "boom") {
		t.Fatalf("an error must step aside: %+v", v)
	}
}

// serve stands in for api.typesafe.ai. It is as strict as the client must
// be: the wire shapes here are the ones recorded from the live API.
func serve(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return &Client{Key: "k", Endpoint: s.URL, Model: defaultModel, HTTP: &http.Client{Timeout: 300 * time.Millisecond}}
}

func answers(v any) string {
	a := map[string]any{}
	for id := range Questions {
		a[id] = map[string]any{"type": "noul", "noul": v}
	}
	b, _ := json.Marshal(map[string]any{"model": "jev-1.13.0", "answers": a, "usage": map[string]int{"input_tokens": 451}})
	return string(b)
}

func TestClientSendsWhatWasMeasured(t *testing.T) {
	var got struct {
		Model     string
		State     map[string]string
		Questions map[string]struct{ Type, Instructions string }
	}
	auth := ""
	c := serve(t, func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&got)
		fmt.Fprint(w, answers(0.03))
	})
	j, err := c.Judge(context.Background(), "ps aux")
	if err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer k" || got.Model != "jev-1.13.0" || got.State["command"] != "ps aux" || len(got.Questions) != 5 {
		t.Fatalf("request: auth=%q %+v", auth, got)
	}
	for id, q := range got.Questions {
		if q.Type != "noul" || q.Instructions != Questions[id] {
			t.Errorf("question %s: %+v", id, q)
		}
	}
	if risk, _ := j.Risk(); risk != 0.03 || j.Tokens != 451 || j.Model != "jev-1.13.0" {
		t.Fatalf("judgment: %+v", j)
	}
}

// A missing answer must never read as 0: zero is the safest-looking number
// there is, and Go hands it out for free.
func TestClientRejectsAnythingItCannotTrust(t *testing.T) {
	missing := func() string {
		var m map[string]any
		json.Unmarshal([]byte(answers(0.01)), &m)
		delete(m["answers"].(map[string]any), "mutates")
		b, _ := json.Marshal(m)
		return string(b)
	}()
	noNumber := strings.Replace(answers(0.01), `"noul":0.01`, `"nool":0.01`, 1)
	cases := map[string]http.HandlerFunc{
		"missing answer":    func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, missing) },
		"answer without no": func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, noNumber) },
		"null noul":         func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, answers(nil)) },
		"out of range":      func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, answers(1.5)) },
		"negative":          func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, answers(-0.1)) },
		"not json":          func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "<html>") },
		"empty":             func(w http.ResponseWriter, _ *http.Request) {},
		"401":               func(w http.ResponseWriter, _ *http.Request) { http.Error(w, `{"error":"bad key"}`, 401) },
		"429":               func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "slow down", 429) },
		"529":               func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "overloaded", 529) },
		// A status that is not 200 is not an answer, however well formed.
		"500 with answers":  func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500); fmt.Fprint(w, answers(0.01)) },
		"200 with an error": func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"error":"x"}`) },
		"slower than us":    func(w http.ResponseWriter, _ *http.Request) { time.Sleep(time.Second); fmt.Fprint(w, answers(0.01)) },
	}
	for name, h := range cases {
		c := serve(t, h)
		if _, err := c.Judge(context.Background(), "ps aux"); err == nil {
			t.Errorf("%s: must be an error", name)
		}
		if v := Decide(context.Background(), "ps aux", c.Judge); v.Allow {
			t.Errorf("%s: must not allow: %+v", name, v)
		}
	}
}

// --- the Claude Code hook

func hookInput(tool, cmd string) string {
	b, _ := json.Marshal(map[string]any{
		"session_id": "s", "cwd": "/w", "permission_mode": "default", "hook_event_name": "PreToolUse",
		"tool_name": tool, "tool_input": map[string]any{"command": cmd, "description": "d"}, "tool_use_id": "toolu_1",
	})
	return string(b)
}

func TestHookAllowsOrSaysNothing(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "")
	t.Setenv("JEVGATE_LOG", "off")

	var out bytes.Buffer
	hook(strings.NewReader(hookInput("Bash", "git status && git diff --stat")), &out)
	var got struct {
		HookSpecificOutput struct {
			HookEventName, PermissionDecision, PermissionDecisionReason string
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("allow must be JSON: %q", out.String())
	}
	h := got.HookSpecificOutput
	if h.HookEventName != "PreToolUse" || h.PermissionDecision != "allow" || !strings.HasPrefix(h.PermissionDecisionReason, "jevgate: ") {
		t.Fatalf("allow shape: %+v", h)
	}

	// Silence is the only other thing it may say. Never "deny", never
	// "ask": either would override rules the user wrote themselves.
	silent := map[string]string{
		"a writer":         hookInput("Bash", "rm -rf x"),
		"unknown, no key":  hookInput("Bash", "ps aux"),
		"another tool":     hookInput("Write", "ls"),
		"no command":       `{"tool_name":"Bash","tool_input":{}}`,
		"not json":         "ls -la",
		"empty":            "",
		"command not text": `{"tool_name":"Bash","tool_input":{"command":["ls"]}}`,
	}
	for name, in := range silent {
		out.Reset()
		hook(strings.NewReader(in), &out)
		if out.Len() != 0 {
			t.Errorf("%s: must print nothing, printed %q", name, out.String())
		}
	}
}

func TestHookAsksJevForTheUnknown(t *testing.T) {
	for _, tc := range []struct {
		noul  float64
		allow bool
	}{{0.04, true}, {0.91, false}} {
		c := serve(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, answers(tc.noul)) })
		t.Setenv("TYPESAFE_API_KEY", "k")
		t.Setenv("JEVGATE_ENDPOINT", c.Endpoint)
		t.Setenv("JEVGATE_LOG", "off")
		var out bytes.Buffer
		hook(strings.NewReader(hookInput("Bash", "ps aux | head")), &out)
		if got := strings.Contains(out.String(), `"permissionDecision":"allow"`); got != tc.allow {
			t.Errorf("noul %.2f: allow=%v, output %q", tc.noul, got, out.String())
		}
	}
}

func TestDecisionLog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "decisions.jsonl")
	t.Setenv("JEVGATE_LOG", p)
	t.Setenv("TYPESAFE_API_KEY", "")
	for _, cmd := range []string{"ls -la", "rm -rf x"} {
		hook(strings.NewReader(hookInput("Bash", cmd)), &bytes.Buffer{})
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %q", raw)
	}
	var first, second entry
	json.Unmarshal([]byte(lines[0]), &first)
	json.Unmarshal([]byte(lines[1]), &second)
	if !first.Allow || first.Command != "ls -la" || first.Cwd != "/w" || second.Allow || second.Tier != "refused" {
		t.Fatalf("log: %+v %+v", first, second)
	}
	if info, _ := os.Stat(p); info.Mode().Perm() != 0o600 {
		t.Fatalf("log must be private, is %v", info.Mode().Perm())
	}
	// A log that cannot be written never changes a decision.
	t.Setenv("JEVGATE_LOG", "/proc/nope/decisions.jsonl")
	var out bytes.Buffer
	hook(strings.NewReader(hookInput("Bash", "ls -la")), &out)
	if !strings.Contains(out.String(), "allow") {
		t.Fatal("an unwritable log must not stop an allow")
	}
}
