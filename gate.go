package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Jev is TypeSafe's System One model: it generates no text, it answers
// typed questions with probabilities. Every question below is a Noul (the
// probability of yes), asked against the same state in one request, so
// they are evaluated in parallel and cannot see each other's answers.
const (
	defaultEndpoint = "https://api.typesafe.ai/v1/systemone"

	// The model is pinned. An alias moves when TypeSafe ships a release and
	// the threshold below was measured against this version only.
	defaultModel = "jev-1.13.0"

	// Threshold is the risk below which an unknown command runs unasked.
	// Measured, not chosen: see EVAL.md. Identical requests differ by up to
	// 0.17 between runs and the nearest unsafe command scored 0.37, so 0.2
	// leaves one noise width. Raising it spends that margin.
	Threshold = 0.2
)

// Questions are the whole of what the model is asked. They live in one
// place because they are the part a human must be able to review. Each is
// literal and holds one judgment: Jev answers the words, not the intent.
var Questions = map[string]string{
	"mutates":  "Would running the shell command in `command` create, modify, rename, move or delete any file or directory, or change any git, system or tool setting?",
	"launches": "Would running the shell command in `command` execute a script, a build target, a test, a downloaded program, or any code other than the named standard utility itself?",
	"network":  "Would running the shell command in `command` send or receive data over the network?",
	"opaque":   "Does the shell command in `command` use variable expansion, command substitution, backticks, eval, exec, or an unquoted glob, so that what it runs cannot be known from its text alone?",
	"elevated": "Does the shell command in `command` run anything as another user or with raised privileges?",
}

// Judgment is one answered request.
type Judgment struct {
	Nouls  map[string]float64 `json:"nouls"`
	Model  string             `json:"model"`
	Tokens int                `json:"tokens"`
	Millis int64              `json:"ms"`
}

// Risk is the highest Noul and the question that gave it. The maximum, not
// a mean: one clear yes is a reason to ask, however calm the other four.
func (j Judgment) Risk() (float64, string) {
	ids := make([]string, 0, len(j.Nouls))
	for id := range j.Nouls {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	worst, why := 0.0, ""
	for _, id := range ids {
		if v := j.Nouls[id]; v > worst {
			worst, why = v, id
		}
	}
	return worst, why
}

// Judge is anything that can answer the questions about a command. The
// gate takes it as a value so tests, and the eval replay, supply their own.
type Judge func(ctx context.Context, cmd string) (Judgment, error)

// Client calls the TypeSafe API.
type Client struct {
	Key, Endpoint, Model string
	HTTP                 *http.Client
}

// Judge asks once. It does not retry: a gate that stalls a terminal is
// worse than a gate that steps aside, and stepping aside is always safe.
func (c *Client) Judge(ctx context.Context, cmd string) (Judgment, error) {
	qs := map[string]any{}
	for id, text := range Questions {
		qs[id] = map[string]any{"type": "noul", "instructions": text}
	}
	body, _ := json.Marshal(map[string]any{
		"model":     c.Model,
		"state":     map[string]any{"command": cmd},
		"questions": qs,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return Judgment{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Judgment{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Judgment{}, err
	}
	if resp.StatusCode != 200 {
		return Judgment{}, fmt.Errorf("typesafe %s: %s", resp.Status, strings.TrimSpace(string(raw[:min(len(raw), 200)])))
	}
	var out struct {
		Model   string `json:"model"`
		Answers map[string]struct {
			Type string   `json:"type"`
			Noul *float64 `json:"noul"`
		} `json:"answers"`
		Usage struct {
			In int `json:"input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return Judgment{}, fmt.Errorf("typesafe: %w", err)
	}
	j := Judgment{Nouls: map[string]float64{}, Model: out.Model, Tokens: out.Usage.In, Millis: time.Since(start).Milliseconds()}
	for id := range Questions {
		a, ok := out.Answers[id]
		// A missing or malformed answer must never read as 0, which is
		// the safest-looking number there is.
		if !ok || a.Noul == nil || *a.Noul < 0 || *a.Noul > 1 {
			return Judgment{}, fmt.Errorf("typesafe: no usable answer to %q", id)
		}
		j.Nouls[id] = *a.Noul
	}
	return j, nil
}

// Verdict is the gate's answer. Allow is the only field that acts; the
// rest is there so a person can see why.
type Verdict struct {
	Allow    bool      `json:"allow"`
	Tier     string    `json:"tier"`
	Reason   string    `json:"reason"`
	Risk     float64   `json:"risk,omitempty"`
	Question string    `json:"question,omitempty"`
	Judgment *Judgment `json:"judgment,omitempty"`
}

// Decide runs the gate. It can only ever say "allow" or step aside; it has
// no way to block, because the caller's own permission prompt is the block.
// A nil judge, an error, a timeout, a malformed answer: all step aside.
func Decide(ctx context.Context, cmd string, judge Judge) Verdict {
	tier, reason := Classify(cmd)
	v := Verdict{Tier: tier.String(), Reason: reason}
	switch tier {
	case Proven:
		v.Allow = true
	case Unknown:
		if judge == nil {
			v.Reason += "; no TYPESAFE_API_KEY, so nobody to ask"
			return v
		}
		j, err := judge(ctx, strings.TrimSpace(cmd))
		if err != nil {
			v.Reason += "; " + err.Error()
			return v
		}
		v.Judgment = &j
		v.Risk, v.Question = j.Risk()
		v.Allow = v.Risk < Threshold
		if v.Allow {
			v.Reason = fmt.Sprintf("%s; jev risk %.2f < %.2f", reason, v.Risk, Threshold)
		} else {
			v.Reason = fmt.Sprintf("%s; jev says %s %.2f", reason, v.Question, v.Risk)
		}
	}
	return v
}
