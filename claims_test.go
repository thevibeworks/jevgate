package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The docs quote numbers. This test recomputes each one from the committed
// judgments and the shipped policy, so a stale document turns CI red
// instead of reading green while it lies. Every assertion is an exact
// string the document must contain, built from the recomputed value.

func captureReport(t *testing.T) string {
	t.Helper()
	var cases []evalCase
	raw, err := os.ReadFile("eval/corpus.json")
	if err != nil || json.Unmarshal(raw, &cases) != nil {
		t.Fatal("eval/corpus.json:", err)
	}
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	code := report(cases, loadRows("eval/results.jsonl"))
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	if code != 0 {
		t.Fatalf("the gate leaks on the committed judgments:\n%s", buf.String())
	}
	return buf.String()
}

func TestDocsQuoteTheMeasurement(t *testing.T) {
	out := captureReport(t)
	find := func(re string) []string {
		m := regexp.MustCompile(re).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("report no longer matches %q:\n%s", re, out)
		}
		return m[1:]
	}
	head := find(`(?m)^(\d+) commands, (\d+) judgments, model (\S+), threshold (\S+)$`)
	noise := find(`noise: (\d+) of (\d+) answers moved between identical runs, widest spread (\S+) on`)
	lat := find(`latency ms: p50 (\d+), p90 (\d+),`)
	reached := find(`(?m)^(\d+) unsafe commands had only Jev`)
	closest := find(`The five closest:\n\s+(\S+)\s+(.+)\n\s+(\S+)\s+(.+)\n`)

	parts := strings.Split(out, "held-out sets")
	row := func(part, gate string) []string {
		m := regexp.MustCompile(`(?m)^\s+` + gate + `\s+(\d+/\d+)\s+(\d+/\d+)$`).FindStringSubmatch(part)
		if m == nil {
			t.Fatalf("no %q row in:\n%s", gate, part)
		}
		return m[1:]
	}
	comma := func(s string) string { // 1245 -> 1,245
		if len(s) > 3 {
			return s[:len(s)-3] + "," + s[len(s)-3:]
		}
		return s
	}

	eval, _ := os.ReadFile("EVAL.md")
	readme, _ := os.ReadFile("README.md")
	must := func(doc []byte, name, want string) {
		t.Helper()
		if !strings.Contains(strings.Join(strings.Fields(string(doc)), " "), strings.Join(strings.Fields(want), " ")) {
			t.Errorf("%s must say %q", name, want)
		}
	}

	must(eval, "EVAL.md", "## The corpus: "+head[0]+" labelled commands")
	must(eval, "EVAL.md", "against `"+head[2]+"`")
	for i, g := range []struct{ doc, gate string }{{"allowlist alone", "allowlist alone"}, {"Jev alone", "jev alone"}, {"jevgate", "jevgate"}} {
		_ = i
		d, h := row(parts[0], g.gate), row(parts[1], g.gate)
		must(eval, "EVAL.md", fmt.Sprintf("| development: %s | %s | %s |", g.doc, d[0], d[1]))
		must(eval, "EVAL.md", fmt.Sprintf("| held-out: %s | %s | %s |", g.doc, h[0], h[1]))
	}
	must(eval, "EVAL.md", fmt.Sprintf("%s of %s answers moved", comma(noise[0]), comma(noise[1])))
	must(eval, "EVAL.md", "the widest spread on one question was "+noise[2])
	must(eval, "EVAL.md", reached[0]+" unsafe commands had only Jev")
	must(eval, "EVAL.md", fmt.Sprintf("took %s ms at the median (p90 %s ms)", lat[0], lat[1]))
	must(eval, "EVAL.md", fmt.Sprintf("`%s` scores %s.", closest[1], closest[0]))
	must(eval, "EVAL.md", fmt.Sprintf("`%s` scored %s", closest[3], closest[2]))
	must(eval, "EVAL.md", fmt.Sprintf("The threshold (%.1f)", Threshold))

	// README carries the headline only, from the same rows.
	dj, hj := row(parts[0], "jevgate"), row(parts[1], "jevgate")
	da, ha := row(parts[0], "allowlist alone"), row(parts[1], "allowlist alone")
	must(readme, "README.md", fmt.Sprintf("| allowlist alone | %s | %s | %s | %s |", da[0], da[1], ha[0], ha[1]))
	must(readme, "README.md", fmt.Sprintf("| jevgate | %s | %s | %s | %s |", dj[0], dj[1], hj[0], hj[1]))
	must(readme, "README.md", "`"+defaultModel+"`")
	must(readme, "README.md", fmt.Sprintf("below %.1f", Threshold))
}

// The README prints the questions. They are the reviewable core, so the
// copy must be the code.
func TestReadmeQuotesTheQuestions(t *testing.T) {
	readme, _ := os.ReadFile("README.md")
	flat := strings.Join(strings.Fields(string(readme)), " ")
	for id, q := range Questions {
		if !strings.Contains(flat, strings.Join(strings.Fields(q), " ")) {
			t.Errorf("README.md must quote question %q verbatim", id)
		}
	}
}
