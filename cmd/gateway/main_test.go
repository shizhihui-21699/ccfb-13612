package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadQueueInfersDomain(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "q.json")
	raw := []map[string]any{
		{"id": "1", "from": "a@corp.test", "to": []string{"x@partner.example"}, "body": "hi"},
		{"id": "2", "domain": "explicit.example", "from": "a@corp.test",
			"to": []string{"y@ignored.example"}, "body": "hi"},
	}
	b, _ := json.Marshal(raw)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	ents, err := loadQueue(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 2 {
		t.Fatalf("%d entries", len(ents))
	}
	if ents[0].Domain != "partner.example" {
		t.Errorf("inferred domain = %q", ents[0].Domain)
	}
	if ents[1].Domain != "explicit.example" {
		t.Errorf("explicit domain overridden: %q", ents[1].Domain)
	}
}

func TestLoadQueueRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "q.json")
	if err := os.WriteFile(p, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadQueue(p); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestLoadAnchorsRoundTrip(t *testing.T) {
	// A DNSKEY text record must parse back into a *dns.DNSKEY; anything
	// else means the trust anchor was not installed and every lookup is
	// silently insecure.
	const key = "example. 3600 IN DNSKEY 257 3 13 MIGYSaEAIrUeYcrsRORtZTfOHYKcACRNYfaQm/fcBOyx5HSQDAoFhYwVtQKPMWosC3ZCWMjEQ2OdhzOgjzIcCA=="
	dir := t.TempDir()
	p := filepath.Join(dir, "a.json")
	b, _ := json.Marshal(map[string][]string{"example.": {key}})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	anchors, err := loadAnchors(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors["example."]) != 1 {
		t.Fatalf("anchors = %+v", anchors)
	}
	// A non-DNSKEY anchor must be rejected, not silently ignored.
	b, _ = json.Marshal(map[string][]string{"example.": {"example. 3600 IN A 192.0.2.1"}})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAnchors(p); err == nil {
		t.Fatal("non-DNSKEY anchor accepted")
	}
}

var _ = time.Now

// TestSimulationUsesProductionPath runs the simulation, which drives the
// real queue and SMTP client against a live lab network, and asserts the
// four outcomes are distinguished. This is the closest thing to an
// end-to-end test of the shipping code path.
func TestSimulationUsesProductionPath(t *testing.T) {
	var text, js bytes.Buffer
	if code := runSimulation(nil, nil, nil, &text, &js, t.TempDir()); code != 0 {
		t.Fatalf("exit %d", code)
	}
	out := text.String()
	for _, want := range []string{
		"deliveries: 4",
		"over policy-compliant TLS : 1",
		"REMOTE MISCONFIGURATION",
		"ROLLOVER IN PROGRESS",
		"POLICY UNAVAILABLE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// No cleartext delivered under an enforcing policy.
	if strings.Contains(out, "cleartext                 : 1") {
		t.Errorf("cleartext delivery under enforce:\n%s", out)
	}
	var parsed struct {
		Deliveries []struct {
			Outcome string `json:"outcome"`
			Fault   string `json:"fault"`
		} `json:"deliveries"`
	}
	if err := json.Unmarshal(js.Bytes(), &parsed); err != nil {
		t.Fatalf("json: %v\n%s", err, js.String())
	}
	if len(parsed.Deliveries) != 4 {
		t.Fatalf("%d deliveries in json", len(parsed.Deliveries))
	}
	seen := map[string]bool{}
	for _, d := range parsed.Deliveries {
		seen[d.Outcome+"|"+d.Fault] = true
	}
	for _, want := range []string{
		"delivered_tls|none",
		"deferred|remote_misconfiguration",
		"deferred|rollover_in_progress",
		"blocked|policy_unavailable",
	} {
		if !seen[want] {
			t.Errorf("missing outcome %q; got %v", want, seen)
		}
	}
}
