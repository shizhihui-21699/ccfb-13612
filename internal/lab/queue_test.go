package lab

import (
	"context"
	"testing"
	"time"

	"gateway/internal/model"
	"gateway/internal/queue"
)

// queueHarness bundles a world with a queue worker.
type queueHarness struct {
	*harness
	Worker *queue.Worker
	Store  *queue.MemStore
	Clock  *Clock
}

func newQueueHarness(t *testing.T, clock *Clock, body string, sp ServerPolicy, wopts WorldOptions) *queueHarness {
	t.Helper()
	wopts.Domain = "partner.example"
	wopts.SignedDomain = true
	wopts.PolicyTXT = true
	if wopts.PolicyID == "" {
		wopts.PolicyID = "id1"
	}
	wopts.PolicyBody = body
	wopts.Clock = clock
	if len(wopts.MXHosts) == 0 {
		wopts.MXHosts = []MXHostSpec{{Host: "mx1.partner.example"}}
	}
	h := newHarness(t, wopts, map[string]ServerPolicy{"mx1.partner.example": sp})
	st := queue.NewMemStore()
	w := &queue.Worker{
		Engine: h.Policy,
		Client: h.client(),
		Store:  st,
		Now:    clock.Now,
	}
	return &queueHarness{harness: h, Worker: w, Store: st, Clock: clock}
}

func (qh *queueHarness) enqueue(t *testing.T) *queue.Entry {
	t.Helper()
	e := &queue.Entry{
		Domain: qh.Domain, From: "sender@corp.test",
		To:   []string{"ops@partner.example"},
		Body: []byte("Subject: t\r\n\r\nbody\r\n"),
	}
	if err := qh.Worker.Enqueue(context.Background(), e); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return e
}

// TestQueuedEnforceThenPolicyWithdrawnUnsanctioned covers the scenario that
// no other design handles: a message accepted while the domain enforced TLS,
// then the domain's policy silently disappears (an attacker stripping the
// record, or a broken signer). The message must stay held, not go out in
// cleartext.
func TestQueuedEnforceThenPolicyWithdrawnUnsanctioned(t *testing.T) {
	clock := NewClock(time.Unix(1_700_000_000, 0))
	cs := NewCertStore()
	const body = "version: STSv1\nmode: enforce\nmx: mx1.partner.example\nmax_age: 600\n"
	qh := newQueueHarness(t, clock, body,
		ServerPolicy{AdvertiseSTARTTLS: false, Certs: cs},
		WorldOptions{Attack: AttackerStripPolicyTXT})
	iss, _ := qh.CA.Issue(IssueOptions{DNSNames: []string{"mx1.partner.example"}})
	cs.Set(iss.Cert, iss.Key)

	// Establish a baseline before the attacker joins the path.
	if res := qh.EstablishClean(t); res.Policy.Mode != model.ModeEnforce {
		t.Fatalf("baseline mode = %s", res.Policy.Mode)
	}
	e := qh.enqueue(t)
	if e.PlannedMode != model.ModeEnforce {
		t.Fatalf("planned mode = %s", e.PlannedMode)
	}
	// The attacker is now in the path and the policy has to be re-read.
	clock.Advance(2 * time.Hour)
	qh.Policy.ExpireForTest(qh.Domain)

	reports, err := qh.Worker.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	acc, clear, _, _ := qh.MX["mx1.partner.example"].Stats()
	if clear != 0 {
		t.Fatalf("message delivered in cleartext after policy vanished: accepted=%d cleartext=%d", acc, clear)
	}
	if acc != 0 {
		t.Fatalf("message delivered after policy vanished; reports=%+v", reports)
	}
	found := false
	for _, r := range reports {
		if r.CleartextRefused {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a report saying cleartext was refused; got %+v", reports)
	}
}

// TestQueuedEnforceThenAuthenticatedWithdrawalReleases: the domain really
// did stop enforcing, with DNSSEC-authenticated evidence. The queued
// message may then go out unencrypted, and the release is recorded.
func TestQueuedEnforceThenAuthenticatedWithdrawalReleases(t *testing.T) {
	clock := NewClock(time.Unix(1_700_000_000, 0))
	cs := NewCertStore()
	const body = "version: STSv1\nmode: enforce\nmx: mx1.partner.example\nmax_age: 600\n"
	qh := newQueueHarness(t, clock, body,
		ServerPolicy{AdvertiseSTARTTLS: false, Certs: cs}, WorldOptions{})
	iss, _ := qh.CA.Issue(IssueOptions{DNSNames: []string{"mx1.partner.example"}})
	cs.Set(iss.Cert, iss.Key)
	qh.EstablishClean(t)
	qh.enqueue(t)

	// The domain withdraws enforcement, authenticated (signed zone), and
	// the old policy expires first so the transition is accepted.
	clock.Advance(30 * time.Minute)
	qh.Policy.ExpireForTest(qh.Domain)
	if err := qh.SetPolicyBody("version: STSv1\nmode: testing\nmx: mx1.partner.example\nmax_age: 600\n", "id2"); err != nil {
		t.Fatal(err)
	}
	res, err := qh.Policy.Resolve(context.Background(), qh.Domain)
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy.Mode != model.ModeTesting {
		t.Fatalf("engine did not accept the authenticated withdrawal: %s %v", res.Policy.Mode, res.Evidence)
	}
	reports, err := qh.Worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	acc, clear, _, _ := qh.MX["mx1.partner.example"].Stats()
	if acc != 1 || clear != 1 {
		t.Fatalf("expected a recorded release; accepted=%d cleartext=%d reports=%+v", acc, clear, reports)
	}
	if !reports[0].Entry.Released || !reports[0].CleartextSent {
		t.Fatalf("expected a recorded release, got %+v", reports[0])
	}
	// The release must be visible as an explicit event, not silently
	// indistinguishable from an ordinary cleartext delivery.
	var sawRelease bool
	for _, sig := range reports[0].Verdict.Signals {
		if sig.Code == "enforce_released" {
			sawRelease = true
		}
	}
	if !sawRelease {
		t.Fatalf("release not surfaced in the report signals: %+v", reports[0].Verdict)
	}
}

// TestQueuedTestingThenUpgradeDoesNotGoCleartext: the reverse case. A message
// queued under testing must be re-planned if the domain upgrades to enforce
// before it is sent.
func TestQueuedTestingThenUpgradeDoesNotGoCleartext(t *testing.T) {
	clock := NewClock(time.Unix(1_700_000_000, 0))
	cs := NewCertStore()
	const bodyA = "version: STSv1\nmode: testing\nmx: mx1.partner.example\nmax_age: 600\n"
	qh := newQueueHarness(t, clock, bodyA,
		ServerPolicy{AdvertiseSTARTTLS: false, Certs: cs}, WorldOptions{})
	iss, _ := qh.CA.Issue(IssueOptions{DNSNames: []string{"mx1.partner.example"}})
	cs.Set(iss.Cert, iss.Key)
	qh.enqueue(t)

	clock.Advance(10 * time.Minute)
	qh.Policy.ExpireForTest(qh.Domain)
	if err := qh.SetPolicyBody("version: STSv1\nmode: enforce\nmx: mx1.partner.example\nmax_age: 600\n", "id2"); err != nil {
		t.Fatal(err)
	}
	reports, err := qh.Worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	acc, clear, _, _ := qh.MX["mx1.partner.example"].Stats()
	if acc != 0 || clear != 0 {
		t.Fatalf("delivered despite an upgrade to enforce: accepted=%d cleartext=%d", acc, clear)
	}
	_ = reports
}

// TestQueuedNeverSendsInWindow tests the pre-DATA gate directly: the policy
// weakens after the connection is open but before DATA. Nothing may be
// transmitted.
func TestPreDATAGateAbortsOnWeakening(t *testing.T) {
	clock := NewClock(time.Unix(1_700_000_000, 0))
	cs := NewCertStore()
	const body = "version: STSv1\nmode: enforce\nmx: mx1.partner.example\nmax_age: 600\n"
	qh := newQueueHarness(t, clock, body,
		ServerPolicy{AdvertiseSTARTTLS: true, Certs: cs}, WorldOptions{})
	iss, _ := qh.CA.Issue(IssueOptions{DNSNames: []string{"mx1.partner.example"}})
	cs.Set(iss.Cert, iss.Key)
	qh.enqueue(t)

	// Force a weakening that the engine did not sanction, straight into
	// the cache, and check the gate refuses.
	qh.Policy.InjectWeakPolicyForTest(qh.Domain)
	reports, err := qh.Worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	acc, clear, _, _ := qh.MX["mx1.partner.example"].Stats()
	if acc != 0 || clear != 0 {
		t.Fatalf("sent despite unsanctioned weakening: accepted=%d cleartext=%d reports=%+v", acc, clear, reports)
	}
	if len(reports) == 0 || !reports[0].CleartextRefused {
		t.Fatalf("expected refusal report, got %+v", reports)
	}
}
