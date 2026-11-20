package lab

import (
	"testing"
	"time"

	"gateway/internal/classify"
	"gateway/internal/model"
)

// TestRolloverHalfway: two MX hosts, one has the new certificate, one still
// has the old one that no longer validates. The policy permits both hosts,
// so delivery must succeed via the good host and the classifier must call
// the bad one a rollover, not an attack.
func TestRolloverHalfway(t *testing.T) {
	const body = `version: STSv1
mode: enforce
mx: mx1.partner.example
mx: mx2.partner.example
max_age: 86400
`
	good := NewCertStore()
	bad := NewCertStore()
	h := newHarness(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		PolicyTXT: true, PolicyID: "id1", PolicyBody: body,
		MXHosts: []MXHostSpec{
			{Host: "mx1.partner.example"}, {Host: "mx2.partner.example"},
		},
	}, map[string]ServerPolicy{
		"mx1.partner.example": {AdvertiseSTARTTLS: true, Certs: good},
		"mx2.partner.example": {AdvertiseSTARTTLS: true, Certs: bad},
	})
	// mx1 has the new cert.
	iss1, _ := h.CA.Issue(IssueOptions{DNSNames: []string{"mx1.partner.example"}})
	good.Set(iss1.Cert, iss1.Key)
	// mx2 presents a cert for mx1: the classic half-done deployment.
	iss2, _ := h.CA.Issue(IssueOptions{DNSNames: []string{"mx1.partner.example"}})
	bad.Set(iss2.Cert, iss2.Key)

	res := h.resolve()
	// Try mx1 first: policy order is preference order, and both are
	// permitted.
	sr := h.sendTo("mx1.partner.example", res)
	if !sr.Delivered {
		t.Fatalf("mx1 should deliver: %s %s", sr.Attempt.Phase, sr.Attempt.Error)
	}
	// Now the bad host on its own: must be blocked, and classified as a
	// rollover.
	sr2 := h.sendTo("mx2.partner.example", res)
	if sr2.Delivered {
		t.Fatal("mx2 presented the wrong name and must not be accepted")
	}
	v := classify.Classify(classify.Input{
		Domain:   h.Domain,
		Policy:   res.Policy,
		Attempts: []model.Attempt{sr2.Attempt},
		MXSet:    res.MX,
		Now:      time.Now(),
	})
	if v.Fault != model.FaultRolloverInProgress {
		t.Fatalf("fault = %s (%s); signals=%v", v.Fault, v.Explanation, v.Signals)
	}
	if !v.Retry {
		t.Error("a rollover should be retried")
	}
}

// TestClassificationAttackVsMisconfig exercises the headline distinction on
// synthetic observations.
func TestClassificationAttackVsMisconfig(t *testing.T) {
	base := model.Policy{Domain: "d", Mode: model.ModeEnforce, Source: model.SourceMTASTS}
	now := time.Now()

	// Attack: server that used to do TLS now does not advertise it.
	attack := classify.Classify(classify.Input{
		Domain: "d", Policy: &base, Now: now,
		Attempts: []model.Attempt{{MX: "mx.d", Phase: "starttls-missing", StartTLSAdvertised: false}},
		History: map[string]classify.HostHistory{
			"mx.d": {Host: "mx.d", TLSValid: true, LastSeen: now.Add(-time.Hour),
				LastCertSHA256: "abc"},
		},
	})
	if attack.Fault != model.FaultAttackSuspected || !attack.Escalate {
		t.Fatalf("expected attack, got %s (%s)", attack.Fault, attack.Explanation)
	}

	// Misconfig: server never did TLS, and it is hurting several domains.
	misconfig := classify.Classify(classify.Input{
		Domain: "d", Policy: &base, Now: now,
		Attempts:           []model.Attempt{{MX: "mx.d", Phase: "starttls-missing"}},
		SharedHostFailures: map[string]int{"mx.d": 4},
	})
	if misconfig.Fault != model.FaultRemoteMisconfig {
		t.Fatalf("expected misconfig, got %s (%s)", misconfig.Fault, misconfig.Explanation)
	}
	if !misconfig.Retry {
		t.Error("a misconfiguration should be retried")
	}

	// Policy DNS bogus is an attack signal with high confidence.
	bogus := classify.Classify(classify.Input{
		Domain: "d", Policy: &base, Now: now,
		PolicyObs: classify.PolicyObservation{TXTStatus: model.DNSBogus},
		Attempts:  []model.Attempt{{MX: "mx.d", Phase: "connect", Error: "timeout"}},
	})
	if bogus.Fault != model.FaultAttackSuspected {
		t.Fatalf("bogus DNS should be an attack signal: %s", bogus.Explanation)
	}
}
