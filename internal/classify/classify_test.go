package classify

import (
	"testing"
	"time"

	"gateway/internal/model"
)

func TestNoSignalsMeansNone(t *testing.T) {
	v := Classify(Input{
		Domain:   "d",
		Policy:   &model.Policy{Mode: model.ModeEnforce},
		Attempts: []model.Attempt{{MX: "mx", Phase: "done", TLSStarted: true, TLSPolicyOK: true}},
	})
	if v.Fault != model.FaultNone {
		t.Fatalf("fault = %s", v.Fault)
	}
	if !v.Retry {
		t.Error("a successful delivery should not be marked do-not-retry")
	}
}

func TestEveryVerdictHasSignals(t *testing.T) {
	// A report without its reasons is not actionable; assert that any
	// non-none verdict carries at least one.
	inputs := []Input{
		{Domain: "d", Policy: &model.Policy{Mode: model.ModeEnforce},
			Attempts: []model.Attempt{{MX: "mx", Phase: "starttls-missing"}}},
		{Domain: "d", Policy: &model.Policy{Mode: model.ModeEnforce},
			Attempts: []model.Attempt{{MX: "mx", Phase: "connect", Error: "refused"}}},
		{Domain: "d", Policy: &model.Policy{Mode: model.ModeEnforce},
			PolicyObs: PolicyObservation{TXTStatus: model.DNSBogus},
			Attempts:  []model.Attempt{{MX: "mx", Phase: "tls", TLSError: "handshake failure"}}},
	}
	for i, in := range inputs {
		v := Classify(in)
		if v.Fault == model.FaultNone {
			continue
		}
		if len(v.Signals) == 0 {
			t.Errorf("input %d: verdict %s with no signals", i, v.Fault)
		}
		if v.Explanation == "" {
			t.Errorf("input %d: no explanation", i)
		}
	}
}

func TestConfidenceIsBoundedAndMonotone(t *testing.T) {
	// A single weak signal must not read as certain; several mutually
	// reinforcing signals must read stronger than one.
	weak := Classify(Input{
		Domain: "d", Policy: &model.Policy{Mode: model.ModeEnforce},
		Attempts: []model.Attempt{{MX: "mx", Phase: "starttls-missing"}},
	})
	strong := Classify(Input{
		Domain: "d", Policy: &model.Policy{Mode: model.ModeEnforce},
		PolicyObs: PolicyObservation{TXTStatus: model.DNSBogus, PreviouslySecure: true},
		Attempts:  []model.Attempt{{MX: "mx", Phase: "starttls-missing"}},
		History: map[string]HostHistory{
			"mx": {Host: "mx", TLSValid: true, LastSeen: time.Now().Add(-time.Hour), LastCertSHA256: "x"},
		},
	})
	if weak.Confidence >= 0.9 {
		t.Errorf("one weak signal produced confidence %.2f", weak.Confidence)
	}
	if strong.Confidence <= weak.Confidence {
		t.Errorf("stronger evidence did not raise confidence: %.2f vs %.2f", strong.Confidence, weak.Confidence)
	}
	if strong.Confidence > 0.99 {
		t.Errorf("confidence %.2f exceeds cap", strong.Confidence)
	}
}

func TestExpiredCertIsMisconfigNotAttack(t *testing.T) {
	v := Classify(Input{
		Domain: "d", Policy: &model.Policy{Mode: model.ModeEnforce},
		Attempts: []model.Attempt{{
			MX: "mx", Phase: "tls", TLSStarted: true, TLSPolicyOK: false,
			PeerCertSum:         "aa",
			PeerCertVerifyError: "x509: certificate has expired or is not yet valid",
			PeerDNSNames:        []string{"mx"},
		}},
	})
	if v.Fault != model.FaultRemoteMisconfig {
		t.Fatalf("expired certificate classified as %s (%s)", v.Fault, v.Explanation)
	}
}

func TestUnknownCAIsAttack(t *testing.T) {
	v := Classify(Input{
		Domain: "d", Policy: &model.Policy{Mode: model.ModeEnforce},
		Attempts: []model.Attempt{{
			MX: "mx", Phase: "tls", TLSStarted: true, TLSPolicyOK: false,
			PeerCertSum:         "bb",
			PeerCertVerifyError: "x509: certificate signed by unknown authority",
			PeerDNSNames:        []string{"mx"},
		}},
	})
	if v.Fault != model.FaultAttackSuspected {
		t.Fatalf("unknown CA classified as %s (%s)", v.Fault, v.Explanation)
	}
}
