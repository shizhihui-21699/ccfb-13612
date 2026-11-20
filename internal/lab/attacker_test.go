package lab

import (
	"testing"
	"time"

	"gateway/internal/classify"
	"gateway/internal/model"
)

// TestAttackerJoinsAfterCleanSession is the scenario the brief calls out:
// the attacker is in the network before the first policy fetch. The right
// answer is not to invent a policy: it is to refuse to guess, and to say
// clearly that the relationship was held rather than downgraded.
func TestAttackerJoinsAfterCleanSession(t *testing.T) {
	w := NewWorld(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		PolicyTXT: true, PolicyID: "id1",
		PolicyBody: "version: STSv1\nmode: enforce\nmx: mx1.partner.example\nmax_age: 600\n",
		MXHosts:    []MXHostSpec{{Host: "mx1.partner.example"}},
		Attack:     AttackerStripPolicyTXT,
		Clock:      NewClock(time.Unix(1_700_000_000, 0)),
	})
	// Baseline through the clean path first.
	res := w.EstablishClean(t)
	if res.Policy.Mode != model.ModeEnforce {
		t.Fatalf("baseline = %s", res.Policy.Mode)
	}
	// Now the attacker removes the record and the policy expires.
	w.Clock.Advance(2 * time.Hour)
	w.Policy.ExpireForTest(w.Domain)
	res, err := w.Policy.Resolve(Ctx(), w.Domain)
	if err != nil {
		t.Fatal(err)
	}
	// The engine must keep enforcing rather than fall back.
	if res.Policy.Mode != model.ModeEnforce {
		t.Fatalf("policy downgraded after record stripped: %s", res.Policy.Mode)
	}
	if !res.Degraded {
		t.Fatal("expected the resolution to be marked degraded")
	}
	// And the classifier must call it an attack, not a config error.
	v := classify.Classify(classify.Input{
		Domain: w.Domain, Policy: res.Policy, Now: time.Now(),
		PolicyObs: classify.PolicyObservation{
			TXTStatus: res.Observation.TXTStatus, TXTPresent: res.Observation.TXTPresent,
			PreviouslySecure: true,
		},
		Attempts: []model.Attempt{{MX: "mx1.partner.example", Phase: "starttls-missing"}},
	})
	if v.Fault != model.FaultAttackSuspected {
		t.Fatalf("fault = %s: %s", v.Fault, v.Explanation)
	}
}

// TestDistinguishesTargetedAttackFromNetworkProblem is the discriminator
// that matters operationally: one domain attacked, another merely broken.
func TestDistinguishesTargetedAttackFromNetworkProblem(t *testing.T) {
	// A targeted attack: HTTPS policy vanished for one domain, everything
	// else about the connection is normal, and no other domain is
	// affected.
	attacked := classify.Classify(classify.Input{
		Domain: "a.example", Policy: &model.Policy{Mode: model.ModeEnforce},
		Now: time.Now(),
		PolicyObs: classify.PolicyObservation{
			TXTStatus: model.DNSBogus, PreviouslySecure: true,
		},
		Attempts:           []model.Attempt{{MX: "mx.a.example", Phase: "starttls-missing"}},
		SharedHostFailures: map[string]int{},
	})
	if attacked.Fault != model.FaultAttackSuspected {
		t.Fatalf("targeted: %s", attacked.Fault)
	}

	// A network problem: the same host is failing for many domains.
	broken := classify.Classify(classify.Input{
		Domain: "b.example", Policy: &model.Policy{Mode: model.ModeEnforce},
		Now:                time.Now(),
		Attempts:           []model.Attempt{{MX: "mx.shared.example", Phase: "starttls-missing"}},
		SharedHostFailures: map[string]int{"mx.shared.example": 12},
	})
	if broken.Fault != model.FaultRemoteMisconfig {
		t.Fatalf("network problem: %s (%s)", broken.Fault, broken.Explanation)
	}
	if broken.Escalate {
		t.Error("a wide misconfiguration should not page anyone")
	}
}
