package lab

import (
	"context"
	"testing"
	"time"

	"gateway/internal/model"
)

const (
	bodyEnforce = "version: STSv1\nmode: enforce\nmx: mx1.partner.example\nmax_age: 600\n"
	bodyTesting = "version: STSv1\nmode: testing\nmx: mx1.partner.example\nmax_age: 600\n"
)

func modeWorld(t *testing.T, clock *Clock, signed bool) *World {
	t.Helper()
	return NewWorld(t, WorldOptions{
		Domain: "partner.example", SignedDomain: signed,
		PolicyTXT: true, PolicyID: "id-enforce", PolicyBody: bodyEnforce,
		MXHosts:             []MXHostSpec{{Host: "mx1.partner.example"}},
		Clock:               clock,
		StabilizationWindow: 24 * time.Hour,
		StaleGrace:          7 * 24 * time.Hour,
	})
}

// TestAuthenticatedDowngradeWaitsForExpiry: with DNSSEC, an enforce->testing
// change is authenticated, but the old policy keeps applying until it
// expires, so a freshly rolled-back zone cannot yank protection from
// messages already queued.
func TestAuthenticatedDowngradeWaitsForExpiry(t *testing.T) {
	clock := NewClock(time.Unix(1_700_000_000, 0))
	w := modeWorld(t, clock, true)
	res, err := w.Policy.Resolve(context.Background(), w.Domain)
	if err != nil || res.Policy.Mode != model.ModeEnforce {
		t.Fatalf("setup: %v %v", res, err)
	}

	// Change the policy while the old one still has most of its lifetime
	// left. This is the dangerous shape: a fresh, DNSSEC-valid signature on
	// a weaker policy.
	clock.Advance(5 * time.Minute)
	if err := w.SetPolicyBody(bodyTesting, "id-testing"); err != nil {
		t.Fatal(err)
	}
	w.Policy.RefreshForTest(w.Domain)
	res, _ = w.Policy.Resolve(context.Background(), w.Domain)
	if res.Policy.Mode != model.ModeEnforce {
		t.Fatalf("authenticated downgrade applied before expiry: mode=%s", res.Policy.Mode)
	}

	// After expiry, it takes effect.
	clock.Advance(20 * time.Minute)
	w.Policy.RefreshForTest(w.Domain)
	res, _ = w.Policy.Resolve(context.Background(), w.Domain)
	if res.Policy.Mode != model.ModeTesting {
		t.Fatalf("downgrade did not apply after expiry: mode=%s evidence=%v", res.Policy.Mode, res.Evidence)
	}
	if len(res.History) < 2 || res.History[len(res.History)-1].Reason != "authenticated_downgrade" {
		t.Fatalf("unexpected history: %+v", res.History)
	}
}

// TestUnauthenticatedDowngradeNeedsStabilization: without DNSSEC, an
// enforce->testing change needs two identical observations spanning the
// stabilization window.
func TestUnauthenticatedDowngradeNeedsStabilization(t *testing.T) {
	clock := NewClock(time.Unix(1_700_000_000, 0))
	w := modeWorld(t, clock, false)
	res, err := w.Policy.Resolve(context.Background(), w.Domain)
	if err != nil || res.Policy.Mode != model.ModeEnforce {
		t.Fatalf("setup: %v %v %v", res, err, res.Evidence)
	}

	// First weak observation, well past expiry.
	clock.Advance(48 * time.Hour)
	w.Policy.ExpireForTest(w.Domain)
	if err := w.SetPolicyBody(bodyTesting, "id-testing"); err != nil {
		t.Fatal(err)
	}
	res, _ = w.Policy.Resolve(context.Background(), w.Domain)
	if res.Policy.Mode != model.ModeEnforce {
		t.Fatalf("one-shot downgrade accepted without stabilization: %s", res.Policy.Mode)
	}

	// Still inside the window: not yet.
	clock.Advance(1 * time.Hour)
	w.Policy.ExpireForTest(w.Domain)
	res, _ = w.Policy.Resolve(context.Background(), w.Domain)
	if res.Policy.Mode != model.ModeEnforce {
		t.Fatalf("downgrade accepted inside the stabilization window: %s", res.Policy.Mode)
	}

	// Past the window with the same observation: accepted.
	clock.Advance(30 * time.Hour)
	w.Policy.ExpireForTest(w.Domain)
	res, _ = w.Policy.Resolve(context.Background(), w.Domain)
	if res.Policy.Mode != model.ModeTesting {
		t.Fatalf("stabilized downgrade rejected: %s evidence=%v", res.Policy.Mode, res.Evidence)
	}
}

// TestUpgradeIsImmediate: the asymmetry. An upgrade must take effect on the
// first observation, authenticated or not.
func TestUpgradeIsImmediate(t *testing.T) {
	clock := NewClock(time.Unix(1_700_000_000, 0))
	w := NewWorld(t, WorldOptions{
		Domain: "partner.example", SignedDomain: false,
		PolicyTXT: true, PolicyID: "id-testing", PolicyBody: bodyTesting,
		MXHosts: []MXHostSpec{{Host: "mx1.partner.example"}}, Clock: clock,
	})
	res, err := w.Policy.Resolve(context.Background(), w.Domain)
	if err != nil || res.Policy.Mode != model.ModeTesting {
		t.Fatalf("setup: %v %v", res, err)
	}
	if err := w.SetPolicyBody(bodyEnforce, "id-enforce"); err != nil {
		t.Fatal(err)
	}
	w.Policy.ExpireForTest(w.Domain)
	res, _ = w.Policy.Resolve(context.Background(), w.Domain)
	if res.Policy.Mode != model.ModeEnforce {
		t.Fatalf("upgrade not applied immediately: %s", res.Policy.Mode)
	}
}

// TestStaleEnforceIsKeptWhenRefreshFails: the domain's DNS breaks. The
// enforcing policy stays in force well past expiry, and delivery is
// deferred rather than downgraded.
func TestStaleEnforceIsKeptWhenRefreshFails(t *testing.T) {
	clock := NewClock(time.Unix(1_700_000_000, 0))
	w := modeWorld(t, clock, true)
	if _, err := w.Policy.Resolve(context.Background(), w.Domain); err != nil {
		t.Fatal(err)
	}
	// The policy host goes away while the record still says a policy
	// exists. That is a fetch failure, not a withdrawal.
	w.StopPolicyServer(t)
	clock.Advance(2 * time.Hour)
	w.Policy.ExpireForTest(w.Domain)
	res, err := w.Policy.Resolve(context.Background(), w.Domain)
	if err != nil {
		t.Fatalf("resolve should not error: %v", err)
	}
	if res.Policy.Mode != model.ModeEnforce {
		t.Fatalf("stale enforcing policy downgraded to %s", res.Policy.Mode)
	}
	if !res.Degraded {
		t.Fatal("expected Degraded to be set")
	}
}
