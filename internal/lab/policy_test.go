package lab

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"gateway/internal/model"
	"gateway/internal/policy"
)

// TestSignedZonePolicyFetch exercises the narrow path the gateway depends on:
// a signed zone, a signed policy TXT record, an HTTPS policy fetch that is
// certificate-verified, and a resulting enforcing policy.
func TestSignedZonePolicyFetch(t *testing.T) {
	const body = `version: STSv1
mode: enforce
mx: mx1.partner.example
mx: *.partner.example
max_age: 86400
`
	w := NewWorld(t, WorldOptions{
		Domain:       "partner.example",
		SignedDomain: true,
		PolicyTXT:    true,
		PolicyID:     "20260101T000000",
		PolicyBody:   body,
		MXHosts:      []MXHostSpec{{Host: "mx1.partner.example"}},
	})

	res, err := w.Policy.Resolve(Ctx(), w.Domain)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	t.Logf("evidence: %+v", res.Evidence)
	if res.Policy.Mode != model.ModeEnforce {
		t.Fatalf("mode = %s, want enforce; events: %v", res.Policy.Mode, res.Evidence)
	}
	if res.Policy.Source != model.SourceMTASTS {
		t.Fatalf("source = %s", res.Policy.Source)
	}
	if res.Policy.PolicyID != "20260101T000000" {
		t.Fatalf("policy id = %q", res.Policy.PolicyID)
	}
	if !res.Policy.MatchesMX("mx1.partner.example") {
		t.Error("mx1 should match")
	}
	if !res.Policy.MatchesMX("anything.partner.example") {
		t.Error("wildcard should match one label")
	}
	if res.Policy.MatchesMX("a.b.partner.example") {
		t.Error("wildcard must not match two labels")
	}
	if len(res.MX) == 0 || res.MX[0].Host != "mx1.partner.example" {
		t.Fatalf("mx = %+v", res.MX)
	}
}

// TestPolicyTXTStrippedByMITM is the core threat from the brief: an attacker
// removes the policy record. Because the zone is signed, the validator must
// see this as bogus, not as absence.
func TestPolicyTXTStrippedByMITM(t *testing.T) {
	const body = `version: STSv1
mode: enforce
mx: mx1.partner.example
max_age: 86400
`
	w := NewWorld(t, WorldOptions{
		Domain:       "partner.example",
		SignedDomain: true,
		PolicyTXT:    true,
		PolicyID:     "id1",
		PolicyBody:   body,
		MXHosts:      []MXHostSpec{{Host: "mx1.partner.example"}},
		Attack:       AttackerStripPolicyTXT,
	})
	res, err := w.Policy.Resolve(Ctx(), w.Domain)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Observation.TXTStatus != model.DNSBogus {
		t.Fatalf("observation status = %s, want bogus (attacker tried to strip a signed record); evidence=%v",
			res.Observation.TXTStatus, res.Evidence)
	}
	// Nothing was accepted: an attacker cannot manufacture a policy, and
	// strip-to-nothing must not look like "publishes no policy".
	if res.Policy.Mode != model.ModeNone {
		t.Fatalf("mode = %s, want none", res.Policy.Mode)
	}
	if res.Policy.DNSSEC == model.DNSSecure {
		t.Fatal("policy must not be recorded as resting on secure DNS")
	}
}

// TestValidatorDirect checks the resolver itself, independently of the
// policy engine.
func TestValidatorDirect(t *testing.T) {
	w := NewWorld(t, WorldOptions{
		Domain:       "partner.example",
		SignedDomain: true,
		PolicyTXT:    true,
		PolicyID:     "abc",
		MXHosts:      []MXHostSpec{{Host: "mx1.partner.example"}},
	})
	res := w.Resolver.Lookup(Ctx(), "_mta-sts.partner.example", dns.TypeTXT)
	if res.Status != model.DNSSecure || !res.Exists {
		t.Fatalf("secure TXT: status=%s exists=%v err=%v", res.Status, res.Exists, res.Err)
	}
	// Absence of a name that does not exist must be a *validated* denial.
	res = w.Resolver.Lookup(Ctx(), "_mta-sts.www.partner.example", dns.TypeTXT)
	if res.Status != model.DNSSecure || res.Exists {
		t.Fatalf("signed denial: status=%s exists=%v err=%v", res.Status, res.Exists, res.Err)
	}
}

// TestUnsignedZoneIsInsecure checks the other half of the validator: a zone
// with no DS must be reported insecure, not secure and not bogus.
func TestUnsignedZoneIsInsecure(t *testing.T) {
	w := NewWorld(t, WorldOptions{
		Domain:       "partner.example",
		SignedDomain: false,
		PolicyTXT:    true,
		PolicyID:     "abc",
		MXHosts:      []MXHostSpec{{Host: "mx1.partner.example"}},
	})
	res := w.Resolver.Lookup(Ctx(), "_mta-sts.partner.example", dns.TypeTXT)
	if res.Status != model.DNSInsecure {
		t.Fatalf("unsigned zone: status=%s want insecure (err=%v)", res.Status, res.Err)
	}
}

var _ = strings.Contains
var _ = time.Now
var _ = policy.NewMemStore
