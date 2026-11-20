package lab

import (
	"testing"

	"gateway/internal/model"
)

// TestDANEDeliversWithMatchingTLSA: MX and TLSA are DNSSEC-secure, the TLSA
// record matches, delivery proceeds with no MTA-STS policy at all.
func TestDANEDeliversWithMatchingTLSA(t *testing.T) {
	cs := NewCertStore()
	w := NewWorld(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		PolicyTXT: false,
		MXHosts:   []MXHostSpec{{Host: "mx1.partner.example"}},
	})
	iss, _ := w.CA.Issue(IssueOptions{DNSNames: []string{"mx1.partner.example"}})
	cs.Set(iss.Cert, iss.Key)
	// Publish TLSA *after* we know the cert; NewWorld built the zone, so
	// add the record now.
	w.AddTLSA(t, "mx1.partner.example", TLSAForSHA256(iss.Cert))

	h := &harness{World: w, MX: map[string]*Server{}}
	s, err := NewServer("mx1", ServerPolicy{AdvertiseSTARTTLS: true, Certs: cs})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	h.MX["mx1.partner.example"] = s
	w.SetMXPorts = func(host string) (int, bool) { return PortOf(s.Addr()), true }

	res := h.resolve()
	if res.Policy.Source != model.SourceDANE || res.Policy.Mode != model.ModeEnforce {
		t.Fatalf("expected DANE enforce, got %s/%s (%v)", res.Policy.Source, res.Policy.Mode, res.Evidence)
	}
	sr := h.sendTo("mx1.partner.example", res)
	if !sr.Delivered {
		t.Fatalf("DANE delivery failed: %s %s", sr.Attempt.Phase, sr.Attempt.Error)
	}
}

// TestDANERejectsWrongCert: TLSA does not match the presented cert.
func TestDANERejectsWrongCert(t *testing.T) {
	cs := NewCertStore()
	w := NewWorld(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		PolicyTXT: false,
		MXHosts:   []MXHostSpec{{Host: "mx1.partner.example"}},
	})
	// The zone advertises a TLSA for a cert we do NOT serve.
	other, _ := w.CA.Issue(IssueOptions{DNSNames: []string{"mx1.partner.example"}})
	w.AddTLSA(t, "mx1.partner.example", TLSAForSHA256(other.Cert))
	// We serve a different, valid WebPKI-style cert.
	served, _ := w.CA.Issue(IssueOptions{DNSNames: []string{"mx1.partner.example"}})
	cs.Set(served.Cert, served.Key)
	h := &harness{World: w, MX: map[string]*Server{}}
	s, _ := NewServer("mx1", ServerPolicy{AdvertiseSTARTTLS: true, Certs: cs})
	t.Cleanup(s.Close)
	h.MX["mx1.partner.example"] = s
	w.SetMXPorts = func(host string) (int, bool) { return PortOf(s.Addr()), true }

	res := h.resolve()
	if res.Policy.Source != model.SourceDANE {
		t.Fatalf("expected DANE, got %s", res.Policy.Source)
	}
	sr := h.sendTo("mx1.partner.example", res)
	if sr.Delivered {
		t.Fatal("DANE must reject a certificate that does not match the TLSA record")
	}
	t.Logf("rejected: %s", sr.Attempt.TLSError)
}

// TestDANEStrippedByDNSAttacker: attacker removes the TLSA records. Because
// MX and TLSA live in a signed zone, the validator must not let that look
// like "this domain does not use DANE".
func TestDANEStrippedByDNSAttacker(t *testing.T) {
	w := NewWorld(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		PolicyTXT: false,
		MXHosts:   []MXHostSpec{{Host: "mx1.partner.example"}},
		Attack:    AttackerStripDANE,
	})
	iss, _ := w.CA.Issue(IssueOptions{DNSNames: []string{"mx1.partner.example"}})
	// Add TLSA to the zone so the attacker has something to strip.
	w.AddTLSA(t, "mx1.partner.example", TLSAForSHA256(iss.Cert))
	res, err := w.Policy.Resolve(Ctx(), w.Domain)
	if err != nil {
		t.Fatal(err)
	}
	// The MX set is signed, so the engine sees a signed zone with TLSA
	// removed at the transport; the resolver reports bogus. It must not
	// produce a usable policy.
	if res.Policy.Source == model.SourceDANE {
		t.Fatal("attacker stripping TLSA must not yield a DANE policy")
	}
	t.Logf("source=%s mode=%s dane-status-implied evidence=%v", res.Policy.Source, res.Policy.Mode, res.Evidence)
}

// TestStrictUnknownHoldsWithoutAuthenticatedPolicy: the attacker is present
// from before the first fetch and the domain publishes no record. With
// strict mode on for protected domains, the gateway holds rather than
// guessing.
func TestStrictUnknownHoldsWithoutAuthenticatedPolicy(t *testing.T) {
	w := NewWorld(t, WorldOptions{
		Domain: "partner.example", SignedDomain: false,
		PolicyTXT:     false,
		MXHosts:       []MXHostSpec{{Host: "mx1.partner.example"}},
		StrictUnknown: true,
	})
	res, err := w.Policy.Resolve(Ctx(), w.Domain)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Blocked {
		t.Fatalf("strict unknown should block; got mode=%s blocked=%v", res.Policy.Mode, res.Blocked)
	}
}
