package lab

import (
	"testing"

	"gateway/internal/model"
)

const enforceBody = `version: STSv1
mode: enforce
mx: mx1.partner.example
max_age: 86400
`

// TestEnforceDeliversOverTLS is the happy path: policy says enforce, the
// server presents a certificate the private CA signed for the MX name, and
// delivery completes over TLS.
func TestEnforceDeliversOverTLS(t *testing.T) {
	cs := NewCertStore()
	caHolder := struct{ ca *CA }{}
	_ = caHolder
	h := newHarness(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		PolicyTXT: true, PolicyID: "id1", PolicyBody: enforceBody,
		MXHosts: []MXHostSpec{{Host: "mx1.partner.example"}},
	}, map[string]ServerPolicy{
		"mx1.partner.example": {AdvertiseSTARTTLS: true, Certs: cs},
	})
	iss, err := h.CA.Issue(IssueOptions{DNSNames: []string{"mx1.partner.example"}})
	if err != nil {
		t.Fatal(err)
	}
	cs.Set(iss.Cert, iss.Key)

	res := h.resolve()
	if res.Policy.Mode != model.ModeEnforce {
		t.Fatalf("mode %s", res.Policy.Mode)
	}
	sr := h.sendTo("mx1.partner.example", res)
	if !sr.Delivered {
		t.Fatalf("not delivered: phase=%s err=%s tls=%s", sr.Attempt.Phase, sr.Attempt.Error, sr.Attempt.TLSError)
	}
	if !sr.Attempt.TLSStarted {
		t.Fatal("delivered without TLS under enforce")
	}
	if sr.Attempt.TLSVersion < 0x0303 {
		t.Fatalf("TLS version %x too old", sr.Attempt.TLSVersion)
	}
	acc, clear, vers, _ := h.MX["mx1.partner.example"].Stats()
	if acc != 1 || clear != 0 {
		t.Fatalf("accepted=%d cleartext=%d", acc, clear)
	}
	t.Logf("tls version %x cipher %x", vers[0], sr.Attempt.CipherSuite)
}

// TestEnforceNeverDowngradesWhenSTARTTLSStripped is the attack the brief
// opens with: the MITM removes STARTTLS from EHLO. The gateway must not
// deliver in cleartext, and nothing may be written after EHLO.
func TestEnforceNeverDowngradesWhenSTARTTLSStripped(t *testing.T) {
	cs := NewCertStore()
	h := newHarness(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		PolicyTXT: true, PolicyID: "id1", PolicyBody: enforceBody,
		MXHosts: []MXHostSpec{{Host: "mx1.partner.example"}},
	}, map[string]ServerPolicy{
		"mx1.partner.example": {AdvertiseSTARTTLS: false, Certs: cs},
	})
	res := h.resolve()
	sr := h.sendTo("mx1.partner.example", res)
	if sr.Delivered {
		t.Fatal("delivered in cleartext under enforce: attacker succeeded")
	}
	if sr.Attempt.Phase != "starttls-missing" {
		t.Fatalf("phase = %s", sr.Attempt.Phase)
	}
	acc, clear, _, _ := h.MX["mx1.partner.example"].Stats()
	if acc != 0 {
		t.Fatalf("server accepted %d messages", acc)
	}
	if clear != 0 {
		t.Fatalf("cleartext messages accepted: %d", clear)
	}
	t.Logf("blocked at %s: %s", sr.Attempt.Phase, sr.Attempt.Error)
}

// TestEnforceCertificateMismatchBlocks: a MITM with its own certificate.
func TestEnforceCertificateMismatchBlocks(t *testing.T) {
	// Attacker CA, not the one the gateway trusts.
	attackerCA, err := NewCA("attacker root")
	if err != nil {
		t.Fatal(err)
	}
	cs := NewCertStore()
	iss, err := attackerCA.Issue(IssueOptions{DNSNames: []string{"mx1.partner.example"}})
	if err != nil {
		t.Fatal(err)
	}
	cs.Set(iss.Cert, iss.Key)

	h := newHarness(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		PolicyTXT: true, PolicyID: "id1", PolicyBody: enforceBody,
		MXHosts: []MXHostSpec{{Host: "mx1.partner.example"}},
	}, map[string]ServerPolicy{
		"mx1.partner.example": {AdvertiseSTARTTLS: true, Certs: cs},
	})
	res := h.resolve()
	sr := h.sendTo("mx1.partner.example", res)
	if sr.Delivered {
		t.Fatal("delivered to an untrusted certificate")
	}
	if sr.Attempt.Phase != "tls" {
		t.Fatalf("phase = %s (%s)", sr.Attempt.Phase, sr.Attempt.Error)
	}
	if sr.Attempt.PeerCertVerifyError == "" {
		t.Fatal("expected a verification error to be recorded")
	}
	if sr.Attempt.TLSPolicyOK {
		t.Fatal("TLSPolicyOK must be false for an untrusted chain")
	}
	t.Logf("blocked: %s", sr.Attempt.TLSError)
}

// TestOpportunisticWithoutPolicy: no policy means cleartext is allowed, and
// the report must say the message went out unencrypted.
func TestOpportunisticWithoutPolicy(t *testing.T) {
	cs := NewCertStore()
	h := newHarness(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		PolicyTXT: false,
		MXHosts:   []MXHostSpec{{Host: "mx1.partner.example"}},
	}, map[string]ServerPolicy{
		"mx1.partner.example": {AdvertiseSTARTTLS: false, Certs: cs},
	})
	res := h.resolve()
	if res.Policy.Mode != model.ModeNone {
		t.Fatalf("mode = %s", res.Policy.Mode)
	}
	sr := h.sendTo("mx1.partner.example", res)
	if !sr.Delivered {
		t.Fatalf("opportunistic delivery should succeed: %s %s", sr.Attempt.Phase, sr.Attempt.Error)
	}
	if sr.Attempt.TLSStarted {
		t.Fatal("unexpected TLS")
	}
	acc, clear, _, _ := h.MX["mx1.partner.example"].Stats()
	if acc != 1 || clear != 1 {
		t.Fatalf("accepted=%d cleartext=%d", acc, clear)
	}
}

// TestNoCleartextFallbackAfterFailedHandshake pins RFC 3207 §4.2 and its
// security rationale: once the peer accepts STARTTLS, the connection is
// discarded if the handshake fails. Retrying in plaintext is exactly the
// downgrade an active attacker is trying to induce.
func TestNoCleartextFallbackAfterFailedHandshake(t *testing.T) {
	cs := NewCertStore()
	h := newHarness(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		PolicyTXT: false, // opportunistic: no policy at all
		MXHosts:   []MXHostSpec{{Host: "mx1.partner.example"}},
	}, map[string]ServerPolicy{
		"mx1.partner.example": {AdvertiseSTARTTLS: true, BreakHandshake: true, Certs: cs},
	})
	res := h.resolve()
	if res.Policy.Mode != model.ModeNone {
		t.Fatalf("mode = %s", res.Policy.Mode)
	}
	sr := h.sendTo("mx1.partner.example", res)
	if sr.Delivered {
		t.Fatal("fell back to cleartext after a failed STARTTLS handshake")
	}
	if sr.Attempt.Phase != "tls" {
		t.Fatalf("phase = %s", sr.Attempt.Phase)
	}
	acc, clear, _, _ := h.MX["mx1.partner.example"].Stats()
	if acc != 0 || clear != 0 {
		t.Fatalf("server accepted: %d total, %d cleartext", acc, clear)
	}
}
