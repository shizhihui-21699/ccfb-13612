package lab

import (
	"testing"

	"gateway/internal/model"
)

// TestNoCleartextUnderEnforceAcrossScenarios is a belt-and-braces audit of
// the central invariant: in every configuration the lab can build, a server
// that would accept cleartext never receives a message while the effective
// policy is enforce.
func TestNoCleartextUnderEnforceAcrossScenarios(t *testing.T) {
	const body = "version: STSv1\nmode: enforce\nmx: mx1.partner.example\nmax_age: 86400\n"
	scenarios := []struct {
		name string
		pol  ServerPolicy
		// certFor returns the names to put in the presented certificate.
		certNames []string
		goodCert  bool
		// wantBlocked says the attempt must fail.
		wantBlocked bool
	}{
		{name: "tls works", pol: ServerPolicy{AdvertiseSTARTTLS: true},
			certNames: []string{"mx1.partner.example"}, goodCert: true},
		{name: "no starttls", pol: ServerPolicy{AdvertiseSTARTTLS: false},
			certNames: []string{"mx1.partner.example"}, goodCert: true, wantBlocked: true},
		{name: "broken handshake", pol: ServerPolicy{AdvertiseSTARTTLS: true, BreakHandshake: true},
			certNames: []string{"mx1.partner.example"}, goodCert: true, wantBlocked: true},
		{name: "wrong name", pol: ServerPolicy{AdvertiseSTARTTLS: true},
			certNames: []string{"mx2.partner.example"}, goodCert: true, wantBlocked: true},
		{name: "untrusted CA", pol: ServerPolicy{AdvertiseSTARTTLS: true},
			certNames: []string{"mx1.partner.example"}, goodCert: false, wantBlocked: true},
		{name: "454 on STARTTLS", pol: ServerPolicy{AdvertiseSTARTTLS: true, STARTTLSReply: 454},
			certNames: []string{"mx1.partner.example"}, goodCert: true, wantBlocked: true},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			cs := NewCertStore()
			pol := sc.pol
			pol.Certs = cs
			h := newHarness(t, WorldOptions{
				Domain: "partner.example", SignedDomain: true,
				PolicyTXT: true, PolicyID: "id1", PolicyBody: body,
				MXHosts: []MXHostSpec{{Host: "mx1.partner.example"}},
			}, map[string]ServerPolicy{"mx1.partner.example": pol})

			ca := h.CA
			if !sc.goodCert {
				var err error
				ca, err = NewCA("untrusted")
				if err != nil {
					t.Fatal(err)
				}
			}
			iss, err := ca.Issue(IssueOptions{DNSNames: sc.certNames})
			if err != nil {
				t.Fatal(err)
			}
			cs.Set(iss.Cert, iss.Key)

			res := h.resolve()
			if res.Policy.Mode != model.ModeEnforce {
				t.Fatalf("policy mode %s", res.Policy.Mode)
			}
			sr := h.sendTo("mx1.partner.example", res)
			if sc.wantBlocked && sr.Delivered {
				t.Fatalf("delivered although the policy could not be satisfied (phase %s)", sr.Attempt.Phase)
			}
			if !sc.wantBlocked && !sr.Delivered {
				t.Fatalf("failed to deliver on a compliant path: %s %s", sr.Attempt.Phase, sr.Attempt.Error)
			}
			_, clear, _, _ := h.MX["mx1.partner.example"].Stats()
			if clear != 0 {
				t.Fatalf("server accepted %d cleartext messages under enforce", clear)
			}
			// If any bytes followed EHLO on an unencrypted connection the
			// server would have counted a cleartext acceptance; the
			// counter above is the end-to-end check.
		})
	}
}
