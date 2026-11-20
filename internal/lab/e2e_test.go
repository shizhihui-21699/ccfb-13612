package lab

import (
	"context"
	"testing"
	"time"

	"gateway/internal/model"
	"gateway/internal/policy"
	"gateway/internal/smtpc"
)

// harness wires a World to a real SMTP client and queue.
type harness struct {
	*World
	MX   map[string]*Server
	Cert map[string]*CertStore
}

func (h *harness) resolve() *policy.Resolution {
	h.T.Helper()
	res, err := h.Policy.Resolve(Ctx(), h.Domain)
	if err != nil {
		h.T.Fatalf("resolve: %v", err)
	}
	return res
}

// newHarness builds a world plus SMTP servers on loopback, one per host.
func newHarness(t *testing.T, o WorldOptions, policyFor map[string]ServerPolicy) *harness {
	t.Helper()
	w := NewWorld(t, o)
	h := &harness{World: w, MX: map[string]*Server{}, Cert: map[string]*CertStore{}}
	for host, pol := range policyFor {
		if pol.Certs != nil {
			h.Cert[host] = pol.Certs
		}
		s, err := NewServer(host, pol)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		h.MX[host] = s
	}
	// Attach ports to the resolved MX hosts.
	w.SetMXPorts = func(host string) (int, bool) {
		if s, ok := h.MX[host]; ok {
			return PortOf(s.Addr()), true
		}
		return 0, false
	}
	return h
}

func (h *harness) client() *smtpc.Client {
	return smtpc.New(smtpc.Config{
		HeloName: "gateway.test",
		Timeout:  5 * time.Second,
		Roots:    h.CA.Pool(),
	})
}

func (h *harness) sender() *smtpc.Client { return h.client() }

// sendTo attempts delivery to the named MX under the policy currently in
// force, and returns the attempt.
func (h *harness) sendTo(mx string, res *policy.Resolution) *smtpc.SendResult {
	h.T.Helper()
	var host model.MXHost
	found := false
	for _, m := range res.MX {
		if m.Host == mx {
			host = m
			found = true
		}
	}
	if !found {
		h.T.Fatalf("mx %s not in resolution %+v", mx, res.MX)
	}
	msg := &smtpc.Message{
		From: "sender@corp.test", To: []string{"ops@" + h.Domain},
		Body:           []byte("Subject: hello\r\n\r\nbody\r\n"),
		RequireTLS:     res.Policy.RequiresTLS(),
		PolicyMX:       res.Policy.MX,
		TLSA:           res.Policy.TLSA,
		MXDNSSECStatus: res.MXStatus,
	}
	return h.client().Send(context.Background(), host, msg)
}
