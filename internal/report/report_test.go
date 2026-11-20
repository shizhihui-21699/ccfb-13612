package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"gateway/internal/model"
)

func TestOrderingPutsAttacksFirst(t *testing.T) {
	now := time.Now()
	ds := []Delivery{
		{Domain: "broken.example", Fault: model.FaultRemoteMisconfig, Confidence: 0.7,
			Explanation: "handshake failed"},
		{Domain: "evil.example", Fault: model.FaultAttackSuspected, Confidence: 0.9,
			Explanation: "STARTTLS stripped after a prior clean session",
			Signals:     []model.Evidence{{Code: "starttls_stripped_after_prior_tls"}}},
		{Domain: "roll.example", Fault: model.FaultRolloverInProgress, Confidence: 0.7,
			Explanation: "sibling MX certificate"},
		{At: now, Domain: "ok.example", Outcome: model.OutDeliveredTLS, Fault: model.FaultNone},
	}
	var b bytes.Buffer
	WriteText(&b, ds)
	out := b.String()
	iAttack := strings.Index(out, "SUSPECTED INTERCEPTION")
	iConfig := strings.Index(out, "REMOTE MISCONFIGURATION")
	iRoll := strings.Index(out, "ROLLOVER")
	if iAttack < 0 || iConfig < 0 || iRoll < 0 {
		t.Fatalf("missing sections:\n%s", out)
	}
	if !(iAttack < iConfig && iConfig < iRoll) {
		t.Fatalf("sections out of order:\n%s", out)
	}
	if !strings.Contains(out, "evil.example") {
		t.Fatal("attacking domain missing from report")
	}
}

func TestReleaseIsExplicit(t *testing.T) {
	ds := []Delivery{
		{Domain: "d", Outcome: model.OutDeliveredCleartext, Released: true},
		{Domain: "d", Outcome: model.OutDeliveredCleartext},
	}
	var b bytes.Buffer
	WriteText(&b, ds)
	if !strings.Contains(b.String(), "released") {
		t.Fatalf("release not called out:\n%s", b.String())
	}
}

func TestJSONIsStable(t *testing.T) {
	ds := []Delivery{{Domain: "d", Outcome: model.OutDeliveredTLS, Fault: model.FaultNone,
		PolicyMode: model.ModeEnforce, PolicyDNSSEC: model.DNSSecure}}
	var b bytes.Buffer
	if err := WriteJSON(&b, ds); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{`"outcome": "delivered_tls"`, `"policy_mode": "enforce"`, `"policy_dnssec": "secure"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in:\n%s", want, s)
		}
	}
}
