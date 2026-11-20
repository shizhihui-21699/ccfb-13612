// Package report turns per-delivery results into the two artifacts an
// operator actually uses: a machine-readable JSON feed and a human summary
// that separates "somebody attacked us" from "the partner is broken".
//
// The separation is the point. A report that says "27 failures" is unusable;
// a report that says "1 suspected interception, 26 deliveries to one MX that
// has not presented a valid certificate since Tuesday" tells you what to do
// next, and which of the two is worth waking someone for.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"gateway/internal/classify"
	"gateway/internal/model"
)

// Delivery is one classified delivery attempt cycle for one message.
type Delivery struct {
	ID     string    `json:"id"`
	Domain string    `json:"domain"`
	From   string    `json:"from"`
	To     []string  `json:"to"`
	At     time.Time `json:"at"`

	Outcome     model.Outcome    `json:"outcome"`
	Fault       model.FaultClass `json:"fault"`
	Confidence  float64          `json:"confidence"`
	Explanation string           `json:"explanation"`

	PolicyMode   model.Mode      `json:"policy_mode"`
	PolicySource model.Source    `json:"policy_source"`
	PolicyID     string          `json:"policy_id,omitempty"`
	PolicyDNSSEC model.DNSStatus `json:"policy_dnssec,omitempty"`
	Generation   uint64          `json:"policy_generation"`

	// Observation is what the latest policy lookup actually saw, which may
	// be weaker than the policy in force.
	Observation Observation `json:"observation,omitempty"`

	Attempts []AttemptReport  `json:"attempts,omitempty"`
	Signals  []model.Evidence `json:"signals,omitempty"`
	// Released marks a deliberate cleartext release after an authenticated
	// withdrawal of enforcement.
	Released bool `json:"released,omitempty"`
	// PolicyHistory shows the transitions that explain the outcome.
	PolicyHistory []model.Transition `json:"policy_history,omitempty"`
}

type Observation struct {
	TXTStatus  model.DNSStatus `json:"txt_status,omitempty"`
	TXTPresent bool            `json:"txt_present"`
	FetchError string          `json:"fetch_error,omitempty"`
}

type AttemptReport struct {
	MX           string   `json:"mx"`
	Addr         string   `json:"addr,omitempty"`
	Pref         uint16   `json:"pref"`
	Phase        string   `json:"phase"`
	TLSStarted   bool     `json:"tls_started"`
	TLSVersion   string   `json:"tls_version,omitempty"`
	PolicyOK     bool     `json:"tls_policy_ok"`
	CertSHA256   string   `json:"cert_sha256,omitempty"`
	CertIssuer   string   `json:"cert_issuer,omitempty"`
	CertDNSNames []string `json:"cert_dns_names,omitempty"`
	VerifyError  string   `json:"cert_verify_error,omitempty"`
	TLSError     string   `json:"tls_error,omitempty"`
	SMTPReply    int      `json:"smtp_reply,omitempty"`
	DurationMS   int64    `json:"duration_ms"`
}

// FromAttempt converts a model.Attempt for the report.
func FromAttempt(a model.Attempt) AttemptReport {
	return AttemptReport{
		MX: a.MX, Addr: a.Addr, Pref: a.MXPref, Phase: a.Phase,
		TLSStarted: a.TLSStarted, TLSVersion: tlsName(a.TLSVersion),
		PolicyOK: a.TLSPolicyOK, CertSHA256: a.PeerCertSum,
		CertIssuer: a.PeerIssuer, CertDNSNames: a.PeerDNSNames,
		VerifyError: a.PeerCertVerifyError, TLSError: a.TLSError,
		SMTPReply: a.SMTPReply, DurationMS: a.Duration.Milliseconds(),
	}
}

func tlsName(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS1.3"
	case 0x0303:
		return "TLS1.2"
	case 0x0302:
		return "TLS1.1"
	case 0x0301:
		return "TLS1.0"
	}
	if v == 0 {
		return ""
	}
	return fmt.Sprintf("0x%04x", v)
}

// WriteJSON emits the feed.
func WriteJSON(w io.Writer, ds []Delivery) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		GeneratedAt time.Time  `json:"generated_at"`
		Deliveries  []Delivery `json:"deliveries"`
	}{time.Now().UTC(), ds})
}

// Summary is the aggregated human view.
type Summary struct {
	Total              int
	DeliveredTLS       int
	DeliveredCleartext int
	Blocked            int
	Deferred           int
	Released           int
	ByFault            map[model.FaultClass][]Delivery
	Domains            map[string]int
	AttackDomains      []string
	MisconfigDomains   []string
	RolloverDomains    []string
	// UnauthenticatedObservations counts deliveries where the policy lookup
	// was not DNSSEC-secure. It is the honest measure of how much of the
	// fleet is protected by authentication versus by luck.
	UnauthenticatedObservations int
}

// Aggregate builds a Summary.
func Aggregate(ds []Delivery) Summary {
	s := Summary{
		ByFault: map[model.FaultClass][]Delivery{},
		Domains: map[string]int{},
	}
	attack := map[string]bool{}
	misconfig := map[string]bool{}
	rollover := map[string]bool{}
	for _, d := range ds {
		s.Total++
		s.Domains[d.Domain]++
		switch d.Outcome {
		case model.OutDeliveredTLS:
			s.DeliveredTLS++
		case model.OutDeliveredCleartext:
			s.DeliveredCleartext++
		case model.OutBlocked:
			s.Blocked++
		case model.OutDeferred:
			s.Deferred++
		}
		if d.Released {
			s.Released++
		}
		if d.Observation.TXTStatus != "" && d.Observation.TXTStatus != model.DNSSecure &&
			d.Observation.TXTStatus != model.DNSInsecure {
			s.UnauthenticatedObservations++
		}
		s.ByFault[d.Fault] = append(s.ByFault[d.Fault], d)
		switch d.Fault {
		case model.FaultAttackSuspected:
			attack[d.Domain] = true
		case model.FaultRemoteMisconfig:
			misconfig[d.Domain] = true
		case model.FaultRolloverInProgress:
			rollover[d.Domain] = true
		}
	}
	s.AttackDomains = keys(attack)
	s.MisconfigDomains = keys(misconfig)
	s.RolloverDomains = keys(rollover)
	return s
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// WriteText renders the operator summary.
//
// Ordering is deliberate: anything that looks like interception comes first,
// because that is the category where a delay has a cost. Misconfiguration
// and rollover follow, as work to schedule rather than alarms.
func WriteText(w io.Writer, ds []Delivery) {
	s := Aggregate(ds)
	fmt.Fprintf(w, "deliveries: %d\n", s.Total)
	fmt.Fprintf(w, "  over policy-compliant TLS : %d\n", s.DeliveredTLS)
	fmt.Fprintf(w, "  cleartext                 : %d", s.DeliveredCleartext)
	if s.Released > 0 {
		fmt.Fprintf(w, " (%d released after an authenticated withdrawal of enforcement)", s.Released)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  blocked                   : %d\n", s.Blocked)
	fmt.Fprintf(w, "  deferred                  : %d\n", s.Deferred)
	fmt.Fprintf(w, "  policy lookups not DNSSEC-secure: %d\n", s.UnauthenticatedObservations)

	if n := len(s.ByFault[model.FaultAttackSuspected]); n > 0 {
		fmt.Fprintf(w, "\nSUSPECTED INTERCEPTION (%d)\n", n)
		writeGroup(w, s.ByFault[model.FaultAttackSuspected])
		fmt.Fprintf(w, "  action: do not retry these paths; compare the certificate and DNS answers against a trusted vantage point\n")
	}
	if n := len(s.ByFault[model.FaultRemoteMisconfig]); n > 0 {
		fmt.Fprintf(w, "\nREMOTE MISCONFIGURATION (%d)\n", n)
		writeGroup(w, s.ByFault[model.FaultRemoteMisconfig])
		fmt.Fprintf(w, "  action: notify the remote postmaster; retries are safe\n")
	}
	if n := len(s.ByFault[model.FaultRolloverInProgress]); n > 0 {
		fmt.Fprintf(w, "\nROLLOVER IN PROGRESS (%d)\n", n)
		writeGroup(w, s.ByFault[model.FaultRolloverInProgress])
		fmt.Fprintf(w, "  action: nothing; wait for the deployment to finish\n")
	}
	if n := len(s.ByFault[model.FaultPolicyUnavailable]); n > 0 {
		fmt.Fprintf(w, "\nPOLICY UNAVAILABLE (%d)\n", n)
		writeGroup(w, s.ByFault[model.FaultPolicyUnavailable])
		fmt.Fprintf(w, "  action: check DNS and the policy host; delivery is being held, not downgraded\n")
	}
	if n := len(s.ByFault[model.FaultPolicyDowngrade]); n > 0 {
		fmt.Fprintf(w, "\nREFUSED DOWNGRADE (%d)\n", n)
		writeGroup(w, s.ByFault[model.FaultPolicyDowngrade])
		fmt.Fprintf(w, "  action: a domain's policy weakened without an authenticated transition; messages are being held at the stronger policy\n")
	}
}

func writeGroup(w io.Writer, ds []Delivery) {
	// One line per domain, with the strongest signal as the reason.
	byDomain := map[string][]Delivery{}
	var order []string
	for _, d := range ds {
		if _, ok := byDomain[d.Domain]; !ok {
			order = append(order, d.Domain)
		}
		byDomain[d.Domain] = append(byDomain[d.Domain], d)
	}
	sort.Strings(order)
	for _, dom := range order {
		group := byDomain[dom]
		d := group[0]
		fmt.Fprintf(w, "  %-28s %2d message(s)  conf=%.2f  %s\n",
			dom, len(group), d.Confidence, truncate(d.Explanation, 110))
		for _, sig := range d.Signals {
			fmt.Fprintf(w, "      - %s: %s\n", sig.Code, truncate(sig.Detail, 130))
		}
	}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// Build assembles a Delivery from the pieces the queue and classifier
// produce.
func Build(id, domain, from string, to []string, at time.Time,
	pol *model.Policy, obs Observation, attempts []model.Attempt,
	v classify.Verdict, outcome model.Outcome, history []model.Transition, released bool) Delivery {

	d := Delivery{
		ID: id, Domain: domain, From: from, To: to, At: at,
		Outcome: outcome, Fault: v.Fault, Confidence: v.Confidence,
		Explanation: v.Explanation, Observation: obs, Released: released,
		Signals:       append([]model.Evidence(nil), v.Signals...),
		PolicyHistory: history,
	}
	if pol != nil {
		d.PolicyMode = pol.Mode
		d.PolicySource = pol.Source
		d.PolicyID = pol.PolicyID
		d.PolicyDNSSEC = pol.DNSSEC
		d.Generation = pol.Generation
	}
	for _, a := range attempts {
		d.Attempts = append(d.Attempts, FromAttempt(a))
	}
	return d
}
