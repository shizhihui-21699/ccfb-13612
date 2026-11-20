// Package model holds the types shared by the policy engine, the SMTP
// client, the queue and the reporter. It is deliberately dependency-free so
// that every other package can import it without cycles.
package model

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Mode is the effective transport-security posture for a recipient domain.
// The ordering is a security lattice: a higher value is stricter. Several
// decisions in the gateway are expressed as "never move to a lower value
// without authenticated evidence", so the numeric ordering is load-bearing.
type Mode int

const (
	// ModeNone means we have no trustworthy policy. Opportunistic STARTTLS
	// is what every ordinary MTA does; it is also the state an on-path
	// attacker wants us to be in.
	ModeNone Mode = iota
	// ModeTesting means the domain publishes MTA-STS in testing mode: try
	// TLS, report failures, but do not block delivery.
	ModeTesting
	// ModeEnforce means delivery must use TLS that satisfies the policy, or
	// the message is held. No cleartext fallback, ever.
	ModeEnforce
)

func (m Mode) String() string {
	switch m {
	case ModeNone:
		return "none"
	case ModeTesting:
		return "testing"
	case ModeEnforce:
		return "enforce"
	}
	return fmt.Sprintf("mode(%d)", int(m))
}

func (m Mode) MarshalText() ([]byte, error) { return []byte(m.String()), nil }
func (m *Mode) UnmarshalText(b []byte) error {
	switch string(b) {
	case "none":
		*m = ModeNone
	case "testing":
		*m = ModeTesting
	case "enforce":
		*m = ModeEnforce
	default:
		return fmt.Errorf("unknown mode %q", b)
	}
	return nil
}

// Source says which policy mechanism produced an effective policy.
type Source string

const (
	SourceNone   Source = "none"
	SourceMTASTS Source = "mta-sts"
	SourceDANE   Source = "dane"
)

// DNSStatus is the outcome of DNSSEC validation for a name/RRset.
type DNSStatus string

const (
	// DNSSecure: the answer (including authenticated denial of existence)
	// chains to the configured trust anchor.
	DNSSecure DNSStatus = "secure"
	// DNSInsecure: there is a provable unsigned delegation somewhere on the
	// path. The answer may be authentic in the sense of "not tampered with
	// by this resolver", but nobody signed it.
	DNSInsecure DNSStatus = "insecure"
	// DNSBogus: the parent delegates with DS but the answer does not
	// validate. This is what tampering in a signed zone looks like, and
	// also what a broken zone looks like.
	DNSBogus DNSStatus = "bogus"
	// DNSIndeterminate: we could not get enough data to decide (timeout,
	// network error, unsupported algorithm). Never treat as secure.
	DNSIndeterminate DNSStatus = "indeterminate"
)

// Policy is a resolved, cacheable statement about how to reach one domain.
type Policy struct {
	Domain string
	Mode   Mode
	Source Source

	// MX is the allowed MX pattern list from MTA-STS. Empty means "not
	// constrained by STS" (DANE and opportunistic paths do not use it, but
	// an MTA-STS policy always has at least one entry).
	MX []string

	// MaxAge is the policy lifetime from MaxAge= in mta-sts.txt, or the DNS
	// TTL for a DANE-derived policy.
	MaxAge time.Duration

	// PolicyID is the id= from the _mta-sts TXT record, or "dane" for a
	// DANE-derived policy.
	PolicyID string

	// DNSSEC is the validation status of the records this policy rests on:
	// the _mta-sts TXT record and the mta-sts host, or the TLSA/MX set.
	DNSSEC DNSStatus

	// TLSA maps a lowercased MX host to the TLSA records published for it.
	// It is per host on purpose: RFC 7672 requires delivering to a host
	// whose own TLSA set matches its own certificate, and flattening the
	// sets across a domain turns a fasle per-host check into a global one.
	TLSA map[string][]TLSARecord
	// TLSAAll is the same data flattened, for the report.
	TLSAAll []TLSARecord

	FetchedAt time.Time
	ExpiresAt time.Time

	// Generation is a per-domain monotonic counter bumped whenever the
	// effective policy changes. A delivery in flight compares the
	// generation it started with against the current one immediately
	// before DATA, which closes the resolve→send window.
	Generation uint64

	Evidence []Evidence
}

// RequiresTLS reports whether cleartext delivery is forbidden.
func (p *Policy) RequiresTLS() bool { return p.Mode == ModeEnforce }

// Expired reports whether the policy is past its lifetime at t.
func (p *Policy) Expired(t time.Time) bool { return !t.Before(p.ExpiresAt) }

// MatchesMX reports whether host is permitted by the STS mx list. A leading
// "*." matches exactly one label, per RFC 8461 section 4.1.
func (p *Policy) MatchesMX(host string) bool {
	if len(p.MX) == 0 {
		return true // DANE / unconstrained
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pat := range p.MX {
		pat = strings.ToLower(pat)
		if pat == host {
			return true
		}
		if strings.HasPrefix(pat, "*.") {
			suffix := pat[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) {
				label := host[:len(host)-len(suffix)]
				if label != "" && !strings.Contains(label, ".") {
					return true
				}
			}
		}
	}
	return false
}

// TLSARecord is a parsed TLSA RR (RFC 6698).
type TLSARecord struct {
	Usage        uint8 // 0 PKIX-TA, 1 PKIX-EE, 2 DANE-TA, 3 DANE-EE
	Selector     uint8 // 0 full cert, 1 SPKI
	MatchingType uint8 // 0 exact, 1 SHA-256, 2 SHA-512
	Data         []byte
	TTL          time.Duration
}

func (t TLSARecord) String() string {
	return fmt.Sprintf("TLSA %d %d %d %x", t.Usage, t.Selector, t.MatchingType, t.Data)
}

// Evidence is one observation that a classifier can use. Codes are stable
// strings so that reports can be aggregated and diffed over time.
type Evidence struct {
	Code   string    `json:"code"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

func Ev(code, detail string) Evidence {
	return Evidence{Code: code, Detail: detail, At: time.Now()}
}

// FaultClass is the report's best explanation for why a delivery did not
// complete as expected. It is a judgement, not a fact; Confidence carries
// how strongly the signals support it.
type FaultClass string

const (
	FaultNone               FaultClass = "none"
	FaultAttackSuspected    FaultClass = "attack_suspected"
	FaultRemoteMisconfig    FaultClass = "remote_misconfiguration"
	FaultRolloverInProgress FaultClass = "rollover_in_progress"
	FaultPolicyUnavailable  FaultClass = "policy_unavailable"
	FaultPolicyDowngrade    FaultClass = "policy_downgrade_attempt"
	FaultUnclassified       FaultClass = "unclassified"
)

// Outcome is what happened to one delivery attempt, independent of why.
type Outcome string

const (
	// OutDeliveredTLS: message accepted by the remote MTA over TLS that
	// satisfied the effective policy.
	OutDeliveredTLS Outcome = "delivered_tls"
	// OutDeliveredCleartext: message accepted without TLS. Legal only when
	// PolicyAtSend is none or testing and CleartextAuthorized is set.
	OutDeliveredCleartext Outcome = "delivered_cleartext"
	// OutBlocked: policy forbade every available path; nothing was sent.
	OutBlocked Outcome = "blocked"
	// OutDeferred: transient failure or unresolved policy; retry later.
	OutDeferred Outcome = "deferred"
	// OutRejected: remote permanently refused (5xx) on a channel that was
	// already policy-compliant.
	OutRejected Outcome = "rejected"
)

// Attempt is one connection to one MX host, with everything the client and
// the TLS layer observed. It is the raw material for classification.
type Attempt struct {
	MX       string        `json:"mx"`
	Addr     string        `json:"addr,omitempty"`
	MXPref   uint16        `json:"mx_pref"`
	Started  time.Time     `json:"started"`
	Duration time.Duration `json:"duration"`
	Phase    string        `json:"phase"` // where it stopped

	Connected          bool     `json:"connected"`
	Banner             string   `json:"banner,omitempty"`
	EHLO               []string `json:"ehlo,omitempty"`
	StartTLSAdvertised bool     `json:"starttls_advertised"`
	StartTLSReply      int      `json:"starttls_reply,omitempty"`
	TLSStarted         bool     `json:"tls_started"`
	TLSVersion         uint16   `json:"tls_version,omitempty"`
	CipherSuite        uint16   `json:"cipher_suite,omitempty"`
	// PeerCerts is the chain as presented, leaf first, DER.
	PeerCerts    [][]byte `json:"-"`
	PeerCertSum  string   `json:"peer_cert_sha256,omitempty"`
	PeerIssuer   string   `json:"peer_issuer,omitempty"`
	PeerDNSNames []string `json:"peer_dns_names,omitempty"`
	// PeerCertVerifyError is the WebPKI verification error, if any.
	PeerCertVerifyError string `json:"peer_cert_verify_error,omitempty"`
	// TLSPolicyOK says whether the configured policy (DANE or STS) was
	// satisfied by the presented chain.
	TLSPolicyOK bool   `json:"tls_policy_ok"`
	TLSError    string `json:"tls_error,omitempty"`

	// DNSSECOfMX is the validation status of the MX host's address RRset.
	DNSSECOfMX DNSStatus `json:"dnssec_of_mx,omitempty"`
	// MXSource is where the MX list came from ("dns" or "cache").
	MXSource string `json:"mx_source,omitempty"`

	SMTPReply int    `json:"smtp_reply,omitempty"`
	SMTPText  string `json:"smtp_text,omitempty"`
	// Permanent is true when the remote answered 5xx on a channel that was
	// already policy-compliant; the caller should not retry on this path.
	Permanent bool   `json:"permanent,omitempty"`
	Error     string `json:"error,omitempty"`
}

// AttemptResult pairs an attempt with the policy snapshot it was run under
// and the classified result.
type AttemptResult struct {
	Attempt
	Outcome    Outcome    `json:"outcome"`
	Fault      FaultClass `json:"fault"`
	Confidence float64    `json:"confidence"`
	Signals    []Evidence `json:"signals,omitempty"`
	// PolicyModeAtSend and PolicyGenerationAtSend are the guard rails: a
	// cleartext attempt that claims enforce here is a bug, and the lab
	// asserts it never happens.
	PolicyModeAtSend       Mode   `json:"policy_mode_at_send"`
	PolicyGenerationAtSend uint64 `json:"policy_generation_at_send"`
	CleartextAuthorized    bool   `json:"cleartext_authorized"`
}

// Ticker is a convenience for reports.
func (a *Attempt) Succeeded() bool { return a.Phase == "done" }

// Summary renders a one-line description for logs.
func (a *Attempt) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s ", a.MX)
	switch {
	case a.Phase == "done":
		b.WriteString("ok")
	case a.TLSPolicyOK:
		b.WriteString("tls-ok, ")
		fallthrough
	default:
		if a.Phase != "" {
			b.WriteString(a.Phase)
		}
	}
	if a.TLSError != "" {
		fmt.Fprintf(&b, " tls=%q", a.TLSError)
	}
	if a.Error != "" {
		fmt.Fprintf(&b, " err=%q", a.Error)
	}
	return b.String()
}

// MXHost is one resolved mail exchanger. It is resolved at policy time and
// carried into the client so that no DNS lookup happens at connect time:
// a lookup between "policy checked" and "socket opened" is a downgrade
// window an attacker can use.
type MXHost struct {
	Host      string
	Pref      uint16
	Addrs     []string
	DNSSEC    DNSStatus
	FromCache bool
	// Source records where the MX list came from, for the report.
	Source string
	// Port overrides 25. It exists only so the lab can run unprivileged
	// listeners on loopback; production resolution leaves it zero.
	Port int
}

// DialAddr returns the first address with the SMTP port. Empty Addrs means
// the address lookup failed and the caller should treat the host as
// unreachable (defer) rather than falling back to a name lookup.
func (m MXHost) DialAddr() string {
	port := m.Port
	if port == 0 {
		port = 25
	}
	p := strconv.Itoa(port)
	if len(m.Addrs) == 0 {
		return net.JoinHostPort(m.Host, p)
	}
	return net.JoinHostPort(m.Addrs[0], p)
}

// Transition is one accepted change to a domain's effective policy. It is
// the audit trail; the report uses it to explain mode changes and to tell a
// legitimate withdrawal of enforcement from an attack.
type Transition struct {
	At     time.Time `json:"at"`
	From   Mode      `json:"from"`
	To     Mode      `json:"to"`
	Source Source    `json:"source"`
	Reason string    `json:"reason"`
	Gen    uint64    `json:"generation"`
	DNSSEC DNSStatus `json:"dnssec,omitempty"`
}
