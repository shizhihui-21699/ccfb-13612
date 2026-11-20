// Package classify turns raw delivery observations into a fault class.
//
// The hard question this package answers is: when an enforcing policy could
// not be satisfied, was somebody attacking us, or is the remote broken?
//
// The distinction is not cosmetic. A misconfiguration means "keep retrying,
// tell the remote's postmaster, unfreeze when it clears". A suspected attack
// means "do not retry on this path, do not fall back, escalate". Getting it
// backwards in either direction is a real cost: calling every broken server
// an attack produces alert fatigue and eventually someone turns the check
// off; calling every attack a misconfiguration is exactly the downgrade
// this system exists to prevent.
//
// The signals below are chosen so that each one is hard for a single on-path
// attacker to fake in isolation, and so that several of them can be combined.
// Confidence is deliberately coarse: the report says how much it trusts its
// own conclusion, and the number is derived from which signals fired, not
// fitted to anything.
package classify

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gateway/internal/model"
)

// HostHistory is what we have previously and successfully seen from one MX
// host. It is the strongest single anti-MITM signal: an attacker who was not
// present for the earlier, clean connection cannot reproduce it.
type HostHistory struct {
	Host string
	// TLSValid is true if any earlier connection to this host completed a
	// TLS handshake whose certificate validated for the MX name.
	TLSValid bool
	// LastCertSHA256 is the leaf fingerprint seen on the last clean
	// connection.
	LastCertSHA256 string
	LastSeen       time.Time
	// LastDNSSEC is the validation status of the MX host's address RRset
	// on the last clean connection.
	LastDNSSEC model.DNSStatus
	// LastValidUntil is when that certificate expired.
	LastNotAfter time.Time
}

// Input is everything known about one delivery to one domain.
type Input struct {
	Domain string
	Policy *model.Policy
	// Attempts is every MX we tried, in order.
	Attempts []model.Attempt
	// MXSet is the MX host list resolved at policy time.
	MXSet []model.MXHost
	// History maps MX host -> last clean session.
	History map[string]HostHistory
	// PolicyHistory is the domain's accepted transitions.
	PolicyHistory []model.Transition
	// PolicyObservation is what the policy engine saw this refresh: the
	// DNSSEC status of the policy's DNS records, and whether the record was
	// absent.
	PolicyObs PolicyObservation
	// SharedHostFailures counts, across *other* recipient domains, how many
	// are currently failing the same way against the same MX host. It
	// breaks the "one attacker, one domain" ambiguity: a hijack targets a
	// domain, a broken server affects everyone who talks to it.
	SharedHostFailures map[string]int
	// Now is injectable for tests.
	Now time.Time
}

// PolicyObservation records DNS-level facts about the policy lookup itself.
type PolicyObservation struct {
	// TXTStatus is the DNSSEC status of the _mta-sts TXT lookup.
	TXTStatus model.DNSStatus
	// TXTPresent is whether any record was returned.
	TXTPresent bool
	// DANEStatus is the DNSSEC status of the MX/TLSA lookups.
	DANEStatus model.DNSStatus
	// FetchError is set when the policy file fetch failed.
	FetchError string
	// PreviouslySecure is true when the last accepted policy rested on
	// DNSSEC-validated DNS.
	PreviouslySecure bool
}

// Verdict is the classifier's output.
type Verdict struct {
	Fault      model.FaultClass
	Confidence float64
	Signals    []model.Evidence
	// Explanation is one sentence suitable for a human report.
	Explanation string
	// Retry says whether retrying later could plausibly succeed. An attack
	// is not retried on the same path; a misconfiguration is.
	Retry bool
	// Escalate says a human should look now.
	Escalate bool
}

type signal struct {
	code   string
	detail string
	// weight is the contribution to confidence, and the sign says which
	// class it supports.
	weight float64
	// class is the fault class this signal points at.
	class model.FaultClass
}

// Classify computes a verdict. It never returns an empty Signals slice: a
// report without its reasons is not actionable.
func Classify(in Input) Verdict {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	var sigs []signal

	policyMode := model.ModeNone
	if in.Policy != nil {
		policyMode = in.Policy.Mode
	}

	// Figure out the dominant failure shape.
	anyTLSOk := false
	anyDelivered := false
	startTLSMissing := 0
	tlsHandshakeFail := 0
	certPolicyFail := 0
	certUnknownCA := 0
	certNameMismatch := 0
	certExpired := 0
	connFail := 0
	authRequired := 0
	server5xx := 0
	for _, a := range in.Attempts {
		if a.Phase == "done" {
			anyDelivered = true
		}
		if a.TLSPolicyOK {
			anyTLSOk = true
		}
		switch a.Phase {
		case "starttls-missing":
			startTLSMissing++
		case "tls", "starttls-rejected":
			tlsHandshakeFail++
			// The policy-relevant failure is a TLS session that was
			// established but whose certificate did not satisfy policy.
			// A handshake that never completed at all is a different
			// shape and is handled by its own signals.
			if a.TLSStarted {
				certPolicyFail++
			}
			// Classify from the structured verification result when we
			// have one; the human-readable error string is a fallback and
			// its wording is not stable enough to depend on.
			low := strings.ToLower(a.PeerCertVerifyError + " | " + a.TLSError)
			switch {
			case strings.Contains(low, "unknown authority") || strings.Contains(low, "self-signed") || strings.Contains(low, "self signed"):
				certUnknownCA++
			case strings.Contains(low, "not valid for") || strings.Contains(low, "is valid for") ||
				strings.Contains(low, "does not cover") || strings.Contains(low, "legacy common name") ||
				strings.Contains(low, "no alternative certificate subject name"):
				certNameMismatch++
			case strings.Contains(low, "expired") || strings.Contains(low, "not yet valid"):
				certExpired++
			}
		case "connect", "banner":
			connFail++
		case "ehlo", "ehlo-after-tls":
			if a.SMTPReply == 530 {
				authRequired++
			}
		}
		if a.Permanent {
			server5xx++
		}
	}

	// ---- DNS-layer signals ------------------------------------------
	// These describe the policy lookup, which happens before any SMTP
	// connection. An attacker in the network can manipulate them, which is
	// the whole reason the engine is DNSSEC-validating.
	if in.PolicyObs.TXTStatus == model.DNSBogus {
		sigs = append(sigs, signal{
			code: "policy_dns_bogus", weight: 0.9, class: model.FaultAttackSuspected,
			detail: "the _mta-sts TXT answer is signed but does not validate; in a signed zone that is tampering or a broken signer",
		})
	}
	if in.PolicyObs.TXTStatus == model.DNSIndeterminate {
		sigs = append(sigs, signal{
			code: "policy_dns_indeterminate", weight: 0.4, class: model.FaultPolicyUnavailable,
			detail: "could not obtain a policy answer at all",
		})
	}
	if in.PolicyObs.PreviouslySecure && !in.PolicyObs.TXTPresent &&
		in.PolicyObs.TXTStatus != model.DNSSecure {
		sigs = append(sigs, signal{
			code: "policy_vanished_unauthenticated", weight: 0.85, class: model.FaultAttackSuspected,
			detail: "the domain's policy record was previously DNSSEC-secure and is now absent without a validated denial",
		})
	}
	if in.PolicyObs.PreviouslySecure && in.PolicyObs.TXTStatus == model.DNSInsecure {
		sigs = append(sigs, signal{
			code: "policy_dns_insecure_downgrade", weight: 0.7, class: model.FaultAttackSuspected,
			detail: "the policy's DNS chain was secure and is now provably unsigned; either the zone removed DNSSEC or an attacker stripped the DS",
		})
	}
	if in.PolicyObs.DANEStatus == model.DNSBogus {
		sigs = append(sigs, signal{
			code: "dane_dns_bogus", weight: 0.9, class: model.FaultAttackSuspected,
			detail: "the MX/TLSA RRset is signed but does not validate",
		})
	}
	if in.PolicyObs.FetchError != "" && in.PolicyObs.TXTStatus == model.DNSSecure {
		sigs = append(sigs, signal{
			code: "policy_fetch_error", weight: 0.3, class: model.FaultRemoteMisconfig,
			detail: "policy record present and authentic, but the HTTPS policy file could not be fetched or parsed: " + in.PolicyObs.FetchError,
		})
	}

	// ---- Per-host signals -------------------------------------------
	seenHost := map[string]bool{}
	for _, a := range in.Attempts {
		if seenHost[a.MX] {
			continue
		}
		seenHost[a.MX] = true
		h, haveHist := in.History[a.MX]

		// A handshake that never completed is its own shape. Either the
		// peer's TLS stack is broken, or somebody is probing whether we
		// will fall back when TLS "just fails". History is what tells
		// them apart: if this host completed validated TLS before, a
		// sudden inability to complete one is not a coincidence.
		if a.Phase == "tls" && !a.TLSStarted && a.PeerCertSum == "" {
			if haveHist && h.TLSValid {
				sigs = append(sigs, signal{
					code: "handshake_failed_after_prior_tls", weight: 0.85, class: model.FaultAttackSuspected,
					detail: fmt.Sprintf("%s completed validated TLS for this domain at %s and now cannot complete a handshake at all",
						a.MX, h.LastSeen.Format(time.RFC3339)),
				})
			} else {
				sigs = append(sigs, signal{
					code: "handshake_failed", weight: 0.5, class: model.FaultRemoteMisconfig,
					detail: a.MX + " advertised STARTTLS and accepted it, then the handshake failed: " + firstLine(a.TLSError),
				})
			}
		}
		if a.Phase == "starttls-rejected" && a.StartTLSReply >= 400 && a.StartTLSReply < 500 {
			sigs = append(sigs, signal{
				code: "starttls_temp_fail", weight: 0.6, class: model.FaultRemoteMisconfig,
				detail: fmt.Sprintf("%s replied %d to STARTTLS: TLS is configured but temporarily unavailable on their side",
					a.MX, a.StartTLSReply),
			})
		}

		if a.Phase == "starttls-missing" {
			switch {
			case haveHist && h.TLSValid:
				sigs = append(sigs, signal{
					code: "starttls_stripped_after_prior_tls", weight: 0.95, class: model.FaultAttackSuspected,
					detail: fmt.Sprintf("%s completed validated TLS for this domain at %s, and now does not advertise STARTTLS at all",
						a.MX, h.LastSeen.Format(time.RFC3339)),
				})
			default:
				sigs = append(sigs, signal{
					code: "starttls_missing", weight: 0.45, class: model.FaultRemoteMisconfig,
					detail: a.MX + " does not advertise STARTTLS; consistent with a server that has TLS disabled",
				})
			}
		}

		if certPolicyFail > 0 && a.PeerCertSum != "" {
			switch {
			case haveHist && h.TLSValid && a.PeerCertSum != h.LastCertSHA256:
				sigs = append(sigs, signal{
					code: "cert_changed_since_clean", weight: 0.9, class: model.FaultAttackSuspected,
					detail: fmt.Sprintf("%s presented a different leaf certificate (%s) than the one that validated at %s (%s)",
						a.MX, short(a.PeerCertSum), h.LastSeen.Format(time.RFC3339), short(h.LastCertSHA256)),
				})
			case certUnknownCA > 0:
				sigs = append(sigs, signal{
					code: "cert_unknown_ca", weight: 0.6, class: model.FaultAttackSuspected,
					detail: a.MX + " presented a certificate that does not chain to any trusted CA: " + firstLine(a.PeerCertVerifyError),
				})
			case certNameMismatch > 0 && haveHist && h.TLSValid:
				sigs = append(sigs, signal{
					code: "cert_name_mismatch_after_clean", weight: 0.8, class: model.FaultAttackSuspected,
					detail: a.MX + " presented a valid certificate for a different name after previously presenting one for this MX",
				})
			case certExpired > 0:
				sigs = append(sigs, signal{
					code: "cert_expired", weight: 0.7, class: model.FaultRemoteMisconfig,
					detail: a.MX + " presented an expired or not-yet-valid certificate",
				})
			}
		}

		if a.TLSStarted && !a.TLSPolicyOK {
			// A certificate that is valid for a *different* MX hostname of
			// the same domain is the signature of a half-finished
			// rollover, not of an attacker. The distinguishing fact is
			// not the error text but that the presented names are the
			// names of sibling MX hosts: an attacker substituting a
			// certificate would present one for the host it is
			// impersonating, or one that does not chain at all.
			if sib, ok := siblingMX(in.MXSet, a.MX, a.PeerDNSNames); ok {
				sigs = append(sigs, signal{
					code: "cert_matches_sibling_mx", weight: 0.8, class: model.FaultRolloverInProgress,
					detail: a.MX + " presented a certificate for sibling MX " + sib + "; an in-progress deployment, not interception",
				})
			} else if a.PeerCertVerifyError != "" &&
				strings.Contains(strings.ToLower(a.PeerCertVerifyError), "not ") &&
				len(a.PeerDNSNames) > 0 {
				// The chain is trusted but the name is wrong, and it is
				// not a sibling of ours: worth calling out because a
				// trusted-CA certificate for an unrelated name is a
				// plausible mis-issue rather than an on-path attack.
				sigs = append(sigs, signal{
					code: "cert_name_mismatch_trusted_ca", weight: 0.55, class: model.FaultRemoteMisconfig,
					detail: a.MX + " presented a CA-signed certificate for " + strings.Join(a.PeerDNSNames, ",") + ", which is not this MX",
				})
			}
		}
	}

	// Multiple MX hosts where some succeed: the policy is fine, one host is
	// behind. That is a rollover or a single broken host, never an attack on
	// the domain.
	if anyTLSOk && !anyDelivered && len(in.Attempts) > 1 {
		sigs = append(sigs, signal{
			code: "partial_mx_failure", weight: 0.7, class: model.FaultRolloverInProgress,
			detail: "some MX hosts satisfied the policy and others did not; consistent with a partial deployment",
		})
	}

	// Same failing host hurting several recipient domains: a server problem
	// affects everyone; a targeted attack does not.
	for host, n := range in.SharedHostFailures {
		if n >= 2 {
			sigs = append(sigs, signal{
				code: "shared_host_failure", weight: 0.75, class: model.FaultRemoteMisconfig,
				detail: fmt.Sprintf("%s is failing the same policy check for %d recipient domains; a targeted interception would not", host, n),
			})
			break
		}
	}

	if authRequired > 0 {
		sigs = append(sigs, signal{
			code: "smtp_530", weight: 0.8, class: model.FaultRemoteMisconfig,
			detail: "remote requires authentication (530) on an inbound port; this is a configuration error on their side",
		})
	}

	if connFail > 0 && connFail == len(in.Attempts) {
		sigs = append(sigs, signal{
			code: "unreachable", weight: 0.2, class: model.FaultPolicyUnavailable,
			detail: "no MX host accepted a TCP connection",
		})
	}

	if server5xx > 0 && anyTLSOk {
		sigs = append(sigs, signal{
			code: "remote_5xx_after_tls", weight: 0.6, class: model.FaultRemoteMisconfig,
			detail: "remote rejected the message after a compliant TLS session; transport security was not the problem",
		})
	}

	// ---- Policy history signals --------------------------------------
	if len(in.PolicyHistory) > 0 {
		last := in.PolicyHistory[len(in.PolicyHistory)-1]
		if last.From == model.ModeEnforce && last.To < model.ModeEnforce {
			sigs = append(sigs, signal{
				code: "enforce_withdrawn", weight: 0.5, class: model.FaultRemoteMisconfig,
				detail: fmt.Sprintf("the domain withdrew enforce at %s (%s); the new policy is being honoured",
					last.At.Format(time.RFC3339), last.Reason),
			})
		}
	}

	// ---- Aggregate ---------------------------------------------------
	v := aggregate(sigs, in, policyMode, now)
	v.Signals = evidenceOf(sigs, now)
	if v.Fault == model.FaultNone {
		switch {
		case anyDelivered && in.Policy != nil && in.Policy.RequiresTLS() && anyTLSOk:
			v.Explanation = "delivered over policy-compliant TLS"
		case anyDelivered:
			v.Explanation = "delivered"
		default:
			v.Explanation = "no conclusion; insufficient evidence"
		}
	}
	return v
}

func aggregate(sigs []signal, in Input, policyMode model.Mode, now time.Time) Verdict {
	if len(sigs) == 0 {
		return Verdict{Fault: model.FaultNone, Confidence: 0.5, Retry: true}
	}
	// Score each class by summing the weights of the signals that point at
	// it. Confidence is the winner's share of the total, tempered by the
	// absolute signal mass so that one weak signal cannot look certain.
	score := map[model.FaultClass]float64{}
	for _, s := range sigs {
		score[s.class] += s.weight
	}
	var best model.FaultClass
	var bestScore float64
	var total float64
	for c, s := range score {
		total += s
		if s > bestScore {
			best, bestScore = c, s
		}
	}
	conf := 0.0
	if total > 0 {
		conf = bestScore / total
	}
	// Temper: with 0.45 of evidence, share=1.0 still means "not sure".
	mass := bestScore
	if mass > 1.0 {
		mass = 1.0
	}
	conf = conf * (0.35 + 0.65*mass)
	if conf > 0.99 {
		conf = 0.99
	}

	v := Verdict{Fault: best, Confidence: round2(conf)}
	var reasons []string
	for _, s := range sigs {
		if s.class == best {
			reasons = append(reasons, s.detail)
		}
	}
	sort.Strings(reasons)
	switch best {
	case model.FaultAttackSuspected:
		v.Explanation = "transport security was interfered with: " + strings.Join(firstN(reasons, 2), "; ")
		v.Retry = false
		v.Escalate = conf >= 0.7
	case model.FaultRemoteMisconfig:
		v.Explanation = "the remote side appears misconfigured: " + strings.Join(firstN(reasons, 2), "; ")
		v.Retry = true
		v.Escalate = false
	case model.FaultRolloverInProgress:
		v.Explanation = "certificate or MX rollout in progress: " + strings.Join(firstN(reasons, 2), "; ")
		v.Retry = true
		v.Escalate = false
	case model.FaultPolicyUnavailable:
		v.Explanation = "no usable policy could be established: " + strings.Join(firstN(reasons, 2), "; ")
		v.Retry = true
		v.Escalate = policyMode == model.ModeEnforce
	default:
		v.Explanation = "unclassified: " + strings.Join(firstN(reasons, 2), "; ")
		v.Retry = true
	}
	if policyMode == model.ModeEnforce && best == model.FaultAttackSuspected {
		v.Escalate = true
	}
	return v
}

func evidenceOf(sigs []signal, now time.Time) []model.Evidence {
	out := make([]model.Evidence, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, model.Evidence{Code: s.code, Detail: s.detail, At: now})
	}
	return out
}

// siblingMX reports whether the presented names include a different MX host
// of the same domain, and which one.
func siblingMX(set []model.MXHost, host string, names []string) (string, bool) {
	for _, m := range set {
		if strings.EqualFold(m.Host, host) {
			continue
		}
		for _, n := range names {
			if strings.EqualFold(n, m.Host) {
				return m.Host, true
			}
		}
	}
	return "", false
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
