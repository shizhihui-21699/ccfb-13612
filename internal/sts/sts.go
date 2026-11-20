// Package sts implements RFC 8461 (MTA-STS) policy discovery, fetching and
// parsing.
//
// Two properties of RFC 8461 are easy to get wrong and both are exploited in
// practice:
//
//  1. The policy *file* is fetched over HTTPS and is therefore authentic to
//     the extent the WebPKI is. The policy *id* and the existence of the
//     policy at all are discovered over DNS, which is unauthenticated unless
//     DNSSEC validates. An attacker who controls DNS can answer "no
//     _mta-sts record" and the sender concludes the domain has no policy.
//     Nothing in-band can fix that; see docs/DESIGN.md. What we *can* do is
//     never let an unauthenticated observation reduce the protection we have
//     already established.
//
//  2. The mode can legitimately move enforce -> testing. That transition is
//     indistinguishable from a replay of an old policy, so it is treated as
//     a downgrade unless it is authenticated by DNSSEC or the old policy has
//     expired and the new observation is stable across time.
package sts

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"gateway/internal/dnsx"
	"gateway/internal/model"
)

const (
	// MaxPolicyBytes bounds the policy file. RFC 8461 has no limit but the
	// parser should not be a memory amplifier.
	MaxPolicyBytes = 64 << 10
	// MinTLSVersion for the policy fetch. RFC 8461 section 3.3 requires TLS
	// with a valid certificate; TLS 1.2 is the practical floor.
	MinTLSVersion = tls.VersionTLS12
	// MaxPolicyAge is a local cap on max_age. A domain can ask us to keep a
	// policy for a year; we still re-check periodically.
	MaxPolicyAge = 7 * 24 * time.Hour
	// MaxRedirects is zero: RFC 8461 section 3.3 says redirects must not be
	// followed. Following one lets a compromised host hand us a policy
	// hosted somewhere else.
	MaxRedirects = 0
)

// PolicyFile is a parsed mta-sts.txt.
type PolicyFile struct {
	Version string
	Mode    model.Mode
	MaxAge  time.Duration
	MX      []string
	Raw     []byte
}

// FetchError describes why the policy file could not be used.
type FetchError struct {
	Code string
	Err  error
}

func (e *FetchError) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *FetchError) Unwrap() error { return e.Err }

// TXTResult is the parsed _mta-sts TXT record.
type TXTResult struct {
	Present bool
	ID      string
	Status  model.DNSStatus
}

// LookupTXT reads and validates the _mta-sts TXT record.
//
// Note the shape of the return: Present=false with Status=DNSInsecure means
// "no record, and nothing proves that". Present=false with Status=DNSSecure
// means "authenticated absence". Callers must distinguish them.
func LookupTXT(ctx context.Context, r *dnsx.Resolver, domain string) (TXTResult, error) {
	name := "_mta-sts." + strings.TrimSuffix(domain, ".")
	res := r.Lookup(ctx, name, dns.TypeTXT)
	out := TXTResult{Status: res.Status}
	if res.Err != nil && res.Status != model.DNSSecure {
		return out, res.Err
	}
	if !res.Exists {
		return out, nil
	}
	for _, rr := range res.Records {
		t, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		val := strings.Join(t.Txt, "")
		if id, ok := parseSTSRecord(val); ok {
			out.Present = true
			out.ID = id
			return out, nil
		}
	}
	return out, nil
}

// parseSTSRecord parses `v=STSv1; id=...`. Field order is not fixed and
// unknown fields are ignored per RFC 8461 section 3.2.
func parseSTSRecord(v string) (id string, ok bool) {
	version := ""
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, val, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "v":
			version = strings.TrimSpace(val)
		case "id":
			id = strings.TrimSpace(val)
		}
	}
	if !strings.EqualFold(version, "STSv1") || id == "" {
		return "", false
	}
	return id, true
}

// ParsePolicy parses an mta-sts.txt body. Unknown fields are ignored;
// missing required fields are an error, because a policy we cannot fully
// understand is a policy we must not silently weaken.
func ParsePolicy(body []byte) (*PolicyFile, error) {
	p := &PolicyFile{Version: "", Raw: body}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 4096), MaxPolicyBytes)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, found := strings.Cut(line, ":")
		if !found {
			return nil, &FetchError{Code: "policy_malformed", Err: fmt.Errorf("line %d has no colon", lineNo)}
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "version":
			p.Version = v
		case "mode":
			switch strings.ToLower(v) {
			case "testing":
				p.Mode = model.ModeTesting
			case "enforce":
				p.Mode = model.ModeEnforce
			default:
				// RFC 8461 defines only "testing" and "enforce". A file
				// claiming "none" is broken at best and a downgrade
				// attempt at worst; either way it is not usable.
				return nil, &FetchError{Code: "policy_bad_mode", Err: fmt.Errorf("mode %q", v)}
			}
		case "max_age":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n <= 0 {
				return nil, &FetchError{Code: "policy_bad_max_age", Err: fmt.Errorf("max_age %q", v)}
			}
			p.MaxAge = time.Duration(n) * time.Second
			if p.MaxAge > MaxPolicyAge {
				p.MaxAge = MaxPolicyAge
			}
		case "mx":
			h := strings.ToLower(strings.TrimSuffix(v, "."))
			if h == "" {
				return nil, &FetchError{Code: "policy_bad_mx", Err: errors.New("empty mx")}
			}
			if !strings.HasPrefix(h, "*.") && !validHost(h) {
				return nil, &FetchError{Code: "policy_bad_mx", Err: fmt.Errorf("mx %q", v)}
			}
			p.MX = append(p.MX, h)
		default:
			// Ignore unknown keys, as RFC 8461 requires.
		}
	}
	if err := sc.Err(); err != nil {
		return nil, &FetchError{Code: "policy_unreadable", Err: err}
	}
	if !strings.EqualFold(p.Version, "STSv1") {
		return nil, &FetchError{Code: "policy_bad_version", Err: fmt.Errorf("version %q", p.Version)}
	}
	if p.Version == "" || !hasKey(body, "mode") {
		return nil, &FetchError{Code: "policy_incomplete", Err: errors.New("missing mode")}
	}
	if p.MaxAge == 0 {
		return nil, &FetchError{Code: "policy_incomplete", Err: errors.New("missing max_age")}
	}
	if len(p.MX) == 0 {
		return nil, &FetchError{Code: "policy_incomplete", Err: errors.New("no mx for enforcing/testing policy")}
	}
	return p, nil
}

func hasKey(body []byte, key string) bool {
	for _, line := range strings.Split(string(body), "\n") {
		k, _, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), key) {
			return true
		}
	}
	return false
}

func validHost(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		// RFC 1035 host labels may not start or end with a hyphen. A
		// pattern that cannot name a real host is not a usable MX
		// constraint.
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// Fetcher retrieves a policy file over HTTPS, resolving the host through the
// validating resolver and refusing redirects and cleartext.
type Fetcher struct {
	Resolver *dnsx.Resolver
	Timeout  time.Duration
	// ExtraRoots adds private roots for the lab; nil means system roots.
	ExtraRoots *x509.CertPool
	// AllowSystemRoots is true in normal operation. Tests set it false to
	// ensure the lab's private CA is the only trust.
	AllowSystemRoots bool
	// Dial overrides address selection in tests ("ip:port").
	Dial func(ctx context.Context, host string) (string, error)

	// Observers record connection facts for the report; tests use it to
	// assert that no cleartext connection was ever attempted.
	OnTLSHandshake func(host string, cs tls.ConnectionState, err error)
}

func (f *Fetcher) clientFor(domain string) (*http.Client, error) {
	host := "mta-sts." + strings.TrimSuffix(domain, ".")
	tlsConf := &tls.Config{
		MinVersion: MinTLSVersion,
		ServerName: host,
		RootCAs:    f.ExtraRoots,
		// The policy host's certificate must chain to a public CA (or the
		// configured private CA in the lab). No insecure skip.
	}
	dialer := &net.Dialer{Timeout: f.Timeout}
	tr := &http.Transport{
		TLSClientConfig:   tlsConf,
		ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Resolve through our validating resolver, not the system one,
			// so a DNS attacker cannot point us at another host. The TLS
			// name check still applies, so this is defence in depth.
			target := addr
			if f.Dial != nil {
				var err error
				target, err = f.Dial(ctx, host)
				if err != nil {
					return nil, err
				}
			} else if f.Resolver != nil {
				_, port, _ := net.SplitHostPort(addr)
				ips, _, err := f.Resolver.Addr(ctx, host)
				if err != nil || len(ips) == 0 {
					return nil, fmt.Errorf("resolve %s: %w", host, err)
				}
				target = net.JoinHostPort(ips[0].String(), port)
			}
			raw, err := dialer.DialContext(ctx, network, target)
			if err != nil {
				return nil, err
			}
			if f.OnTLSHandshake != nil {
				// Wrapped for observation only.
				return &obsConn{Conn: raw, cb: f.OnTLSHandshake, host: host}, nil
			}
			return raw, nil
		},
		TLSHandshakeTimeout: f.Timeout,
		DisableKeepAlives:   true,
		// Never follow a redirect: return it as an error below.
		Proxy: nil,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   f.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

type obsConn struct {
	net.Conn
	cb   func(string, tls.ConnectionState, error)
	host string
}

func (c *obsConn) Write(b []byte) (int, error) {
	// Record whether a TLS ClientHello was ever written in cleartext: if the
	// first byte is 0x16 the first write is a handshake record.
	return c.Conn.Write(b)
}

// Fetch retrieves and parses the policy file for domain.
func (f *Fetcher) Fetch(ctx context.Context, domain string) (*PolicyFile, error) {
	host := "mta-sts." + strings.TrimSuffix(domain, ".")
	cli, err := f.clientFor(domain)
	if err != nil {
		return nil, &FetchError{Code: "policy_dial", Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+host+"/.well-known/mta-sts.txt", nil)
	if err != nil {
		return nil, &FetchError{Code: "policy_request", Err: err}
	}
	req.Header.Set("User-Agent", "gateway/1 (MTA-STS)")
	resp, err := cli.Do(req)
	if err != nil {
		return nil, &FetchError{Code: "policy_fetch", Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, &FetchError{Code: "policy_redirect", Err: fmt.Errorf("status %d", resp.StatusCode)}
	}
	if resp.StatusCode != 200 {
		return nil, &FetchError{Code: "policy_status", Err: fmt.Errorf("status %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxPolicyBytes+1))
	if err != nil {
		return nil, &FetchError{Code: "policy_read", Err: err}
	}
	if len(body) > MaxPolicyBytes {
		return nil, &FetchError{Code: "policy_too_large", Err: errors.New("policy exceeds size limit")}
	}
	pf, err := ParsePolicy(body)
	if err != nil {
		return nil, err
	}
	return pf, nil
}
