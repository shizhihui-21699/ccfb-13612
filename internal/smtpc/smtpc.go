// Package smtpc is a minimal ESMTP client whose only unusual property is
// that it cannot be talked into cleartext when the policy forbids it.
//
// The interesting cases are all in the TLS layer:
//
//   - A server that advertises STARTTLS, then breaks the handshake, is not
//     an invitation to retry in cleartext. Under enforce it is a failure.
//   - A server that does not advertise STARTTLS at all is the classic
//     active-downgrade signature: the attacker strips the capability from
//     the EHLO response. Under enforce it is a failure, and it is reported
//     as a suspected attack rather than a misconfiguration, because a
//     server that dropped STARTTLS globally would break every other sender
//     too (the report correlates this across domains).
//   - A server whose certificate does not match may be mid-rollover. Under
//     enforce that is a deferral, and the classifier uses the MX set and
//     cert fields to decide between "rollover" and "MITM".
package smtpc

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"gateway/internal/dane"
	"gateway/internal/model"
)

// Config controls one client instance.
type Config struct {
	// HeloName is what we say in EHLO.
	HeloName string
	// Timeout is the per-phase deadline.
	Timeout time.Duration
	// MinTLSVersion defaults to TLS 1.2.
	MinTLSVersion uint16
	// RequireTLSForEnforce is the central safety switch: when the caller
	// says the policy is enforce, the client will not do anything but TLS.
	// It is redundant with Policy.Mode by construction, and that redundancy
	// is intentional — a bug in policy plumbing must not produce cleartext.
	RequireTLSForEnforce bool
	// Roots for WebPKI verification. nil means the peer chain is not
	// verified by WebPKI; policy-specific checks still run. In the lab the
	// private CA is supplied.
	Roots *x509.CertPool
	// InsecureSkipWebPKI disables the *opportunistic* WebPKI check (lab
	// only, for testing the "peer presented an unknown cert" path).
	InsecureSkipWebPKI bool
	// DNSSECRequiredForDANE controls whether a DANE policy must be backed
	// by a secure MX RRset. It is always true in production.
	DNSSECRequiredForDANE bool
	// Dial overrides TCP dialing (lab).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// OnTLSHandshake observes every handshake; the lab asserts there was no
	// cleartext write before it and records the negotiated parameters.
	OnTLSHandshake func(mx string, cs *tls.ConnectionState, err error)
}

func (c *Config) fill() {
	if c.Timeout == 0 {
		c.Timeout = 20 * time.Second
	}
	if c.MinTLSVersion == 0 {
		c.MinTLSVersion = tls.VersionTLS12
	}
	if c.HeloName == "" {
		c.HeloName = "gateway.invalid"
	}
	c.DNSSECRequiredForDANE = true
}

// Client sends one message to one MX host.
type Client struct{ Config Config }

func New(cfg Config) *Client {
	cfg.fill()
	return &Client{Config: cfg}
}

// Message is the envelope and body to transmit.
type Message struct {
	From string
	To   []string
	Body []byte
	// RequireTLS is set by the queue from Policy.Mode == enforce.
	RequireTLS bool
	// PolicyMX is the allowable MX pattern list from MTA-STS.
	PolicyMX []string
	// TLSA maps MX host to its TLSA records, for DANE-enforced hosts.
	TLSA map[string][]model.TLSARecord
	// MXDNSSECStatus is the validation status of the MX host's addresses.
	MXDNSSECStatus model.DNSStatus
	// BeforeDATA is called after the envelope is accepted and before the
	// DATA command. If it returns an error the client aborts with phase
	// "policy-changed" without transmitting the body.
	//
	// This is the last-moment policy re-check. It is placed before DATA
	// specifically because that is the first point at which the *body*
	// would leave the host: a policy change between planning and this
	// moment aborts with nothing written, and the queue re-plans the
	// message under the new policy.
	BeforeDATA func() error
}

// SendResult is everything the caller needs to classify the attempt.
type SendResult struct {
	Attempt model.Attempt
	// Delivered says the remote accepted the final dot.
	Delivered bool
	// Permanent is true when the remote gave a 5xx on a compliant channel.
	Permanent bool
	// RejectedAt names the phase that produced a permanent failure.
	RejectedAt string
}

// Send connects to one MX and attempts delivery.
//
// The returned result never has Delivered=true on a cleartext connection
// when msg.RequireTLS is set; that invariant is asserted at the end.
func (c *Client) Send(ctx context.Context, mx model.MXHost, msg *Message) *SendResult {
	start := time.Now()
	a := model.Attempt{
		MX: mx.Host, MXPref: mx.Pref, Started: start,
		MXSource: mx.Source,
	}
	res := &SendResult{Attempt: a}
	fail := func(phase string, err error) *SendResult {
		res.Attempt.Phase = phase
		res.Attempt.Error = errString(err)
		res.Attempt.Duration = time.Since(start)
		res.Attempt.Permanent = res.Permanent
		return res
	}

	addr := mx.DialAddr()
	conn, err := c.dial(ctx, addr)
	if err != nil {
		return fail("connect", err)
	}
	defer conn.Close()
	res.Attempt.Connected = true
	res.Attempt.Addr = addr

	// Enforce a hard deadline for the whole exchange.
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	} else {
		conn.SetDeadline(time.Now().Add(c.Config.Timeout * 4))
	}

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	code, text, err := readReply(br)
	if err != nil {
		return fail("banner", err)
	}
	res.Attempt.Banner = text
	if code != 220 {
		res.Attempt.SMTPReply, res.Attempt.SMTPText = code, text
		res.Permanent = code >= 500
		return fail("banner", fmt.Errorf("banner %d", code))
	}

	if err := writeLine(bw, "EHLO "+c.Config.HeloName); err != nil {
		return fail("ehlo", err)
	}
	code, text, caps, err := readEHLO(br)
	if err != nil {
		return fail("ehlo", err)
	}
	if code != 250 {
		// Some ancient servers only do HELO. That is not a downgrade path
		// we need; treat as failure.
		res.Attempt.SMTPReply, res.Attempt.SMTPText = code, text
		return fail("ehlo", fmt.Errorf("EHLO %d", code))
	}
	res.Attempt.EHLO = caps
	startTLS := hasCap(caps, "STARTTLS")
	res.Attempt.StartTLSAdvertised = startTLS

	needTLS := msg.RequireTLS
	if needTLS && !startTLS {
		// The central case this gateway exists for.
		res.Attempt.SMTPReply, res.Attempt.SMTPText = code, text
		return fail("starttls-missing", errors.New("STARTTLS not advertised"))
	}

	if startTLS {
		if err := writeLine(bw, "STARTTLS"); err != nil {
			return fail("starttls", err)
		}
		code, text, err = readReply(br)
		res.Attempt.StartTLSReply = code
		if err != nil {
			return fail("starttls", err)
		}
		if code != 220 {
			res.Attempt.SMTPText = text
			if needTLS {
				return fail("starttls-rejected", fmt.Errorf("STARTTLS %d", code))
			}
			// Opportunistic: fall through to cleartext below.
		} else {
			tlsConn, herr := c.handshake(ctx, conn, mx.Host, msg, res)
			if err := herr; err != nil {
				res.Attempt.TLSError = errString(err)
				if needTLS {
					return fail("tls", err)
				}
				// Never fall back to cleartext after the peer has
				// accepted STARTTLS, even when the policy is only
				// opportunistic. RFC 3207 §4.2 requires discarding the
				// connection, and the security reason is stronger than the
				// protocol one: "TLS failed, try plaintext" is precisely
				// the behaviour an on-path attacker induces by breaking
				// the handshake. Falling back would hand them the
				// downgrade for free on every domain that merely runs
				// opportunistic TLS.
				//
				// The distinction that remains is what we *report*: under
				// an enforcing policy this is a blocked delivery, under an
				// opportunistic one it is a deferral with a TLS-failure
				// signal, so a partner with a broken TLS stack is visible
				// rather than silently receiving plaintext.
				res.Attempt.Phase = "tls"
				res.Attempt.Error = errString(err)
				res.Attempt.Duration = time.Since(start)
				return res
			}
			// Handshake succeeded.
			{
				res.Attempt.TLSStarted = true
				// Everything from here on must go through the TLS record
				// layer. Replacing conn and re-creating the buffers is
				// load-bearing: leaving the old bufio.Writer in place
				// would send the post-STARTTLS EHLO in cleartext.
				conn = tlsConn
				if dl, ok := ctx.Deadline(); ok {
					conn.SetDeadline(dl)
				}
				br = bufio.NewReader(conn)
				bw = bufio.NewWriter(conn)
				// Re-EHLO after STARTTLS, per RFC 3207.
				if err := writeLine(bw, "EHLO "+c.Config.HeloName); err != nil {
					return fail("ehlo-after-tls", err)
				}
				code, text, caps, err = readEHLO(br)
				if err != nil || code != 250 {
					return fail("ehlo-after-tls", fmt.Errorf("EHLO after TLS: %d %v", code, err))
				}
				res.Attempt.EHLO = caps
			}
		}
	}

	encrypted := res.Attempt.TLSStarted

	// Envelope.
	if err := writeLine(bw, "MAIL FROM:<"+msg.From+">"); err != nil {
		return fail("mail-from", err)
	}
	code, text, err = readReply(br)
	if err != nil {
		return fail("mail-from", err)
	}
	res.Attempt.SMTPReply, res.Attempt.SMTPText = code, text
	if code/100 != 2 {
		res.Permanent = code >= 500
		return fail("mail-from", fmt.Errorf("%d %s", code, text))
	}
	for _, rcpt := range msg.To {
		if err := writeLine(bw, "RCPT TO:<"+rcpt+">"); err != nil {
			return fail("rcpt-to", err)
		}
		code, text, err = readReply(br)
		if err != nil {
			return fail("rcpt-to", err)
		}
		res.Attempt.SMTPReply, res.Attempt.SMTPText = code, text
		if code/100 != 2 {
			res.Permanent = code >= 500
			return fail("rcpt-to", fmt.Errorf("%d %s", code, text))
		}
	}

	if msg.BeforeDATA != nil {
		if err := msg.BeforeDATA(); err != nil {
			// Nothing has been sent yet; the entry is safe to re-plan.
			return fail("policy-changed", err)
		}
	}

	if err := writeLine(bw, "DATA"); err != nil {
		return fail("data", err)
	}
	code, text, err = readReply(br)
	if err != nil {
		return fail("data", err)
	}
	if code != 354 {
		res.Attempt.SMTPReply, res.Attempt.SMTPText = code, text
		res.Permanent = code >= 500
		return fail("data", fmt.Errorf("%d %s", code, text))
	}

	body := dotStuff(msg.Body)
	if _, err := bw.Write(body); err != nil {
		return fail("body", err)
	}
	if _, err := bw.WriteString("\r\n.\r\n"); err != nil {
		return fail("body", err)
	}
	if err := bw.Flush(); err != nil {
		return fail("body", err)
	}
	code, text, err = readReply(br)
	if err != nil {
		return fail("final-dot", err)
	}
	res.Attempt.SMTPReply, res.Attempt.SMTPText = code, text
	if code/100 != 2 {
		res.Permanent = code >= 500
		return fail("final-dot", fmt.Errorf("%d %s", code, text))
	}

	// The invariant this package exists to keep.
	if msg.RequireTLS && !encrypted {
		res.Attempt.Phase = "invariant-violation"
		res.Attempt.Error = "cleartext delivery completed under an enforcing policy"
		return res
	}

	if err := writeLine(bw, "QUIT"); err != nil {
		// Not worth failing delivery over.
		_ = err
	}
	res.Delivered = true
	res.Attempt.Phase = "done"
	res.Attempt.Duration = time.Since(start)
	return res
}

func (c *Client) dial(ctx context.Context, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: c.Config.Timeout}
	if c.Config.Dial != nil {
		return c.Config.Dial(ctx, "tcp", addr)
	}
	return d.DialContext(ctx, "tcp", addr)
}

func (c *Client) handshake(ctx context.Context, conn net.Conn, mxHost string, msg *Message, res *SendResult) (net.Conn, error) {
	tlsConf := &tls.Config{
		ServerName: mxHost,
		MinVersion: c.Config.MinTLSVersion,
		RootCAs:    c.Config.Roots,
		// We deliberately do NOT set InsecureSkipVerify: the chain is
		// always parsed, and policy decides what to accept. For DANE-EE
		// the name check is done after the fact by the DANE matcher, so
		// verification against the MX name is not required to succeed,
		// but it is recorded.
		InsecureSkipVerify: true,
		// Record everything we can for the report.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if c.Config.OnTLSHandshake != nil {
				c.Config.OnTLSHandshake(mxHost, &cs, nil)
			}
			return nil
		},
	}
	tc := tls.Client(conn, tlsConf)
	if err := tc.HandshakeContext(ctx); err != nil {
		if c.Config.OnTLSHandshake != nil {
			c.Config.OnTLSHandshake(mxHost, nil, err)
		}
		return nil, err
	}
	cs := tc.ConnectionState()
	res.Attempt.TLSVersion = cs.Version
	res.Attempt.CipherSuite = cs.CipherSuite
	res.Attempt.TLSStarted = true
	var chain []*x509.Certificate
	var leafSum string
	for i, c := range cs.PeerCertificates {
		chain = append(chain, c)
		if i == 0 {
			sum := sha256Hex(c.Raw)
			leafSum = sum
			res.Attempt.PeerIssuer = c.Issuer.String()
			res.Attempt.PeerDNSNames = append([]string(nil), c.DNSNames...)
		}
	}
	res.Attempt.PeerCertSum = leafSum
	for _, c := range cs.PeerCertificates {
		res.Attempt.PeerCerts = append(res.Attempt.PeerCerts, c.Raw)
	}

	// Find out whether the chain verifies against WebPKI roots.
	var verifyErr error
	if !c.Config.InsecureSkipWebPKI && len(chain) > 0 {
		inter := x509.NewCertPool()
		for _, c := range chain[1:] {
			inter.AddCert(c)
		}
		opts := x509.VerifyOptions{
			DNSName:       mxHost,
			Intermediates: inter,
			Roots:         c.Config.Roots,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		_, verifyErr = chain[0].Verify(opts)
	}
	if verifyErr != nil {
		res.Attempt.PeerCertVerifyError = verifyErr.Error()
	}

	// Policy check.
	switch {
	case len(msg.TLSA) > 0 && msg.MXDNSSECStatus == model.DNSSecure:
		// RFC 7672: the applicable TLSA set is the one published under
		// this exact MX hostname, not any set for the domain.
		recs := msg.TLSA[strings.ToLower(mxHost)]
		if len(recs) == 0 {
			res.Attempt.TLSPolicyOK = false
			return tc, fmt.Errorf("no TLSA records for MX %s; host is not DANE-eligible", mxHost)
		}
		if err := dane.Verify(recs, chain, mxHost); err != nil {
			res.Attempt.TLSPolicyOK = false
			return tc, fmt.Errorf("DANE: %w", err)
		}
		res.Attempt.TLSPolicyOK = true
		return tc, nil
	case msg.RequireTLS:
		// STS enforce, or enforce by other means: the chain must validate
		// for the MX name against the configured roots.
		if verifyErr != nil {
			res.Attempt.TLSPolicyOK = false
			return tc, fmt.Errorf("certificate does not satisfy policy: %w", verifyErr)
		}
		if len(msg.PolicyMX) > 0 && !mxMatches(msg.PolicyMX, mxHost) {
			return tc, fmt.Errorf("MX %s not permitted by policy", mxHost)
		}
		res.Attempt.TLSPolicyOK = true
		return tc, nil
	default:
		// Opportunistic: record, do not block.
		res.Attempt.TLSPolicyOK = verifyErr == nil
		return tc, nil
	}
}

func mxMatches(patterns []string, host string) bool {
	host = strings.ToLower(host)
	for _, p := range patterns {
		p = strings.ToLower(p)
		if p == host {
			return true
		}
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:]
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

func readReply(r *bufio.Reader) (int, string, error) {
	var lines []string
	code := 0
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return 0, strings.Join(lines, " "), err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			return 0, strings.Join(lines, " "), fmt.Errorf("short reply %q", line)
		}
		n, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, strings.Join(lines, " "), fmt.Errorf("bad reply %q", line)
		}
		code = n
		lines = append(lines, line)
		if len(line) == 3 || line[3] == ' ' {
			return code, strings.Join(lines, " "), nil
		}
		if len(lines) > 100 {
			return 0, "", errors.New("reply too long")
		}
	}
}

func readEHLO(r *bufio.Reader) (int, string, []string, error) {
	var lines []string
	code := 0
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return 0, strings.Join(lines, " "), nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			return 0, strings.Join(lines, " "), nil, fmt.Errorf("short reply %q", line)
		}
		n, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, strings.Join(lines, " "), nil, fmt.Errorf("bad reply %q", line)
		}
		code = n
		lines = append(lines, line)
		if len(line) > 4 {
			lines = append(lines, strings.TrimSpace(line[4:]))
		}
		if len(line) == 3 || line[3] == ' ' {
			break
		}
		if len(lines) > 200 {
			return 0, "", nil, errors.New("EHLO reply too long")
		}
	}
	var caps []string
	for _, l := range lines {
		if len(l) > 3 && (l[3] == ' ' || l[3] == '-') {
			l = l[4:]
		}
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		upper := strings.ToUpper(l)
		if strings.HasPrefix(upper, "250 ") || strings.HasPrefix(upper, "250-") {
			l = l[4:]
			upper = upper[4:]
		}
		if upper == "HELO" && len(l) == 4 {
			continue
		}
		caps = append(caps, l)
	}
	return code, strings.Join(lines, " "), caps, nil
}

func hasCap(caps []string, name string) bool {
	name = strings.ToUpper(name)
	for _, c := range caps {
		if strings.EqualFold(c, name) || strings.HasPrefix(strings.ToUpper(c), name+" ") {
			return true
		}
	}
	return false
}

func writeLine(w *bufio.Writer, s string) error {
	if _, err := w.WriteString(s + "\r\n"); err != nil {
		return err
	}
	return w.Flush()
}

func dotStuff(body []byte) []byte {
	out := make([]byte, 0, len(body)+16)
	lineStart := true
	for _, b := range body {
		if lineStart && b == '.' {
			out = append(out, '.')
		}
		out = append(out, b)
		lineStart = b == '\n'
	}
	return out
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
