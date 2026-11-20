// Package dane implements RFC 6698 TLSA matching for SMTP (RFC 7672).
//
// The rules that matter for this gateway:
//
//   - TLSA records only count if the MX RRset and the TLSA RRset are DNSSEC
//     secure (RFC 7672 section 2.2.1). An insecure or bogus answer is not a
//     usable DANE policy, and crucially it is not "no policy" either.
//   - Usage 3 (DANE-EE) authorises the certificate directly; the name in the
//     certificate is not checked against the MX hostname. Usage 2 (DANE-TA)
//     anchors a CA and the leaf must still chain to it.
//   - Usage 0/1 are PKIX plus a TLSA constraint: the WebPKI path must
//     validate first.
package dane

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"gateway/internal/model"
)

// Verify checks a presented chain (leaf first) against the TLSA records.
// host is the MX hostname; it is used only for PKIX usages, where the name
// must match. It returns nil on success.
//
// lenientParams is a deliberate knob for the "our side is broken" case: if
// the remote publishes a TLSA RRset using a matching type or selector this
// implementation does not support, a strict failure would block all mail to
// a domain that is itself fine. The caller decides; the default is strict.
func Verify(records []model.TLSARecord, chain []*x509.Certificate, host string) error {
	if len(records) == 0 {
		return errors.New("dane: no TLSA records")
	}
	if len(chain) == 0 {
		return errors.New("dane: peer presented no certificate")
	}
	var supported int
	var lastErr error
	for _, rec := range records {
		if rec.MatchingType > 2 || rec.Selector > 1 || rec.Usage > 3 {
			lastErr = fmt.Errorf("dane: unsupported TLSA parameters %d %d %d", rec.Usage, rec.Selector, rec.MatchingType)
			continue
		}
		supported++
		err := matchOne(rec, chain, host)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	if supported == 0 {
		return fmt.Errorf("dane: no usable TLSA record (%w)", lastErr)
	}
	return fmt.Errorf("dane: no TLSA record matched: %w", lastErr)
}

func matchOne(rec model.TLSARecord, chain []*x509.Certificate, host string) error {
	switch rec.Usage {
	case 3: // DANE-EE: match the leaf directly, skip name checks.
		if rec.Selector == 0 {
			return matchCert(rec, chain[0])
		}
		return matchSPKI(rec, chain[0])
	case 2: // DANE-TA: cert must chain to a TA whose cert/SPKI matches.
		// Build a pool from matching chain members and verify.
		var pool []*x509.Certificate
		for _, c := range chain {
			var err error
			if rec.Selector == 0 {
				err = matchCert(rec, c)
			} else {
				err = matchSPKI(rec, c)
			}
			if err == nil {
				pool = append(pool, c)
			}
		}
		if len(pool) == 0 {
			return errors.New("dane: no chain member matches DANE-TA")
		}
		roots := x509.NewCertPool()
		for _, c := range pool {
			roots.AddCert(c)
		}
		// The chain presented may be partial; verify the leaf against the
		// matched anchor. Hostname check is done for usage 2.
		_, err := chain[0].Verify(x509.VerifyOptions{
			Roots:       roots,
			CurrentTime: Now(),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			return fmt.Errorf("dane: DANE-TA chain verify: %w", err)
		}
		if err := verifyName(chain[0], host); err != nil {
			return err
		}
		return nil
	case 0, 1: // PKIX-TA / PKIX-EE: normal WebPKI validation first.
		inter := x509.NewCertPool()
		for _, c := range chain[1:] {
			inter.AddCert(c)
		}
		if _, err := chain[0].Verify(x509.VerifyOptions{
			Intermediates: inter,
			CurrentTime:   Now(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return fmt.Errorf("dane: PKIX chain first: %w", err)
		}
		if err := verifyName(chain[0], host); err != nil {
			return err
		}
		if rec.Usage == 0 { // TA: any chain cert may match
			for _, c := range chain {
				var err error
				if rec.Selector == 0 {
					err = matchCert(rec, c)
				} else {
					err = matchSPKI(rec, c)
				}
				if err == nil {
					return nil
				}
			}
			return errors.New("dane: no chain cert matches PKIX-TA")
		}
		if rec.Selector == 0 {
			return matchCert(rec, chain[0])
		}
		return matchSPKI(rec, chain[0])
	}
	return fmt.Errorf("dane: unsupported usage %d", rec.Usage)
}

func matchCert(rec model.TLSARecord, c *x509.Certificate) error {
	return compare(rec, c.Raw)
}

func matchSPKI(rec model.TLSARecord, c *x509.Certificate) error {
	return compare(rec, c.RawSubjectPublicKeyInfo)
}

func compare(rec model.TLSARecord, data []byte) error {
	switch rec.MatchingType {
	case 0:
		if bytes.Equal(rec.Data, data) {
			return nil
		}
		return errors.New("dane: exact match differs")
	case 1:
		sum := sha256.Sum256(data)
		if bytes.Equal(rec.Data, sum[:]) {
			return nil
		}
		return errors.New("dane: sha256 differs")
	case 2:
		sum := sha512.Sum512(data)
		if bytes.Equal(rec.Data, sum[:]) {
			return nil
		}
		return errors.New("dane: sha512 differs")
	}
	return fmt.Errorf("dane: unsupported matching type %d", rec.MatchingType)
}

func verifyName(c *x509.Certificate, host string) error {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if err := c.VerifyHostname(host); err != nil {
		return fmt.Errorf("dane: certificate does not cover %s: %w", host, err)
	}
	return nil
}

// Now is the clock used for PKIX validity checks. Tests pin it.
var Now = func() time.Time { return time.Now() }
