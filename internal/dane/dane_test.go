package dane

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"gateway/internal/lab"
	"gateway/internal/model"
)

func issue(t *testing.T, ca *lab.CA, names ...string) *x509.Certificate {
	t.Helper()
	iss, err := ca.Issue(lab.IssueOptions{DNSNames: names})
	if err != nil {
		t.Fatal(err)
	}
	return iss.Cert
}

func rec(usage, sel, mt uint8, data []byte) model.TLSARecord {
	return model.TLSARecord{Usage: usage, Selector: sel, MatchingType: mt, Data: data}
}

func TestDANEEEMatchesSPKI(t *testing.T) {
	ca, _ := lab.NewCA("t")
	c := issue(t, ca, "mx.example")
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	if err := Verify([]model.TLSARecord{rec(3, 1, 1, sum[:])}, []*x509.Certificate{c}, "mx.example"); err != nil {
		t.Fatal(err)
	}
}

func TestDANEEESkipsNameCheck(t *testing.T) {
	// Usage 3 authorises the certificate directly; the MX name need not
	// appear in it. This is the rule that makes DANE stronger than PKIX.
	ca, _ := lab.NewCA("t")
	c := issue(t, ca, "something-else.example")
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	if err := Verify([]model.TLSARecord{rec(3, 1, 1, sum[:])}, []*x509.Certificate{c}, "mx.example"); err != nil {
		t.Fatalf("DANE-EE must not require a name match: %v", err)
	}
}

func TestDANEEEWrongSPKIFails(t *testing.T) {
	ca, _ := lab.NewCA("t")
	c := issue(t, ca, "mx.example")
	other := issue(t, ca, "mx.example")
	sum := sha256.Sum256(other.RawSubjectPublicKeyInfo)
	if err := Verify([]model.TLSARecord{rec(3, 1, 1, sum[:])}, []*x509.Certificate{c}, "mx.example"); err == nil {
		t.Fatal("a TLSA record for a different key must not match")
	}
}

func TestExactMatchMatchingType(t *testing.T) {
	ca, _ := lab.NewCA("t")
	c := issue(t, ca, "mx.example")
	if err := Verify([]model.TLSARecord{rec(3, 0, 0, c.Raw)}, []*x509.Certificate{c}, "mx.example"); err != nil {
		t.Fatal(err)
	}
}

func TestSHA512MatchingType(t *testing.T) {
	ca, _ := lab.NewCA("t")
	c := issue(t, ca, "mx.example")
	sum := sha512.Sum512(c.RawSubjectPublicKeyInfo)
	if err := Verify([]model.TLSARecord{rec(3, 1, 2, sum[:])}, []*x509.Certificate{c}, "mx.example"); err != nil {
		t.Fatal(err)
	}
}

func TestMultipleRecordsAnyMatch(t *testing.T) {
	// During a rollover a host publishes old and new. Matching either is
	// correct; requiring the first would break every rollover.
	ca, _ := lab.NewCA("t")
	c := issue(t, ca, "mx.example")
	old := issue(t, ca, "mx.example")
	so := sha256.Sum256(old.RawSubjectPublicKeyInfo)
	sn := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	records := []model.TLSARecord{rec(3, 1, 1, so[:]), rec(3, 1, 1, sn[:])}
	if err := Verify(records, []*x509.Certificate{c}, "mx.example"); err != nil {
		t.Fatal(err)
	}
}

func TestUnsupportedParamsFailClosed(t *testing.T) {
	ca, _ := lab.NewCA("t")
	c := issue(t, ca, "mx.example")
	// Matching type 9 does not exist. Silently ignoring it would mean
	// "no usable records", which reads as "no DANE policy".
	if err := Verify([]model.TLSARecord{rec(3, 1, 9, []byte("x"))}, []*x509.Certificate{c}, "mx.example"); err == nil {
		t.Fatal("unsupported matching type must fail, not be skipped")
	}
}

func TestNoCertsFails(t *testing.T) {
	if err := Verify([]model.TLSARecord{rec(3, 1, 1, []byte("x"))}, nil, "mx.example"); err == nil {
		t.Fatal("no peer certificate must fail")
	}
}

func TestPKIXUsageRequiresValidChain(t *testing.T) {
	// Usage 1 is "PKIX-EE": the certificate must both chain normally and
	// match the TLSA record.
	ca, _ := lab.NewCA("t")
	c := issue(t, ca, "mx.example")
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	// With no system trust for the private CA, the PKIX path must fail
	// even though the TLSA digest matches.
	if err := Verify([]model.TLSARecord{rec(1, 1, 1, sum[:])}, []*x509.Certificate{c}, "mx.example"); err == nil {
		t.Fatal("PKIX usage must validate the chain first")
	}
}

var _ = pem.Decode
