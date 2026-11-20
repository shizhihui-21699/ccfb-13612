// Package lab builds a simulated network for exercising the gateway against
// hostile peers. Nothing in this package is imported by production code.
package lab

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"
)

// CA is a throwaway private certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	pool *x509.CertPool
}

// NewCA creates a CA valid for ten years from now.
func NewCA(name string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"lab"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{Cert: cert, Key: key, pool: pool}, nil
}

// Pool returns a CertPool holding only this CA.
func (c *CA) Pool() *x509.CertPool { return c.pool }

// PEM returns the CA certificate in PEM form.
func (c *CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
}

// IssueOptions describes one leaf certificate.
type IssueOptions struct {
	DNSNames []string
	IPs      []net.IP
	// NotBefore and NotAfter override validity; zero means now / +90 days.
	NotBefore, NotAfter time.Time
	// IsCA makes the leaf a CA, for DANE-TA tests.
	IsCA bool
	// CommonName defaults to DNSNames[0].
	CommonName string
}

// Issued is a leaf certificate and its private key.
type Issued struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// tlsPair renders the issued certificate as a tls.Certificate.
func (i Issued) tlsPair() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{i.Cert.Raw}, PrivateKey: i.Key, Leaf: i.Cert}
}

// Issue signs a leaf certificate with the CA.
func (c *CA) Issue(o IssueOptions) (Issued, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Issued{}, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return Issued{}, err
	}
	now := time.Now()
	nb, na := o.NotBefore, o.NotAfter
	if nb.IsZero() {
		nb = now.Add(-time.Hour)
	}
	if na.IsZero() {
		na = now.AddDate(0, 3, 0)
	}
	cn := o.CommonName
	if cn == "" && len(o.DNSNames) > 0 {
		cn = o.DNSNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"lab"}},
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     o.DNSNames,
		IPAddresses:  o.IPs,
	}
	if o.IsCA {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, key.Public(), c.Key)
	if err != nil {
		return Issued{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Issued{}, err
	}
	return Issued{Cert: cert, Key: key}, nil
}

// TLSPair converts the stored pair into a tls.Certificate.
func (s *CertStore) TLSPair() (tls.Certificate, bool) {
	cert, key, ok := s.Get()
	if !ok {
		return tls.Certificate{}, false
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}, true
}

// CertStore is a convenience for the lab's servers: a set of named
// certificates that can be swapped at runtime, which is how rollover and
// attacker-substitution are modelled.
type CertStore struct {
	mu   sync.RWMutex
	pair *tlsPair
}

type tlsPair struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func NewCertStore() *CertStore { return &CertStore{} }

func (s *CertStore) Set(cert *x509.Certificate, key crypto.Signer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pair = &tlsPair{cert: cert, key: key}
}

func (s *CertStore) Get() (*x509.Certificate, crypto.Signer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.pair == nil {
		return nil, nil, false
	}
	return s.pair.cert, s.pair.key, true
}
