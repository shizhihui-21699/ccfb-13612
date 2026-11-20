package lab

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"gateway/internal/dnsx"
	"gateway/internal/model"
	"gateway/internal/policy"
	"gateway/internal/sts"

	"crypto/tls"
)

// World is a complete simulated network: a validating resolver pointed at a
// DNSSEC-signed zone tree, optionally through an on-path DNS attacker, plus
// one or more SMTP peers.
type World struct {
	T           *testing.T
	CA          *CA
	DNS         *DNSServer
	Attacker    *DNSAttacker
	Resolver    *dnsx.Resolver
	STS         *sts.Fetcher
	Policy      *policy.Engine
	Domain      string
	STSAddr     string // host:port of the policy HTTPS server
	SMTP        []*Server
	STSCert     *CertStore
	TLSDNSPort  int
	policyStore policy.Store
	// SetMXPorts lets a harness map an MX host to the loopback port its
	// simulated server listens on.
	SetMXPorts func(host string) (int, bool)

	Clock *Clock
	// CleanDNSAddr is the unattacked resolver address, for tests that
	// establish a trusted policy before an attacker appears.
	CleanDNSAddr string
	// CleanPolicy is a second engine that uses only the clean DNS path.
	CleanPolicy *policy.Engine
	domainZone  *Zone
	policySrv   *PolicyServer
	setBody     func(string)
}

type WorldOptions struct {
	Domain string
	// Attack applies an on-path DNS attacker.
	Attack AttackerMode
	// SignedDomain makes the recipient zone signed.
	SignedDomain bool
	// PolicyTXTPresent publishes a _mta-sts TXT record.
	PolicyTXT bool
	PolicyID  string
	// PolicyBody is served at mta-sts.<domain>/.well-known/mta-sts.txt.
	// Empty means the fetch 404s.
	PolicyBody string
	// MXHosts lists MX hostnames, with the SMTP server index (or -1 for
	// no server), sorted by preference as given.
	MXHosts []MXHostSpec
	// DANE publishes TLSA records. The map is MX host -> records. The MX
	// RRset must be signed for the policy engine to use them.
	DANE map[string][]model.TLSARecord
	// StrictUnknown turns on the strict mode.
	StrictUnknown bool
	// Clock drives every time-dependent rule; nil uses the wall clock.
	Clock *Clock
	// StabilizationWindow overrides the engine's default.
	StabilizationWindow time.Duration
	// StaleGrace overrides the engine's default.
	StaleGrace time.Duration
}

type MXHostSpec struct {
	Host string
	Port int
}

// NewWorld assembles the world. It fails the test on setup errors.
func NewWorld(t *testing.T, o WorldOptions) *World {
	t.Helper()
	ca, err := NewCA("lab root")
	if err != nil {
		t.Fatal(err)
	}
	dnssrv, err := NewDNSServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dnssrv.Close)

	domain := o.Domain
	if domain == "" {
		domain = "partner.example"
	}

	// Root zone, signed, delegating to `example.` which is also signed.
	// This is the simplest tree in which DNSSEC validation actually
	// happens: without a signed delegation the resolver would correctly
	// say "insecure" and the tests would not exercise the validator.
	root, err := NewZone(".", true)
	if err != nil {
		t.Fatal(err)
	}
	tld, err := NewZone("example.", true)
	if err != nil {
		t.Fatal(err)
	}
	root.Delegate(tld)
	dnssrv.AddZone(root)
	dnssrv.AddZone(tld)

	dom, err := NewZone(domain, o.SignedDomain)
	if err != nil {
		t.Fatal(err)
	}
	tld.Delegate(dom)
	dnssrv.AddZone(dom)

	// mta-sts host.
	stsHost := "mta-sts." + domain + "."
	mxHosts := o.MXHosts
	for _, m := range mxHosts {
		_ = m
	}

	// Start the policy HTTPS server if a body is supplied.
	var stsAddr string
	certStore := NewCertStore()
	var bodySetter func(string)
	var policyServer *PolicyServer
	if o.PolicyBody != "" {
		issued, err := ca.Issue(IssueOptions{DNSNames: []string{"mta-sts." + domain}})
		if err != nil {
			t.Fatal(err)
		}
		certStore.Set(issued.Cert, issued.Key)
		pair := issued.tlsPair()
		srv, addr, err := NewHTTPServer(pair, o.PolicyBody)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { srv.Close() })
		stsAddr = addr
		bodySetter = srv.SetBody
		policyServer = srv
	}

	// Publish DNS records.
	if o.PolicyTXT {
		dom.Add(&dns.TXT{
			Hdr: dns.RR_Header{Name: "_mta-sts." + domain + ".", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{"v=STSv1; id=" + o.PolicyID},
		})
	}
	for i, m := range mxHosts {
		dom.Add(&dns.MX{
			Hdr:        dns.RR_Header{Name: domain + ".", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60},
			Preference: uint16(i * 10),
			Mx:         dns.Fqdn(m.Host),
		})
		// All MX hosts point at the same loopback address in the lab;
		// the port distinguishes them.
		dom.Add(&dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn(m.Host), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   mustIP("127.0.0.1"),
		})
	}
	for host, recs := range o.DANE {
		for _, r := range recs {
			dom.Add(&dns.TLSA{
				Hdr:          dns.RR_Header{Name: "_25._tcp." + host + ".", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 60},
				Usage:        r.Usage,
				Selector:     r.Selector,
				MatchingType: r.MatchingType,
				Certificate:  hex.EncodeToString(r.Data),
			})
		}
	}
	if stsAddr != "" {
		host, _, _ := net.SplitHostPort(stsAddr)
		dom.Add(&dns.A{
			Hdr: dns.RR_Header{Name: stsHost, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   mustIP(host),
		})
	}

	cleanAddr := dnssrv.Addr()
	dnsAddr := cleanAddr
	if o.Attack != AttackerPassive {
		atk, err := NewDNSAttacker(dnsAddr, o.Attack)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(atk.Close)
		dnsAddr = atk.Addr()
	}

	res := dnsx.NewResolver(dnsAddr)
	res.SetCleanUpstream(cleanAddr)
	// Trust anchor: the signed root's KSK.
	res.AddAnchor(".", root.Keys()[0])

	stsFetcher := &sts.Fetcher{
		Resolver:         res,
		Timeout:          3 * time.Second,
		ExtraRoots:       ca.Pool(),
		AllowSystemRoots: false,
	}

	store := policy.NewMemStore()
	var nowFn func() time.Time
	if o.Clock != nil {
		nowFn = o.Clock.Now
	}
	engOpts := policy.Options{
		StrictUnknown:       o.StrictUnknown,
		Now:                 nowFn,
		StabilizationWindow: o.StabilizationWindow,
		StaleGrace:          o.StaleGrace,
	}
	if stsAddr != "" {
		stsLocal := stsAddr
		engOpts.PolicyHostOverride = func(string) (string, bool) { return stsLocal, true }
	}
	eng := policy.New(res, stsFetcher, store, engOpts)

	wld := &World{
		T: t, CA: ca, DNS: dnssrv, Resolver: res, STS: stsFetcher,
		Policy: eng, Domain: domain, STSAddr: stsAddr,
		STSCert: certStore, policyStore: store,
		domainZone: dom, setBody: bodySetter, Clock: o.Clock,
		policySrv:    policyServer,
		CleanDNSAddr: cleanAddr,
	}
	// Defer port wiring: the harness installs it after servers exist.
	eng.SetMXPortOverride(func(host string) (int, bool) {
		if wld.SetMXPorts == nil {
			return 0, false
		}
		return wld.SetMXPorts(host)
	})
	cleanRes, err := res.CleanResolver()
	if err == nil {
		var cleanNow func() time.Time
		if o.Clock != nil {
			cleanNow = o.Clock.Now
		}
		copts := engOpts
		copts.Now = cleanNow
		wld.CleanPolicy = policy.New(cleanRes, &sts.Fetcher{
			Resolver: cleanRes, Timeout: 3 * time.Second, ExtraRoots: ca.Pool(),
		}, policy.NewMemStore(), copts)
		wld.CleanPolicy.SetMXPortOverride(func(host string) (int, bool) {
			if wld.SetMXPorts == nil {
				return 0, false
			}
			return wld.SetMXPorts(host)
		})
	}
	return wld
}

// SetPolicyBody swaps the body served by the policy HTTPS server and bumps
// the TXT record id, modelling a real policy change.
func (w *World) SetPolicyBody(body, id string) error {
	w.T.Helper()
	if w.STSAddr == "" {
		w.T.Fatal("no policy server")
	}
	// The HTTPS server reads the body via this indirection.
	w.setBody(body)
	z := w.domainZone
	if z == nil {
		w.T.Fatal("no domain zone")
	}
	z.Remove("_mta-sts."+w.Domain+".", 16)
	if id != "" {
		z.Add(&dns.TXT{
			Hdr: dns.RR_Header{Name: "_mta-sts." + w.Domain + ".", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{"v=STSv1; id=" + id},
		})
	}
	return nil
}

// Ctx returns a test context.
func Ctx() context.Context { return context.Background() }

var _ = tls.VersionTLS12

// EstablishClean resolves the domain through the unattacked path and copies
// the resulting record into the engine that is about to face the attacker.
// This models the realistic sequence: a first delivery happened while the
// network was clean, so the gateway has a baseline to compare against.
func (w *World) EstablishClean(t *testing.T) *policy.Resolution {
	t.Helper()
	if w.CleanPolicy == nil {
		t.Fatal("no clean policy engine")
	}
	res, err := w.CleanPolicy.Resolve(Ctx(), w.Domain)
	if err != nil {
		t.Fatalf("clean resolve: %v", err)
	}
	if res.Policy.Mode == model.ModeNone {
		t.Fatalf("clean path produced no policy; evidence=%v", res.Evidence)
	}
	// Copy the record across.
	rec, err := w.CleanPolicy.Store.Load(w.Domain)
	if err != nil || rec == nil {
		t.Fatalf("clean store: %v", err)
	}
	if err := w.Policy.Store.Save(rec); err != nil {
		t.Fatal(err)
	}
	w.Policy.ExpireForTest(w.Domain)
	res, err = w.Policy.Resolve(Ctx(), w.Domain)
	if err != nil {
		t.Fatalf("resolve after seeding: %v", err)
	}
	return res
}

// TLSAForSHA256 builds a DANE-EE TLSA record matching a certificate's SPKI.
func TLSAForSHA256(cert *x509.Certificate) model.TLSARecord {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return model.TLSARecord{Usage: 3, Selector: 1, MatchingType: 1, Data: sum[:]}
}

// AddTLSA publishes a TLSA record for an MX host in the domain zone.
func (w *World) AddTLSA(t *testing.T, host string, rec model.TLSARecord) {
	t.Helper()
	if w.domainZone == nil {
		t.Fatal("no domain zone")
	}
	w.domainZone.Add(&dns.TLSA{
		Hdr:          dns.RR_Header{Name: "_25._tcp." + host + ".", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 60},
		Usage:        rec.Usage,
		Selector:     rec.Selector,
		MatchingType: rec.MatchingType,
		Certificate:  hex.EncodeToString(rec.Data),
	})
}

// StopPolicyServer makes the policy HTTPS endpoint unavailable while leaving
// the DNS record in place, modelling a partner whose policy host is down.
func (w *World) StopPolicyServer(t *testing.T) {
	t.Helper()
	if w.policySrv == nil {
		t.Fatal("no policy server")
	}
	w.policySrv.Close()
}
