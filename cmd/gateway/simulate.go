package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"

	"gateway/internal/dnsx"
	"gateway/internal/lab"
	"gateway/internal/policy"
	"gateway/internal/queue"
	"gateway/internal/report"
	"gateway/internal/smtpc"
	"gateway/internal/sts"
)

// runSimulation builds a hostile network in-process and runs the gateway
// against it, printing the same report the real path produces.
//
// The scenario is deliberately the one from the brief: a partner with a
// signed zone and an enforcing policy, a second partner whose MX set is
// half-rolled-over, and an on-path attacker who strips STARTTLS from one
// host and the policy record from another.
func runSimulation(res *dnsx.Resolver, eng *policy.Engine, client *smtpc.Client, textOut, jsonOut io.Writer, stateDir string) int {
	fmt.Fprintln(os.Stderr, "gateway: -simulate builds a private lab network in-process")

	ca, err := lab.NewCA("simulation root")
	must(err)

	dnsSrv, err := lab.NewDNSServer()
	must(err)
	defer dnsSrv.Close()

	root, err := lab.NewZone(".", true)
	must(err)
	tld, err := lab.NewZone("example.", true)
	must(err)
	root.Delegate(tld)
	dnsSrv.AddZone(root)
	dnsSrv.AddZone(tld)

	type partner struct {
		domain string
		zone   *lab.Zone
		stmts  string
		id     string
		hosts  []string
	}
	partners := []partner{
		{domain: "good.example", stmts: "version: STSv1\nmode: enforce\nmx: mx1.good.example\nmax_age: 86400\n", id: "good-1", hosts: []string{"mx1.good.example"}},
		{domain: "roll.example", stmts: "version: STSv1\nmode: enforce\nmx: mx1.roll.example\nmx: mx2.roll.example\nmax_age: 86400\n", id: "roll-1", hosts: []string{"mx1.roll.example", "mx2.roll.example"}},
		{domain: "broken.example", stmts: "version: STSv1\nmode: enforce\nmx: mx1.broken.example\nmax_age: 86400\n", id: "broken-1", hosts: []string{"mx1.broken.example"}},
		{domain: "strip.example", stmts: "version: STSv1\nmode: enforce\nmx: mx1.strip.example\nmax_age: 86400\n", id: "strip-1", hosts: []string{"mx1.strip.example"}},
	}

	// Servers.
	type peer struct {
		srv  *lab.Server
		port int
	}
	peers := map[string]*peer{}
	stsSrv := map[string]*lab.PolicyServer{}
	stsAddr := map[string]string{}

	goodCert := lab.NewCertStore()
	iss, err := ca.Issue(lab.IssueOptions{DNSNames: []string{"mx1.good.example"}})
	must(err)
	goodCert.Set(iss.Cert, iss.Key)

	stripCert := lab.NewCertStore()
	iss, err = ca.Issue(lab.IssueOptions{DNSNames: []string{"mx1.strip.example"}})
	must(err)
	stripCert.Set(iss.Cert, iss.Key)

	rollGood := lab.NewCertStore()
	iss, err = ca.Issue(lab.IssueOptions{DNSNames: []string{"mx1.roll.example"}})
	must(err)
	rollGood.Set(iss.Cert, iss.Key)
	rollBad := lab.NewCertStore()
	iss, err = ca.Issue(lab.IssueOptions{DNSNames: []string{"mx1.roll.example"}})
	must(err)
	rollBad.Set(iss.Cert, iss.Key)

	brokenCert := lab.NewCertStore()
	iss, err = ca.Issue(lab.IssueOptions{DNSNames: []string{"mx1.broken.example"}})
	must(err)
	brokenCert.Set(iss.Cert, iss.Key)

	policies := map[string]lab.ServerPolicy{
		"mx1.good.example": {AdvertiseSTARTTLS: true, Certs: goodCert},
		// A server whose TLS is genuinely broken: it advertises STARTTLS
		// but cannot complete a handshake.
		"mx1.broken.example": {AdvertiseSTARTTLS: true, BreakHandshake: true, Certs: brokenCert},
		// The first host of the pair is mid-restart and cannot complete a
		// handshake; the second presents its sibling's certificate.
		"mx1.roll.example": {AdvertiseSTARTTLS: true, BreakHandshake: true, Certs: rollGood},
		"mx2.roll.example": {AdvertiseSTARTTLS: true, Certs: rollBad},
		// Only reachable once the attacker strips the capability.
		"mx1.strip.example": {AdvertiseSTARTTLS: false, Certs: stripCert},
	}
	for host, pol := range policies {
		s, err := lab.NewServer(host, pol)
		must(err)
		defer s.Close()
		peers[host] = &peer{srv: s, port: lab.PortOf(s.Addr())}
	}

	// Zones, policy hosts, and records.
	for _, p := range partners {
		z, err := lab.NewZone(p.domain, true)
		must(err)
		tld.Delegate(z)
		dnsSrv.AddZone(z)
		z.Add(&dns.TXT{
			Hdr: dns.RR_Header{Name: "_mta-sts." + p.domain + ".", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{"v=STSv1; id=" + p.id},
		})
		for i, h := range p.hosts {
			z.Add(&dns.MX{
				Hdr:        dns.RR_Header{Name: p.domain + ".", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60},
				Preference: uint16(i * 10),
				Mx:         h + ".",
			})
			z.Add(&dns.A{
				Hdr: dns.RR_Header{Name: h + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   []byte{127, 0, 0, 1},
			})
		}
		pair, err := ca.Issue(lab.IssueOptions{DNSNames: []string{"mta-sts." + p.domain}})
		must(err)
		ps, addr, err := lab.NewHTTPServer(tls.Certificate{
			Certificate: [][]byte{pair.Cert.Raw}, PrivateKey: pair.Key, Leaf: pair.Cert,
		}, p.stmts)
		must(err)
		defer ps.Close()
		stsSrv[p.domain] = ps
		stsAddr[p.domain] = addr
		host, _, _ := splitHostPort(addr)
		z.Add(&dns.A{
			Hdr: dns.RR_Header{Name: "mta-sts." + p.domain + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte(netIP(host)),
		})
	}

	// The attacker's DNS, aimed at one relationship. Everything else on
	// the network resolves normally, which is what makes the difference
	// between "the network is broken" and "someone is after this domain"
	// observable in the report.
	atk, err := lab.NewDNSAttacker(dnsSrv.Addr(), lab.AttackerStripPolicyTXT)
	must(err)
	atk.OnlyDomain = "strip.example"
	defer atk.Close()

	// Wire the engine to the simulated network.
	liveRes := dnsx.NewResolver(atk.Addr())
	liveRes.AddAnchor(".", root.Keys()[0])
	opts := policy.Options{
		// The attacker here is present before the first policy fetch, so
		// there is no baseline to compare against. The only defence is to
		// refuse to guess for relationships that are worth the
		// deliverability cost. This is the honest tradeoff, and the
		// simulation shows both sides of it: strip.example is protected,
		// and a domain nobody protected would have gone out in cleartext.
		ProtectedDomains: []string{"strip.example"},
		PolicyHostOverride: func(domain string) (string, bool) {
			a, ok := stsAddr[domain]
			return a, ok
		},
		MXPortOverride: func(host string) (int, bool) {
			p, ok := peers[host]
			if !ok {
				return 0, false
			}
			return p.port, true
		},
	}
	liveFetcher := &sts.Fetcher{Resolver: liveRes, Timeout: 5 * time.Second, ExtraRoots: ca.Pool()}
	liveEng := policy.New(liveRes, liveFetcher, policy.NewMemStore(), opts)
	liveClient := smtpc.New(smtpc.Config{HeloName: "simulation", Timeout: 5 * time.Second, Roots: ca.Pool()})

	var deliveries []report.Delivery
	ctx := context.Background()

	// Drive the *production* queue and client, not a parallel hand-rolled
	// loop. A simulation that exercises different code than production
	// proves nothing about production.
	store := queue.NewMemStore()
	worker := &queue.Worker{Engine: liveEng, Client: liveClient, Store: store}
	for _, p := range partners {
		e := &queue.Entry{
			ID: "sim-" + p.domain, Domain: p.domain, From: "gateway@corp.test",
			To:   []string{"ops@" + p.domain},
			Body: []byte("Subject: quarterly\r\n\r\nbody\r\n"),
		}
		if err := worker.Enqueue(ctx, e); err != nil {
			fmt.Fprintf(os.Stderr, "simulate: enqueue %s: %v\n", p.domain, err)
		}
	}
	reports, err := worker.RunOnce(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "simulate: run: %v\n", err)
		return 1
	}
	for _, r := range reports {
		deliveries = append(deliveries, toDelivery(r))
	}

	fmt.Fprintln(textOut, strings.Repeat("=", 72))
	report.WriteText(textOut, deliveries)
	fmt.Fprintln(textOut, strings.Repeat("=", 72))
	if err := report.WriteJSON(jsonOut, deliveries); err != nil {
		fmt.Fprintf(os.Stderr, "simulate: json: %v\n", err)
		return 1
	}
	return 0
}

func splitHostPort(a string) (string, string, error) {
	i := strings.LastIndex(a, ":")
	if i < 0 {
		return a, "", fmt.Errorf("no port in %q", a)
	}
	return a[:i], a[i+1:], nil
}

func netIP(host string) []byte {
	switch host {
	case "127.0.0.1", "localhost":
		return []byte{127, 0, 0, 1}
	}
	return []byte{127, 0, 0, 1}
}
