package lab

import (
	"crypto"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Zone is a simulated authoritative zone. It can be DNSSEC-signed (and then
// it is *actually* signed, so the gateway's validator has real work to do) or
// unsigned, and it can be served under a signed or unsigned delegation.
type Zone struct {
	Name string
	// Signed means every RRset gets an RRSIG and the zone has a DNSKEY.
	Signed bool
	// InsecureDelegation means the parent publishes no DS for this zone,
	// so validators should conclude "insecure" rather than "secure".
	InsecureDelegation bool
	// NoDNSSECOnDelegation additionally strips the parent's NSEC proof of
	// no-DS, which is what a resolver sees when DNSSEC data is filtered.
	NoDNSSECOnDelegation bool

	keys  []*dns.DNSKEY
	privs []crypto.Signer

	mu      sync.RWMutex
	records map[string]map[uint16][]dns.RR
	// ttl per name/type override
	ttl map[string]time.Duration
	// children are delegations (child zone names).
	children []string
	parent   *Zone
}

// NewZone creates a zone; signed zones get one ECDSA P-256 key.
func NewZone(name string, signed bool) (*Zone, error) {
	z := &Zone{
		Name:    dns.Fqdn(strings.ToLower(name)),
		Signed:  signed,
		records: map[string]map[uint16][]dns.RR{},
		ttl:     map[string]time.Duration{},
	}
	if signed {
		k := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: z.Name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags:     257, // KSK
			Protocol:  3,
			Algorithm: dns.ECDSAP256SHA256,
		}
		priv, err := k.Generate(256)
		if err != nil {
			return nil, err
		}
		z.keys = append(z.keys, k)
		z.privs = append(z.privs, priv.(crypto.Signer))
		// ZSK too, so the key set looks realistic.
		k2 := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: z.Name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags:     256,
			Protocol:  3,
			Algorithm: dns.ECDSAP256SHA256,
		}
		priv2, err := k2.Generate(256)
		if err != nil {
			return nil, err
		}
		z.keys = append(z.keys, k2)
		z.privs = append(z.privs, priv2.(crypto.Signer))
	}
	// Apex SOA and NS.
	z.addRaw(&dns.SOA{
		Hdr:    dns.RR_Header{Name: z.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:     subOf(z.Name, "ns1"),
		Mbox:   subOf(z.Name, "hostmaster"),
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
	})
	// Publish the DNSKEY RRset so it can actually be fetched and validated.
	if z.Signed {
		for _, k := range z.keys {
			z.addRaw(k)
		}
	}
	return z, nil
}

// Keys returns the zone's DNSKEYs (for installing anchors).
func (z *Zone) Keys() []*dns.DNSKEY { return z.keys }

// Add records a single RR.
func (z *Zone) Add(rr dns.RR) {
	z.addRaw(rr)
}

// SetTTL overrides the TTL for a name/type.
func (z *Zone) SetTTL(name string, ttl time.Duration) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.ttl[strings.ToLower(dns.Fqdn(name))] = ttl
}

func (z *Zone) addRaw(rr dns.RR) {
	z.mu.Lock()
	defer z.mu.Unlock()
	name := strings.ToLower(rr.Header().Name)
	if z.records[name] == nil {
		z.records[name] = map[uint16][]dns.RR{}
	}
	t := rr.Header().Rrtype
	// Replace any existing RRset of the same type.
	if _, exists := z.records[name][t]; !exists {
		z.records[name][t] = nil
	}
	z.records[name][t] = append(z.records[name][t], rr)
}

// Remove deletes all records for name/type.
func (z *Zone) Remove(name string, t uint16) {
	z.mu.Lock()
	defer z.mu.Unlock()
	name = strings.ToLower(dns.Fqdn(name))
	if m := z.records[name]; m != nil {
		delete(m, t)
	}
}

// Delegate records a child zone: NS in this zone, DS if the child is signed.
func (z *Zone) Delegate(child *Zone) {
	child.parent = z
	z.mu.Lock()
	z.children = append(z.children, child.Name)
	z.mu.Unlock()
	nsTarget := subOf(z.Name, "ns1")
	z.addRaw(&dns.NS{
		Hdr: dns.RR_Header{Name: child.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  nsTarget,
	})
	if child.Signed && !child.InsecureDelegation {
		ksk := child.keys[0]
		ds := ksk.ToDS(dns.SHA256)
		ds.Hdr = dns.RR_Header{Name: child.Name, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
		z.addRaw(ds)
	}
}

// sign adds RRSIGs for an RRset using the zone ZSK.
func (z *Zone) sign(rrset []dns.RR, name string, t uint16) []dns.RR {
	if !z.Signed || len(rrset) == 0 {
		return nil
	}
	if t == dns.TypeRRSIG {
		return nil
	}
	// DS at a delegation is signed by the parent, not the child; the parent
	// calls this on its own records, so no special case is needed here.
	now := time.Now()
	// Real zones sign the DNSKEY RRset with the KSK (SEP) key and
	// everything else with the ZSK. Reproducing that matters: a validator
	// that only anchors the KSK must still be able to bootstrap.
	ki := 1
	if t == dns.TypeDNSKEY {
		ki = 0
	}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: rrset[0].Header().Ttl},
		TypeCovered: t,
		Algorithm:   dns.ECDSAP256SHA256,
		Labels:      uint8(dns.CountLabel(name)),
		OrigTtl:     rrset[0].Header().Ttl,
		Expiration:  uint32(now.Add(24 * time.Hour).Unix()),
		Inception:   uint32(now.Add(-24 * time.Hour).Unix()),
		KeyTag:      z.keys[ki].KeyTag(),
		SignerName:  z.Name,
	}
	if err := sig.Sign(z.privs[ki], rrset); err != nil {
		panic(fmt.Sprintf("lab: sign %s: %v", name, err))
	}
	return []dns.RR{sig}
}

// authoritativeNames returns every name in the zone, canonically sorted,
// with the apex first.
func (z *Zone) authoritativeNames() []string {
	z.mu.RLock()
	seen := map[string]bool{z.Name: true}
	names := []string{z.Name}
	for n := range z.records {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	z.mu.RUnlock()
	sort.Slice(names, func(i, j int) bool { return canonicalLess(names[i], names[j]) })
	return names
}

// subOf joins a label under a zone apex, handling the root correctly:
// subOf(".", "ns1") is "ns1.", not "ns1..".
func subOf(apex, label string) string {
	return dns.Fqdn(label + "." + strings.TrimSuffix(apex, "."))
}

// canonicalLess orders names per RFC 4034 section 6.1: compare labels from
// the rightmost, each label as a lowercased octet string (so "_mta-sts"
// sorts before "mx1" because '_' is 0x5f and 'm' is 0x6d), and a name that
// is a prefix of another sorts first.
func canonicalLess(a, b string) bool {
	la := dns.SplitDomainName(strings.ToLower(a))
	lb := dns.SplitDomainName(strings.ToLower(b))
	n := len(la)
	if len(lb) < n {
		n = len(lb)
	}
	for i := 1; i <= n; i++ {
		x, y := la[len(la)-i], lb[len(lb)-i]
		if x != y {
			return x < y
		}
	}
	return len(la) < len(lb)
}

// Answer builds the response for qname/qtype as a recursive resolver would
// assemble it from this server's zones.
func (s *DNSServer) answer(qname string, qtype uint16) (answer []dns.RR, ns []dns.RR, rcode int) {
	qname = strings.ToLower(dns.Fqdn(qname))
	z := s.zoneFor(qname)

	// DS for a zone apex is answered by the parent.
	if qtype == dns.TypeDS && z != nil && z.parent != nil && qname == z.Name {
		return s.answerDS(z)
	}
	if z == nil {
		return nil, nil, dns.RcodeRefused
	}

	// Walking down: if qname is below a child zone that this server also
	// serves, the child answers. zoneFor already returns the deepest zone.
	z.mu.RLock()
	set := z.records[qname]
	z.mu.RUnlock()

	if set != nil {
		if rrs, ok := set[qtype]; ok && len(rrs) > 0 {
			out := append([]dns.RR(nil), rrs...)
			out = append(out, z.sign(rrs, qname, qtype)...)
			return out, nil, dns.RcodeSuccess
		}
		// Name exists, type does not: NODATA with an NSEC at qname.
		return nil, append(z.denialAt(qname), soaOf(z)...), dns.RcodeSuccess
	}

	// Name does not exist.
	return nil, append(z.denialCovering(qname), soaOf(z)...), dns.RcodeSuccess
}

func (s *DNSServer) answerDS(child *Zone) ([]dns.RR, []dns.RR, int) {
	p := child.parent
	p.mu.RLock()
	set := p.records[child.Name]
	p.mu.RUnlock()
	if set == nil {
		return nil, nil, dns.RcodeServerFailure
	}
	if ds, ok := set[dns.TypeDS]; ok && len(ds) > 0 {
		out := append([]dns.RR(nil), ds...)
		out = append(out, p.sign(ds, child.Name, dns.TypeDS)...)
		return out, nil, dns.RcodeSuccess
	}
	if child.NoDNSSECOnDelegation {
		// Filtered DNSSEC: the NSEC proof of no-DS is missing, so a
		// validator cannot conclude "insecure" — it fails closed.
		return nil, soaOf(p), dns.RcodeSuccess
	}
	return nil, append(p.denialAt(child.Name), soaOf(p)...), dns.RcodeSuccess
}

func soaOf(z *Zone) []dns.RR {
	z.mu.RLock()
	defer z.mu.RUnlock()
	soa := z.records[z.Name][dns.TypeSOA]
	if len(soa) == 0 {
		return nil
	}
	out := append([]dns.RR(nil), soa...)
	out = append(out, z.sign(soa, z.Name, dns.TypeSOA)...)
	return out
}

// denialAt returns the NSEC at name (proving type absence) with its RRSIG.
func (z *Zone) denialAt(name string) []dns.RR {
	if !z.Signed {
		return nil
	}
	names := z.authoritativeNames()
	next := names[0]
	for i, n := range names {
		if n == name {
			next = names[(i+1)%len(names)]
			break
		}
	}
	bitmap := z.typesAt(name)
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: next,
		TypeBitMap: bitmap,
	}
	out := []dns.RR{nsec}
	return append(out, z.sign(out, name, dns.TypeNSEC)...)
}

// denialCovering returns the NSEC whose interval covers name.
func (z *Zone) denialCovering(name string) []dns.RR {
	if !z.Signed {
		return nil
	}
	names := z.authoritativeNames()
	var owner string
	for _, n := range names {
		if canonicalLess(n, name) {
			owner = n
		}
	}
	if owner == "" {
		owner = names[len(names)-1]
	}
	next := names[0]
	for i, n := range names {
		if n == owner {
			next = names[(i+1)%len(names)]
			break
		}
	}
	// Do not emit a delegation NSEC that accidentally "covers" a name that
	// exists in a child zone.
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: next,
		TypeBitMap: z.typesAt(owner),
	}
	out := []dns.RR{nsec}
	return append(out, z.sign(out, owner, dns.TypeNSEC)...)
}

func (z *Zone) typesAt(name string) []uint16 {
	z.mu.RLock()
	defer z.mu.RUnlock()
	var out []uint16
	for t := range z.records[name] {
		out = append(out, t)
	}
	if z.Signed {
		out = append(out, dns.TypeRRSIG)
	}
	if name == z.Name {
		// Apex is also a delegation point in the labs we build.
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// DNSServer serves the configured zones over UDP and TCP.
type DNSServer struct {
	mu    sync.RWMutex
	zones map[string]*Zone
	addr  string
	udp   *dns.Server
	tcp   *dns.Server
	// Queries counts every request, for cache assertions.
	Queries atomic.Int64
}

// NewDNSServer starts a server on loopback.
func NewDNSServer() (*DNSServer, error) {
	s := &DNSServer{zones: map[string]*Zone{}}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		s.Queries.Add(1)
		resp := s.handle(req)
		w.WriteMsg(resp)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		return nil, err
	}
	s.addr = pc.LocalAddr().String()
	s.udp = &dns.Server{PacketConn: pc, Handler: h}
	s.tcp = &dns.Server{Listener: ln, Handler: h}
	go s.udp.ActivateAndServe()
	go s.tcp.ActivateAndServe()
	return s, nil
}

func (s *DNSServer) Addr() string { return s.addr }

// QueryCount returns the number of DNS requests served so far.
func (s *DNSServer) QueryCount() int64 { return s.Queries.Load() }

func (s *DNSServer) Close() {
	s.udp.Shutdown()
	s.tcp.Shutdown()
}

// AddZone registers a zone.
func (s *DNSServer) AddZone(z *Zone) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zones[z.Name] = z
}

func (s *DNSServer) zoneFor(qname string) *Zone {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *Zone
	for name, z := range s.zones {
		if dns.IsSubDomain(name, qname) {
			if best == nil || len(name) > len(best.Name) {
				best = z
			}
		}
	}
	return best
}

func (s *DNSServer) handle(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	if len(req.Question) == 0 {
		resp.Rcode = dns.RcodeFormatError
		return resp
	}
	q := req.Question[0]
	ans, ns, rcode := s.answer(q.Name, q.Qtype)
	resp.Rcode = rcode
	resp.Answer = ans
	resp.Ns = ns
	if req.IsEdns0() != nil {
		resp.SetEdns0(4096, true)
		resp.Extra = append(resp.Extra, &dns.OPT{
			Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096},
			Option: nil,
		})
	}
	return resp
}

// AttackerMode selects what an on-path DNS attacker does to responses.
type AttackerMode int

const (
	// AttackerPassive forwards without modification.
	AttackerPassive AttackerMode = iota
	// AttackerStripPolicyTXT removes _mta-sts TXT answers and their
	// signatures. Against a signed zone the result cannot be made to look
	// like a valid denial, so a validating resolver sees "bogus".
	AttackerStripPolicyTXT
	// AttackerStripAllSigs removes every RRSIG, modelling an attacker who
	// believes the resolver does not validate.
	AttackerStripAllSigs
	// AttackerForgeNXDOMAIN replaces the whole answer with an empty
	// NXDOMAIN carrying no proof.
	AttackerForgeNXDOMAIN
	// AttackerStripDANE removes TLSA answers.
	AttackerStripDANE
	// AttackerRewriteTLSA replaces TLSA records with the attacker's own.
	AttackerRewriteTLSA
)

// DNSAttacker is a DNS server that forwards to upstream and mutates replies.
type DNSAttacker struct {
	Upstream string
	Mode     AttackerMode
	// OnlyDomain restricts the attack to names under this suffix. Empty
	// attacks everything. Targeting one partner is both more realistic
	// and more instructive: it is the difference between a network-wide
	// DNS problem and an interception aimed at one relationship.
	OnlyDomain string
	// ReplaceTLSA is the attacker's TLSA payload for AttackerRewriteTLSA.
	ReplaceTLSA []dns.RR

	addr string
	udp  *dns.Server
	udpC net.PacketConn
	Mu   sync.Mutex
	Seen int
}

// NewDNSAttacker starts the attacker.
func NewDNSAttacker(upstream string, mode AttackerMode) (*DNSAttacker, error) {
	a := &DNSAttacker{Upstream: upstream, Mode: mode}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	a.addr = pc.LocalAddr().String()
	a.udpC = pc
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		a.Mu.Lock()
		a.Seen++
		a.Mu.Unlock()
		resp := a.forward(req)
		if resp != nil {
			w.WriteMsg(resp)
		}
	})
	a.udp = &dns.Server{PacketConn: pc, Handler: h}
	go a.udp.ActivateAndServe()
	return a, nil
}

func (a *DNSAttacker) Addr() string { return a.addr }
func (a *DNSAttacker) Close()       { a.udp.Shutdown() }

func (a *DNSAttacker) forward(req *dns.Msg) *dns.Msg {
	c := &dns.Client{Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(req, a.Upstream)
	if err != nil || resp == nil {
		return nil
	}
	q := req.Question[0]
	if a.OnlyDomain != "" && !dns.IsSubDomain(dns.Fqdn(a.OnlyDomain), strings.ToLower(q.Name)) {
		return resp
	}
	isSTS := strings.HasPrefix(strings.ToLower(q.Name), "_mta-sts.")
	isTLSA := q.Qtype == dns.TypeTLSA

	switch a.Mode {
	case AttackerStripAllSigs:
		var ans, ns []dns.RR
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype != dns.TypeRRSIG {
				ans = append(ans, rr)
			}
		}
		for _, rr := range resp.Ns {
			if rr.Header().Rrtype != dns.TypeRRSIG {
				ns = append(ns, rr)
			}
		}
		resp.Answer, resp.Ns = ans, ns
	case AttackerForgeNXDOMAIN:
		resp.Answer = nil
		resp.Ns = nil
		resp.Rcode = dns.RcodeNameError
	case AttackerStripPolicyTXT:
		if isSTS && q.Qtype == dns.TypeTXT {
			// The attacker cannot forge a signed denial, so it simply
			// removes the answer. This is what real filtering looks like.
			resp.Answer = nil
			resp.Ns = nil
			resp.Rcode = dns.RcodeSuccess
		}
	case AttackerStripDANE:
		if isTLSA {
			resp.Answer = nil
			resp.Ns = nil
		}
	case AttackerRewriteTLSA:
		if isTLSA {
			resp.Answer = append([]dns.RR(nil), a.ReplaceTLSA...)
		}
	}
	return resp
}
