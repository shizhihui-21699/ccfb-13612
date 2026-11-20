// Package dnsx is a small validating resolver built for mail transport
// security. It does not trust the AD bit of an upstream resolver: it fetches
// RRSIGs itself and validates the delegation chain from a configured trust
// anchor.
//
// The distinction it makes between "secure", "insecure", "bogus" and
// "indeterminate" is the entire reason it exists. A conventional stub
// resolver collapses all four into "here is an empty answer", and that
// collapse is precisely how an on-path attacker turns an enforced
// transport-security policy into opportunistic cleartext: strip the record,
// answer NXDOMAIN, and the sender concludes the domain publishes nothing.
package dnsx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"gateway/internal/model"
)

// ErrNoRRSIG is returned when an answer that must be signed carries no
// signature.
var ErrNoRRSIG = errors.New("dnsx: answer carries no RRSIG")

// Resolver validates DNSSEC locally against trust anchors.
type Resolver struct {
	// Upstream is the address of the DNS server we ask. In a hostile
	// network this may be an attacker: that is the point. We never believe
	// its AD bit.
	Upstream string
	Timeout  time.Duration
	// Anchors maps a zone name to the DNSKEY records trusted out of band.
	Anchors map[string][]*dns.DNSKEY
	// MaxDepth bounds the delegation chain walk.
	MaxDepth int
	// clean is an alternate resolver address used only by the lab, to
	// establish trust before an attacker joins the path. Production never
	// sets it.
	clean string

	mu      sync.Mutex
	keys    map[string]*zoneKey
	queries int
}

type zoneKey struct {
	keys    []*dns.DNSKEY
	status  model.DNSStatus
	expires time.Time
}

func NewResolver(upstream string) *Resolver {
	return &Resolver{
		Upstream: upstream,
		Timeout:  3 * time.Second,
		Anchors:  map[string][]*dns.DNSKEY{},
		keys:     map[string]*zoneKey{},
		MaxDepth: 12,
	}
}

// SetCleanUpstream installs a lab-only alternate resolver used by
// LookupClean. Production code never calls it, and nothing that decides a
// security outcome goes through it.
func (r *Resolver) SetCleanUpstream(addr string) { r.clean = addr }

// CleanResolver returns an independent resolver pointed at the clean
// upstream, with the same anchors. It exists so a lab test can establish a
// baseline policy and then introduce an attacker, which is the "attacker
// joined later" scenario.
func (r *Resolver) CleanResolver() (*Resolver, error) {
	if r.clean == "" {
		return nil, errors.New("dnsx: no clean upstream")
	}
	cp := NewResolver(r.clean)
	cp.Timeout = r.Timeout
	cp.MaxDepth = r.MaxDepth
	for z, ks := range r.Anchors {
		cp.Anchors[z] = ks
	}
	return cp, nil
}

// AddAnchor installs a trusted DNSKEY for a zone. The key is copied rather
// than mutated: the caller's DNSKEY may be shared with whatever served it,
// and silently rewriting a record's owner name is exactly the kind of
// aliasing bug that turns into a signature failure at the worst moment.
func (r *Resolver) AddAnchor(zone string, k *dns.DNSKEY) {
	zone = fqdn(zone)
	cp := dns.Copy(k).(*dns.DNSKEY)
	cp.Hdr.Name = zone
	r.Anchors[zone] = append(r.Anchors[zone], cp)
	r.mu.Lock()
	delete(r.keys, zone)
	r.mu.Unlock()
}

// Stats returns how many upstream queries have been made, for the lab's
// assertions about caching behaviour.
func (r *Resolver) Stats() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.queries
}

type answer struct {
	rrset []dns.RR
	sigs  []*dns.RRSIG
	// nsec records prove denial of existence when rrset is empty.
	denial   []dns.RR
	denialBy []*dns.RRSIG
	// soa is the authority SOA of a negative answer; its owner names the
	// zone whose keys can validate the denial.
	soa    *dns.SOA
	status model.DNSStatus
	err    error
}

// RRSet is the public result of a validated lookup.
type RRSet struct {
	Records []dns.RR
	Status  model.DNSStatus
	// Exists is false when a validated denial-of-existence proves the name
	// or type is absent.
	Exists bool
	Err    error
}

func (r *Resolver) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(fqdn(name), qtype)
	m.SetEdns0(4096, true)
	m.RecursionDesired = true

	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	d := &dns.Client{Timeout: timeout, Net: "udp"}
	ctx, cancel := context.WithTimeout(ctx, timeout*3)
	defer cancel()

	r.mu.Lock()
	r.queries++
	r.mu.Unlock()

	resp, _, err := d.ExchangeContext(ctx, m, r.Upstream)
	if err != nil {
		// Retry over TCP once: truncated or filtered UDP is common in the
		// situations this gateway exists for.
		d.Net = "tcp"
		d.Timeout = timeout * 2
		resp, _, err = d.ExchangeContext(ctx, m, r.Upstream)
		if err != nil {
			return nil, fmt.Errorf("dns query %s %s: %w", name, dns.TypeToString[qtype], err)
		}
	}
	if resp.Truncated {
		d.Net = "tcp"
		resp, _, err = d.ExchangeContext(ctx, m, r.Upstream)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// Lookup returns the RRset for name/qtype with its validation status.
//
// The returned status is authoritative about *authenticity*: secure means
// the answer or its denial was validated to the trust anchor; bogus means
// the zone is signed but this answer does not validate, which in a hostile
// network is indistinguishable from tampering.
func (r *Resolver) Lookup(ctx context.Context, name string, qtype uint16) RRSet {
	name = fqdn(name)
	resp, err := r.query(ctx, name, qtype)
	if err != nil {
		return RRSet{Status: model.DNSIndeterminate, Err: err}
	}
	return r.validate(ctx, name, qtype, resp)
}

func (r *Resolver) validate(ctx context.Context, name string, qtype uint16, resp *dns.Msg) RRSet {
	a := &answer{}
	switch resp.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		// NXDOMAIN: denial must cover both the name and the wildcard.
	default:
		return RRSet{Status: model.DNSIndeterminate, Err: fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode])}
	}

	var rrset []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == qtype && strings.EqualFold(rr.Header().Name, name) {
			rrset = append(rrset, rr)
		} else if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == qtype && strings.EqualFold(sig.Hdr.Name, name) {
			sigs = append(sigs, sig)
		}
	}
	// A CNAME chain would need follow-up; mail policy lookups do not use
	// them for the names we care about, and silently following one would be
	// an attack surface. Treat as indeterminate rather than resolve.
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeCNAME && strings.EqualFold(rr.Header().Name, name) {
			return RRSet{Status: model.DNSIndeterminate, Err: errors.New("dnsx: unexpected CNAME")}
		}
	}

	a.rrset, a.sigs = rrset, sigs

	if len(rrset) == 0 {
		// Negative answer. Collect proof and the authority zone.
		for _, rr := range resp.Ns {
			switch t := rr.(type) {
			case *dns.NSEC:
				a.denial = append(a.denial, t)
			case *dns.NSEC3:
				a.denial = append(a.denial, t)
			case *dns.SOA:
				if a.soa == nil {
					a.soa = t
				}
			}
		}
		for _, rr := range resp.Ns {
			if sig, ok := rr.(*dns.RRSIG); ok {
				if sig.TypeCovered == dns.TypeNSEC || sig.TypeCovered == dns.TypeNSEC3 {
					a.denialBy = append(a.denialBy, sig)
				}
			}
		}
		// Some servers place the negative proof in Answer for empty
		// non-terminal answers.
		if len(a.denial) == 0 && a.soa == nil {
			for _, rr := range resp.Answer {
				switch t := rr.(type) {
				case *dns.NSEC:
					a.denial = append(a.denial, t)
				case *dns.NSEC3:
					a.denial = append(a.denial, t)
				}
			}
		}
	}

	zone := signerZone(a, name)
	if zone == "" {
		// A positive answer with no signatures and no authority section
		// still tells us nothing about which zone should have signed it.
		// Ask for the SOA to find the apex, then validate normally; an
		// unsigned zone will come back insecure, a signed one bogus.
		zone = r.findZone(ctx, name)
	}
	if zone == "" {
		return RRSet{Status: model.DNSIndeterminate, Err: errors.New("dnsx: cannot determine signing zone")}
	}

	keys, kstatus, err := r.zoneKeys(ctx, zone, 0)
	if err != nil {
		return RRSet{Status: model.DNSIndeterminate, Err: err}
	}
	if kstatus == model.DNSInsecure {
		// Provably unsigned delegation: the answer is as trustworthy as the
		// resolver channel, which is to say not at all against an on-path
		// attacker. Callers must treat insecure exactly like untrusted for
		// policy purposes.
		return RRSet{Records: rrset, Status: model.DNSInsecure, Exists: len(rrset) > 0}
	}
	if kstatus != model.DNSSecure {
		return RRSet{Status: kstatus, Err: errors.New("dnsx: zone keys not secure")}
	}

	if len(rrset) > 0 {
		if len(sigs) == 0 {
			return RRSet{Status: model.DNSBogus, Err: ErrNoRRSIG}
		}
		if err := verifyRRset(rrset, sigs, keys, zone); err != nil {
			return RRSet{Status: model.DNSBogus, Err: err}
		}
		return RRSet{Records: rrset, Status: model.DNSSecure, Exists: true}
	}

	// Negative answer: validate the denial.
	if err := r.verifyDenial(ctx, a, name, keys, zone); err != nil {
		return RRSet{Status: model.DNSBogus, Err: err}
	}
	return RRSet{Status: model.DNSSecure, Exists: false}
}

// findZone locates the enclosing zone apex for name by asking for its SOA.
// Recursion into the SOA answer is deliberately avoided: this runs only to
// name the zone whose DNSKEY set should be consulted, and the SOA itself is
// not trusted for anything else.
func (r *Resolver) findZone(ctx context.Context, name string) string {
	resp, err := r.query(ctx, name, dns.TypeSOA)
	if err != nil {
		return ""
	}
	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return fqdn(soa.Hdr.Name)
		}
	}
	for _, rr := range resp.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return fqdn(soa.Hdr.Name)
		}
	}
	return ""
}

// signerZone picks the zone that should have signed this answer.
func signerZone(a *answer, name string) string {
	for _, s := range a.sigs {
		return fqdn(s.SignerName)
	}
	for _, s := range a.denialBy {
		return fqdn(s.SignerName)
	}
	if a.soa != nil {
		return fqdn(a.soa.Hdr.Name)
	}
	return ""
}

func (r *Resolver) verifyDenial(ctx context.Context, a *answer, name string, keys []*dns.DNSKEY, zone string) error {
	if len(a.denial) == 0 {
		return errors.New("dnsx: negative answer without NSEC/NSEC3 proof")
	}
	var lastErr error
	for _, rr := range a.denial {
		var sigs []*dns.RRSIG
		for _, s := range a.denialBy {
			if strings.EqualFold(s.Hdr.Name, rr.Header().Name) && s.TypeCovered == rr.Header().Rrtype {
				sigs = append(sigs, s)
			}
		}
		if len(sigs) == 0 {
			lastErr = fmt.Errorf("dnsx: denial %s unsigned", rr.Header().Name)
			continue
		}
		// The owner of an NSEC3 record is a hash, not the zone; validate
		// the RRSIG's signer field, which is the zone name.
		if err := verifyRRset([]dns.RR{rr}, sigs, keys, zone); err != nil {
			lastErr = err
			continue
		}
		if coversName(rr, name) {
			return nil
		}
		lastErr = fmt.Errorf("dnsx: denial %s does not cover %s", rr.Header().Name, name)
	}
	if lastErr == nil {
		lastErr = errors.New("dnsx: no denial matched")
	}
	return lastErr
}

// coversName reports whether an NSEC/NSEC3 record proves qname absent.
func coversName(rr dns.RR, name string) bool {
	name = fqdn(name)
	switch t := rr.(type) {
	case *dns.NSEC:
		return nsecCovers(t, name)
	case *dns.NSEC3:
		return nsec3Covers(t, name)
	}
	return false
}

func nsecCovers(n *dns.NSEC, name string) bool {
	owner := fqdn(n.Hdr.Name)
	next := fqdn(n.NextDomain)
	if strings.EqualFold(owner, name) {
		// Exact match: proves the name exists but the type does not.
		return true
	}
	// Only a same-zone interval can prove absence.
	zone := parentZone(owner)
	if !dns.IsSubDomain(zone, name) {
		return false
	}
	return inCanonicalInterval(owner, next, name)
}

func nsec3Covers(n *dns.NSEC3, name string) bool {
	return n.Cover(name) || n.Match(name)
}

// inCanonicalInterval reports whether x lies strictly between lo and hi in
// DNSSEC canonical name order, handling the wrap at the apex.
func inCanonicalInterval(lo, hi, x string) bool {
	if strings.EqualFold(lo, hi) {
		return false
	}
	cl := canonicalCompare(x, lo)
	ch := canonicalCompare(x, hi)
	wrap := canonicalCompare(hi, lo) < 0
	if wrap { // lo is last name in zone
		return cl > 0 || ch < 0
	}
	return cl > 0 && ch < 0
}

// canonicalCompare compares two names in DNSSEC canonical order
// (RFC 4034 6.1): label by label from the right, then by wire bytes.
func canonicalCompare(a, b string) int {
	la := dns.SplitDomainName(strings.ToLower(a))
	lb := dns.SplitDomainName(strings.ToLower(b))
	for i := 1; i <= len(la) && i <= len(lb); i++ {
		x, y := la[len(la)-i], lb[len(lb)-i]
		if c := compareLabel(x, y); c != 0 {
			return c
		}
	}
	switch {
	case len(la) < len(lb):
		return -1
	case len(la) > len(lb):
		return 1
	}
	return 0
}

func compareLabel(x, y string) int {
	ax, ay := []byte(x), []byte(y)
	for i := 0; i < len(ax) && i < len(ay); i++ {
		if ax[i] != ay[i] {
			if ax[i] < ay[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ax) < len(ay):
		return -1
	case len(ax) > len(ay):
		return 1
	}
	return 0
}

// zoneKeys returns the validated DNSKEY set for zone, following the chain of
// trust from a configured anchor down to zone.
func (r *Resolver) zoneKeys(ctx context.Context, zone string, depth int) ([]*dns.DNSKEY, model.DNSStatus, error) {
	zone = fqdn(zone)
	if depth > r.MaxDepth {
		return nil, model.DNSIndeterminate, errors.New("dnsx: delegation chain too deep")
	}
	r.mu.Lock()
	if zk, ok := r.keys[zone]; ok && time.Now().Before(zk.expires) {
		r.mu.Unlock()
		return zk.keys, zk.status, nil
	}
	r.mu.Unlock()

	if ks, ok := r.Anchors[zone]; ok && len(ks) > 0 {
		// An anchor is a trust judgement about specific key material, not
		// about the whole RRset. Fetch the zone's DNSKEY RRset, require it
		// to be signed by an anchored key, and trust the full set — which
		// is what makes zone-signing keys usable.
		fetched, err := r.fetchDNSKEY(ctx, zone)
		if err != nil {
			// Fall back to the anchor alone: a broken fetch must not turn
			// into "no keys" at the root of the chain.
			r.cacheZone(zone, ks, model.DNSSecure, time.Minute)
			return ks, model.DNSSecure, nil
		}
		rrs := make([]dns.RR, len(fetched))
		for i, k := range fetched {
			rrs[i] = k
		}
		resp, qerr := r.query(ctx, zone, dns.TypeDNSKEY)
		if qerr == nil {
			var sigs []*dns.RRSIG
			for _, rr := range resp.Answer {
				if sg, ok := rr.(*dns.RRSIG); ok && sg.TypeCovered == dns.TypeDNSKEY &&
					strings.EqualFold(sg.Hdr.Name, zone) {
					sigs = append(sigs, sg)
				}
			}
			if len(sigs) > 0 {
				if err := verifyRRset(rrs, sigs, ks, zone); err != nil {
					return nil, model.DNSBogus, fmt.Errorf("dnsx: anchored DNSKEY RRset invalid: %w", err)
				}
			}
		}
		ttl := 3600 * time.Second
		if len(fetched) > 0 && fetched[0].Hdr.Ttl > 0 {
			ttl = time.Duration(fetched[0].Hdr.Ttl) * time.Second
		}
		r.cacheZone(zone, fetched, model.DNSSecure, ttl)
		return fetched, model.DNSSecure, nil
	}

	// Find the DS RRset at this zone, which lives in the parent.
	dsRR, status, err := r.lookupDS(ctx, zone, depth)
	if err != nil {
		return nil, status, err
	}
	if status == model.DNSInsecure || (status == model.DNSSecure && len(dsRR) == 0) {
		// Provable unsigned delegation.
		r.cacheZone(zone, nil, model.DNSInsecure, time.Hour)
		return nil, model.DNSInsecure, nil
	}
	if status != model.DNSSecure {
		return nil, status, fmt.Errorf("dnsx: DS for %s: status %s", zone, status)
	}

	// Fetch the zone's DNSKEY set and validate it against the DS.
	dnskeys, err := r.fetchDNSKEY(ctx, zone)
	if err != nil {
		return nil, model.DNSIndeterminate, err
	}
	if err := verifyDNSKEYWithDS(dnskeys, dsRR, zone); err != nil {
		return nil, model.DNSBogus, err
	}
	ttl := 3600 * time.Second
	if len(dnskeys) > 0 {
		ttl = time.Duration(dnskeys[0].Hdr.Ttl) * time.Second
	}
	r.cacheZone(zone, dnskeys, model.DNSSecure, ttl)
	return dnskeys, model.DNSSecure, nil
}

func (r *Resolver) cacheZone(zone string, keys []*dns.DNSKEY, status model.DNSStatus, ttl time.Duration) {
	if ttl <= 0 {
		ttl = time.Minute
	}
	r.mu.Lock()
	r.keys[zone] = &zoneKey{keys: keys, status: status, expires: time.Now().Add(ttl)}
	r.mu.Unlock()
}

// lookupDS validates the DS RRset for zone. On a provably unsigned
// delegation it returns nil with status insecure.
func (r *Resolver) lookupDS(ctx context.Context, zone string, depth int) ([]*dns.DS, model.DNSStatus, error) {
	if zone == "." {
		return nil, model.DNSIndeterminate, errors.New("dnsx: no anchor covers root")
	}
	resp, err := r.query(ctx, zone, dns.TypeDS)
	if err != nil {
		return nil, model.DNSIndeterminate, err
	}
	// Find DS + its signatures.
	var ds []*dns.DS
	var sigs []*dns.RRSIG
	var denial []dns.RR
	var denialSigs []*dns.RRSIG
	for _, rr := range resp.Answer {
		switch t := rr.(type) {
		case *dns.DS:
			if strings.EqualFold(t.Hdr.Name, zone) {
				ds = append(ds, t)
			}
		case *dns.RRSIG:
			if t.TypeCovered == dns.TypeDS && strings.EqualFold(t.Hdr.Name, zone) {
				sigs = append(sigs, t)
			}
		}
	}
	if len(ds) == 0 {
		for _, rr := range resp.Ns {
			switch t := rr.(type) {
			case *dns.NSEC:
				denial = append(denial, t)
			case *dns.NSEC3:
				denial = append(denial, t)
			}
		}
		for _, rr := range resp.Ns {
			if s, ok := rr.(*dns.RRSIG); ok && (s.TypeCovered == dns.TypeNSEC || s.TypeCovered == dns.TypeNSEC3) {
				denialSigs = append(denialSigs, s)
			}
		}
	}

	if len(ds) == 0 {
		// Unsigned delegation, or no delegation at all. Either way there is
		// no DS; find out whether the parent proves that securely.
		parent := parentZone(zone)
		pkeys, pstatus, err := r.zoneKeys(ctx, parent, depth+1)
		if err != nil {
			return nil, pstatus, err
		}
		if pstatus == model.DNSInsecure {
			return nil, model.DNSInsecure, nil
		}
		if len(denial) == 0 {
			return nil, model.DNSBogus, errors.New("dnsx: no DS and no denial proof")
		}
		for _, rr := range denial {
			var s []*dns.RRSIG
			for _, sg := range denialSigs {
				if strings.EqualFold(sg.Hdr.Name, rr.Header().Name) && sg.TypeCovered == rr.Header().Rrtype {
					s = append(s, sg)
				}
			}
			if len(s) == 0 {
				continue
			}
			if err := verifyRRset([]dns.RR{rr}, s, pkeys, parent); err != nil {
				continue
			}
			if nsecProvesNoDS(rr, zone) {
				return nil, model.DNSInsecure, nil
			}
		}
		return nil, model.DNSBogus, errors.New("dnsx: denial does not prove absence of DS")
	}

	parent := parentZone(zone)
	pkeys, pstatus, err := r.zoneKeys(ctx, parent, depth+1)
	if err != nil {
		return nil, pstatus, err
	}
	if pstatus != model.DNSSecure {
		return nil, pstatus, fmt.Errorf("dnsx: parent %s not secure", parent)
	}
	if len(sigs) == 0 {
		return nil, model.DNSBogus, errors.New("dnsx: DS unsigned")
	}
	rrs := make([]dns.RR, len(ds))
	for i, d := range ds {
		rrs[i] = d
	}
	if err := verifyRRset(rrs, sigs, pkeys, parent); err != nil {
		return nil, model.DNSBogus, err
	}
	return ds, model.DNSSecure, nil
}

func nsecProvesNoDS(rr dns.RR, zone string) bool {
	switch t := rr.(type) {
	case *dns.NSEC:
		if !strings.EqualFold(t.Hdr.Name, zone) {
			return false
		}
		for _, ty := range t.TypeBitMap {
			if ty == dns.TypeDS {
				return false
			}
		}
		for _, ty := range t.TypeBitMap {
			if ty == dns.TypeSOA {
				// An NSEC at the child apex with SOA means it is a zone,
				// and without DS it is an unsigned delegation.
				return false
			}
		}
		// NSEC at the delegation point with NS and no DS/SOA.
		hasNS := false
		for _, ty := range t.TypeBitMap {
			if ty == dns.TypeNS {
				hasNS = true
			}
		}
		return hasNS
	case *dns.NSEC3:
		// Opt-out (flag bit 0x01) can prove an unsigned delegation exists.
		return t.Match(zone) && t.Flags&1 == 1
	}
	return false
}

func (r *Resolver) fetchDNSKEY(ctx context.Context, zone string) ([]*dns.DNSKEY, error) {
	resp, err := r.query(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	var keys []*dns.DNSKEY
	var sigs []*dns.RRSIG
	for _, rr := range resp.Answer {
		switch t := rr.(type) {
		case *dns.DNSKEY:
			if strings.EqualFold(t.Hdr.Name, zone) {
				keys = append(keys, t)
			}
		case *dns.RRSIG:
			if t.TypeCovered == dns.TypeDNSKEY && strings.EqualFold(t.Hdr.Name, zone) {
				sigs = append(sigs, t)
			}
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("dnsx: empty DNSKEY")
	}
	if len(sigs) == 0 {
		return nil, ErrNoRRSIG
	}
	rrs := make([]dns.RR, len(keys))
	for i, k := range keys {
		rrs[i] = k
	}
	// The DNSKEY RRset must be self-signed by a key in the set.
	if err := verifyRRset(rrs, sigs, keys, zone); err != nil {
		return nil, err
	}
	return keys, nil
}

// verifyDNSKEYWithDS checks that some DNSKEY in keys is the digest of some DS.
func verifyDNSKEYWithDS(keys []*dns.DNSKEY, ds []*dns.DS, zone string) error {
	for _, k := range keys {
		if k.Hdr.Name != fqdn(zone) {
			continue
		}
		for _, d := range ds {
			if k.KeyTag() != d.KeyTag || k.Algorithm != d.Algorithm {
				continue
			}
			got := k.ToDS(d.DigestType)
			if got == nil {
				continue
			}
			if strings.EqualFold(got.Digest, d.Digest) {
				return nil
			}
		}
	}
	return errors.New("dnsx: no DNSKEY matches DS")
}

// verifyRRset validates sigs against the signed rrset using keys.
func verifyRRset(rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, zone string) error {
	var lastErr error
	for _, sig := range sigs {
		if !strings.EqualFold(sig.SignerName, fqdn(zone)) {
			continue
		}
		for _, k := range keys {
			if k.KeyTag() != sig.KeyTag || k.Algorithm != sig.Algorithm {
				continue
			}
			if err := sig.Verify(k, rrset); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("dnsx: no matching key for RRSIG")
	}
	return lastErr
}

func parentZone(zone string) string {
	zone = fqdn(zone)
	if zone == "." {
		return "."
	}
	parts := dns.SplitDomainName(zone)
	if len(parts) <= 1 {
		return "."
	}
	return fqdn(strings.Join(parts[1:], "."))
}

func fqdn(s string) string { return strings.ToLower(dns.Fqdn(s)) }

// String helpers for tests and logs.

// SortedNames returns the owner names of rrset, sorted, for deterministic
// diffing in reports.
func SortedNames(rrset []dns.RR) []string {
	out := make([]string, 0, len(rrset))
	for _, rr := range rrset {
		out = append(out, rr.Header().Name)
	}
	sort.Strings(out)
	return out
}

// Addr resolves A and AAAA and returns them with the worse of the two
// validation statuses. An attacker who can forge one family must not be
// able to hide behind a clean answer for the other.
func (r *Resolver) Addr(ctx context.Context, host string) ([]net.IP, model.DNSStatus, error) {
	var ips []net.IP
	status := model.DNSSecure
	var firstErr error
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		res := r.Lookup(ctx, host, qt)
		status = worseStatus(status, res.Status)
		if res.Err != nil {
			status = worseStatus(status, res.Status)
			if firstErr == nil && res.Status != model.DNSSecure {
				firstErr = res.Err
			}
		}
		if res.Exists {
			for _, rr := range res.Records {
				switch t := rr.(type) {
				case *dns.A:
					ips = append(ips, t.A)
				case *dns.AAAA:
					ips = append(ips, t.AAAA)
				}
			}
		}
	}
	if len(ips) == 0 && firstErr == nil {
		firstErr = errors.New("dnsx: host has no address records")
	}
	return ips, status, firstErr
}

var statusRank = map[model.DNSStatus]int{
	model.DNSSecure:        0,
	model.DNSInsecure:      1,
	model.DNSBogus:         2,
	model.DNSIndeterminate: 3,
}

// worseStatus returns whichever status is worse; indeterminate outranks
// bogus because we cannot even tell what happened.
func worseStatus(a, b model.DNSStatus) model.DNSStatus {
	if statusRank[b] > statusRank[a] {
		return b
	}
	return a
}
