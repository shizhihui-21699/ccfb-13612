// Package policy resolves the effective transport-security policy for a
// recipient domain and is the only place that decides whether cleartext is
// permitted.
//
// Design rules encoded here (see docs/DESIGN.md for the reasoning):
//
//	R1  No reduction in protection without authenticated evidence.
//	    A policy observation that is weaker than the last accepted one is
//	    ignored until the old policy has expired, and even then only if the
//	    weaker observation is either DNSSEC-authenticated or stable across a
//	    wall-clock window (which defeats a one-shot replay).
//
//	R2  Absence is not permission. "No _mta-sts record" from an
//	    unauthenticated resolver is a *weaker* observation than any policy
//	    we have ever accepted, and is handled by R1.
//
//	R3  Failure to refresh never lowers the mode. If the cache entry is
//	    stale and refresh fails, the last known policy keeps applying
//	    ("stale enforce") and delivery is deferred rather than downgraded.
//
//	R4  Every policy carries a generation. A delivery records the
//	    generation it planned under and re-checks immediately before DATA,
//	    so a policy change cannot slip between "we checked" and "we sent".
//
//	R5  Authenticated upgrades are immediate; authenticated downgrades wait
//	    for expiry. The asymmetry is the point.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"gateway/internal/dnsx"
	"gateway/internal/model"
	"gateway/internal/sts"
)

// Options tunes the engine. Defaults are the conservative values; the lab
// builds engines with explicit options so tests are not clock-dependent.
type Options struct {
	// StabilizationWindow is how long a weaker, unauthenticated observation
	// must persist, unchanged, before it is accepted after the old policy
	// expires. Two consecutive identical observations at least this far
	// apart are required.
	StabilizationWindow time.Duration

	// StaleGrace is how long past ExpiresAt a domain with an enforcing
	// policy keeps being served (fail closed) while refresh keeps failing.
	// After it, delivery is still deferred, never downgraded; this only
	// controls when the report escalates from "degraded" to "blocked".
	StaleGrace time.Duration

	// StrictUnknown makes an unauthenticated "no policy" observation for a
	// domain we have never seen a policy for cause a hold instead of
	// opportunistic delivery. This is the only defence against an attacker
	// who is present before the first fetch; it costs deliverability to
	// every domain that genuinely publishes no policy, so it is opt-in.
	StrictUnknown bool

	// ProtectedDomains, when non-empty, applies StrictUnknown only to these
	// domains (and their subdomains). This is the practical middle ground.
	ProtectedDomains []string

	// RefreshAhead is how long before expiry we start trying to refresh in
	// the background.
	RefreshAhead time.Duration

	// MaxConcurrentFetch bounds concurrent policy fetches.
	MaxConcurrentFetch int

	// PolicyHostOverride is used only by the lab: it maps a domain to an
	// "ip:port" for the HTTPS policy fetch.
	PolicyHostOverride func(domain string) (string, bool)

	// MXPortOverride is used only by the lab: it maps an MX hostname to the
	// loopback port a simulated server listens on. Production leaves it nil
	// and port 25 is used.
	MXPortOverride func(host string) (int, bool)

	// TrustRoots is the CA pool for policy fetches, nil = system.
	TrustRoots []string

	// Now is injectable for tests.
	Now func() time.Time
}

func (o *Options) fill() {
	if o.StabilizationWindow == 0 {
		o.StabilizationWindow = 24 * time.Hour
	}
	if o.StaleGrace == 0 {
		o.StaleGrace = 7 * 24 * time.Hour
	}
	if o.RefreshAhead == 0 {
		o.RefreshAhead = time.Hour
	}
	if o.MaxConcurrentFetch == 0 {
		o.MaxConcurrentFetch = 16
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// Record is the persisted, per-domain state. It is the trust we carry across
// restarts and the baseline against which every new observation is judged.
type Record struct {
	Domain string `json:"domain"`

	// Last accepted policy.
	Mode       model.Mode                    `json:"mode"`
	Source     model.Source                  `json:"source"`
	MX         []string                      `json:"mx,omitempty"`
	MaxAge     int64                         `json:"max_age_seconds"`
	PolicyID   string                        `json:"policy_id,omitempty"`
	DNSSEC     model.DNSStatus               `json:"dnssec,omitempty"`
	TLSA       map[string][]model.TLSARecord `json:"tlsa,omitempty"`
	AcceptedAt time.Time                     `json:"accepted_at"`
	ExpiresAt  time.Time                     `json:"expires_at"`

	Generation uint64 `json:"generation"`

	// Candidate tracks a weaker unauthenticated observation that is waiting
	// to become stable enough to accept (R1).
	Candidate *Candidate `json:"candidate,omitempty"`
	// History is a bounded ring of accepted transitions, for the report.
	History []Transition `json:"history,omitempty"`
}

type Candidate struct {
	Mode   model.Mode   `json:"mode"`
	Source model.Source `json:"source"`
	MX     []string     `json:"mx,omitempty"`
	ID     string       `json:"id,omitempty"`
	First  time.Time    `json:"first_seen"`
	Last   time.Time    `json:"last_seen"`
	Count  int          `json:"count"`
}

// Transition is model.Transition; aliased so the engine's call sites read
// naturally.
type Transition = model.Transition

// Store persists Records. Implementations must be safe for concurrent use.
type Store interface {
	Load(domain string) (*Record, error)
	Save(rec *Record) error
}

// MemStore is an in-memory Store for tests.
type MemStore struct {
	mu   sync.Mutex
	recs map[string]*Record
}

func NewMemStore() *MemStore { return &MemStore{recs: map[string]*Record{}} }

func (m *MemStore) Load(d string) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.recs[d]
	if !ok {
		return nil, nil
	}
	cp := *r
	return &cp, nil
}

func (m *MemStore) Save(r *Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *r
	m.recs[r.Domain] = &cp
	return nil
}

// FileStore writes one JSON file per domain, atomically, under a directory.
type FileStore struct{ Dir string }

func (f *FileStore) path(d string) string {
	safe := strings.ReplaceAll(d, "/", "_")
	return filepath.Join(f.Dir, safe+".json")
}

func (f *FileStore) Load(d string) (*Record, error) {
	b, err := os.ReadFile(f.path(d))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("policy store %s: %w", d, err)
	}
	return &r, nil
}

func (f *FileStore) Save(r *Record) error {
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(f.Dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.path(r.Domain))
}

// MXHost is one resolved mail exchanger.
type MXHost struct {
	Host      string
	Pref      uint16
	Addrs     []string
	DNSSEC    model.DNSStatus
	FromCache bool
}

// Resolution is the engine's answer for one domain at one instant.
type Resolution struct {
	Domain   string
	Policy   *model.Policy
	MX       []model.MXHost
	MXStatus model.DNSStatus

	// Degraded means we are serving a policy we could not refresh, or a
	// policy that has outlived its MaxAge but is being kept under R3.
	Degraded bool
	// Blocked means the engine refuses to let this message be sent at all
	// (StrictUnknown hold, or policy unavailable after grace).
	Blocked bool
	// Err is a non-fatal explanation when Degraded or Blocked.
	Err error

	Evidence []model.Evidence
	// Observation describes the *current* lookup, which may be weaker than
	// the accepted policy. The report must be able to say "the policy in
	// force is enforce, but this refresh saw a bogus DNS answer" — those
	// are different facts and both matter.
	Observation Observation
	// History is the accepted policy transitions for this domain, oldest
	// first. The queue uses it to distinguish a legitimate withdrawal of
	// enforcement from a downgrade it should refuse to follow.
	History []model.Transition
}

// Observation is the DNS-level outcome of the latest policy lookup.
type Observation struct {
	// TXTStatus is the DNSSEC verdict on the _mta-sts TXT lookup.
	TXTStatus model.DNSStatus
	// TXTPresent is whether a syntactically valid record was returned.
	TXTPresent bool
	// DANEStatus is the DNSSEC verdict on the MX/TLSA lookups when DANE
	// was attempted.
	DANEStatus model.DNSStatus
	// FetchError is set when the policy file could not be fetched or parsed.
	FetchError string
	// Mode/ID are what this observation claimed, before the engine's
	// no-downgrade rules were applied.
	Mode model.Mode
	ID   string
}

// Engine is the policy engine. It is safe for concurrent use.
type Engine struct {
	Resolver *dnsx.Resolver
	Fetcher  *sts.Fetcher
	Store    Store
	Opts     Options

	sf      singleflight.Group
	mu      sync.Mutex
	cache   map[string]*cacheEntry
	mxCache map[string]mxEntry
	sem     chan struct{}

	fetchCount int
	fetchHook  func()
}

type cacheEntry struct {
	res       *Resolution
	nextCheck time.Time
}

func New(r *dnsx.Resolver, f *sts.Fetcher, st Store, o Options) *Engine {
	o.fill()
	return &Engine{
		Resolver: r,
		Fetcher:  f,
		Store:    st,
		Opts:     o,
		cache:    map[string]*cacheEntry{},
		mxCache:  map[string]mxEntry{},
		sem:      make(chan struct{}, o.MaxConcurrentFetch),
	}
}

func (e *Engine) now() time.Time { return e.Opts.Now() }

// SetFetchHook installs an observer that fires once per policy-file fetch.
// It exists for the lab's cache tests.
func (e *Engine) SetFetchHook(f func()) {
	e.mu.Lock()
	e.fetchHook = f
	e.mu.Unlock()
}

// ExpireForTest drops a domain's cache entry and stamps its stored policy as
// expired, so the next Resolve performs a full refresh. It is used by the
// lab; production code has no reason to call it.
func (e *Engine) ExpireForTest(domain string) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	e.mu.Lock()
	delete(e.cache, domain)
	delete(e.mxCache, domain)
	e.mu.Unlock()
	if rec, err := e.Store.Load(domain); err == nil && rec != nil {
		rec.ExpiresAt = e.now().Add(-time.Second)
		e.Store.Save(rec)
	}
}

// RefreshForTest drops a domain's cache entry without expiring its stored
// policy, forcing the next Resolve to re-observe while the policy's
// lifetime is still running. That is the "policy changed early" case, which
// is what distinguishes an authenticated downgrade (waits for expiry) from
// a routine refresh.
func (e *Engine) RefreshForTest(domain string) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	e.mu.Lock()
	delete(e.cache, domain)
	e.mu.Unlock()
}

// InjectWeakPolicyForTest plants a downgraded resolution directly in the
// cache, bypassing the no-downgrade rules, so that the pre-DATA gate can be
// tested in isolation. It is a lab affordance and must never be reachable
// from production code paths.
func (e *Engine) InjectWeakPolicyForTest(domain string) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	e.mu.Lock()
	defer e.mu.Unlock()
	ce := e.cache[domain]
	if ce == nil || ce.res == nil || ce.res.Policy == nil {
		return
	}
	p := *ce.res.Policy
	p.Mode = model.ModeTesting
	p.Generation++
	ce.res = &Resolution{
		Domain:   ce.res.Domain,
		Policy:   &p,
		MX:       ce.res.MX,
		MXStatus: ce.res.MXStatus,
		History:  ce.res.History,
	}
}

// SetMXPortOverride installs the lab's port mapping after construction.
func (e *Engine) SetMXPortOverride(f func(string) (int, bool)) { e.Opts.MXPortOverride = f }

// Resolve returns the effective policy for domain, refreshing if needed.
// Concurrent callers for the same domain share one refresh.
func (e *Engine) Resolve(ctx context.Context, domain string) (*Resolution, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	e.mu.Lock()
	if ce, ok := e.cache[domain]; ok && e.now().Before(ce.nextCheck) {
		cp := *ce.res
		e.mu.Unlock()
		return &cp, nil
	}
	e.mu.Unlock()

	v, err, _ := e.sf.Do(domain, func() (any, error) {
		// Re-check after winning the singleflight in case someone else
		// refreshed while we queued.
		e.mu.Lock()
		if ce, ok := e.cache[domain]; ok && e.now().Before(ce.nextCheck) {
			cp := *ce.res
			e.mu.Unlock()
			return &cp, nil
		}
		e.mu.Unlock()
		return e.refresh(ctx, domain)
	})
	if err != nil {
		return nil, err
	}
	return v.(*Resolution), nil
}

// Peek returns the current cached resolution without refreshing. It is used
// by the pre-DATA generation check: a nil result means "not cached", which
// the caller treats as "must resolve".
func (e *Engine) Peek(domain string) *Resolution {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	e.mu.Lock()
	defer e.mu.Unlock()
	if ce, ok := e.cache[domain]; ok {
		cp := *ce.res
		return &cp
	}
	return nil
}

type observation struct {
	mode    model.Mode
	source  model.Source
	mx      []string
	maxAge  time.Duration
	id      string
	dnssec  model.DNSStatus
	tlsa    map[string][]model.TLSARecord
	present bool
	// refreshFailed marks an observation that could not be completed: the
	// record exists but the policy file was unreachable, or the lookup
	// itself errored. A failed refresh must never renew a policy's
	// lifetime, because "we could not check" is not "it is still good".
	refreshFailed bool
	// daneStatus is the DNSSEC verdict of the DANE lookups when they were
	// attempted and did not yield a policy (for example because the TLSA
	// answer was bogus).
	daneStatus model.DNSStatus
	// authd says whether the observation itself is authenticated
	// (DNSSEC-secure DNS plus an HTTPS-authenticated policy file).
	authd    bool
	err      error
	evidence []model.Evidence
}

func (e *Engine) refresh(ctx context.Context, domain string) (*Resolution, error) {
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	now := e.now()
	rec, err := e.Store.Load(domain)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		rec = &Record{Domain: domain}
	}

	obs := e.observe(ctx, domain, rec, now)
	resObs := Observation{
		TXTStatus: obs.dnssec, TXTPresent: obs.present,
		DANEStatus: obs.daneStatus,
		FetchError: fetchErrOf(obs), Mode: obs.mode, ID: obs.id,
	}

	changed, reason := decide(rec, obs, now, e.Opts)
	res := &Resolution{Domain: domain, Evidence: obs.evidence, Observation: resObs}
	if changed {
		// A generation bump means "the rules a delivery was planned under
		// may no longer hold". Extending the lifetime of an unchanged
		// policy is not material: it must not cancel queued mail.
		material := reason != "policy_refresh_identity"
		if material {
			rec.Generation++
		}
		if reason != "policy_refresh_identity" || rec.Mode != obs.mode {
			rec.History = append(rec.History, Transition{
				At: now, From: rec.Mode, To: obs.mode, Source: obs.source,
				Reason: reason, Gen: rec.Generation, DNSSEC: obs.dnssec,
			})
			if len(rec.History) > 32 {
				rec.History = rec.History[len(rec.History)-32:]
			}
		}
		rec.Mode, rec.Source = obs.mode, obs.source
		rec.MX, rec.MaxAge = obs.mx, int64(obs.maxAge/time.Second)
		rec.PolicyID, rec.DNSSEC, rec.TLSA = obs.id, obs.dnssec, obs.tlsa
		rec.AcceptedAt = now
		switch {
		case obs.maxAge > 0:
			rec.ExpiresAt = now.Add(obs.maxAge)
		case obs.present || obs.authd:
			// An authenticated "no policy" is a real answer and must be
			// cached, or every message to a domain that publishes nothing
			// re-resolves and re-fetches. Use a short window: absence is
			// cheap to re-confirm but expensive to get wrong.
			rec.ExpiresAt = now.Add(noPolicyCacheTTL)
		default:
			// Unauthenticated absence: do not extend. A domain whose
			// policy we cannot authenticate gets re-checked on the normal
			// cache cadence, and an enforcer that already holds a policy
			// keeps its own expiry.
			if rec.ExpiresAt.IsZero() {
				rec.ExpiresAt = now.Add(noPolicyCacheTTL)
			}
		}
		if reason != "policy_refresh_identity" {
			res.Evidence = append(res.Evidence, model.Ev("policy_changed", reason))
		}
	}
	if !changed && obs.err != nil {
		res.Evidence = append(res.Evidence, model.Ev("refresh_failed", obs.err.Error()))
	}

	// Decide what to serve.
	expired := !now.Before(rec.ExpiresAt)
	stale := expired && rec.Mode != model.ModeNone
	switch {
	case rec.Mode == model.ModeNone && rec.ExpiresAt.IsZero() && rec.PolicyID == "" && rec.AcceptedAt.IsZero():
		// Never successfully observed policy, and the current observation
		// is an unauthenticated absence.
		if e.strictFor(domain) && !obs.authd {
			res.Blocked = true
			res.Err = errStrictUnknown
			res.Evidence = append(res.Evidence, model.Ev("strict_unknown_hold", domain))
		}
	case stale:
		res.Degraded = true
		if now.Sub(rec.ExpiresAt) > e.Opts.StaleGrace {
			res.Blocked = true
			res.Evidence = append(res.Evidence, model.Ev("policy_stale_beyond_grace", ""))
		}
		if obs.err != nil {
			res.Err = obs.err
		}
	}

	res.History = rec.History
	res.Policy = &model.Policy{
		Domain:     domain,
		Mode:       rec.Mode,
		Source:     rec.Source,
		MX:         append([]string(nil), rec.MX...),
		MaxAge:     time.Duration(rec.MaxAge) * time.Second,
		PolicyID:   rec.PolicyID,
		DNSSEC:     rec.DNSSEC,
		TLSA:       rec.TLSA,
		TLSAAll:    flattenTLSA(rec.TLSA),
		FetchedAt:  rec.AcceptedAt,
		ExpiresAt:  rec.ExpiresAt,
		Generation: rec.Generation,
		Evidence:   res.Evidence,
	}

	// Resolve MX now, at policy time, so that the SMTP client never has to
	// re-resolve: re-resolving at connect time is a downgrade window.
	mx, mxStatus := e.resolveMXCached(ctx, domain)
	res.MX, res.MXStatus = mx, mxStatus
	if rec.Mode == model.ModeNone && len(mx) == 0 {
		res.Evidence = append(res.Evidence, model.Ev("no_mx", ""))
	}

	if err := e.Store.Save(rec); err != nil {
		res.Evidence = append(res.Evidence, model.Ev("store_error", err.Error()))
	}

	ttl := rec.ExpiresAt.Sub(now) - e.Opts.RefreshAhead
	if ttl < time.Minute {
		ttl = time.Minute
	}
	if ttl > 6*time.Hour {
		ttl = 6 * time.Hour
	}
	e.mu.Lock()
	e.cache[domain] = &cacheEntry{res: res, nextCheck: now.Add(ttl)}
	e.mu.Unlock()
	return res, nil
}

var errStrictUnknown = errors.New("policy: no authenticated policy and strict unknown mode is on")

// noPolicyCacheTTL is how long an authenticated "this domain publishes no
// policy" result is reused. It bounds both DNS and HTTPS load for the large
// minority of domains that publish nothing.
const noPolicyCacheTTL = 10 * time.Minute

func (e *Engine) strictFor(domain string) bool {
	if e.Opts.StrictUnknown {
		return true
	}
	for _, d := range e.Opts.ProtectedDomains {
		d = strings.ToLower(d)
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

// decide applies rules R1/R2/R5. It returns whether to adopt the observation
// and a reason string for the audit trail.
func decide(rec *Record, obs observation, now time.Time, o Options) (bool, string) {
	// A failed refresh never changes the policy, and in particular never
	// extends its lifetime. Extending on failure would let an attacker who
	// can black-hole the policy host keep a stale policy alive forever, and
	// would hide a genuine outage behind a healthy-looking cache.
	if obs.refreshFailed {
		return false, "refresh_failed"
	}

	// First successful observation: TOFU.
	if rec.AcceptedAt.IsZero() {
		if obs.err != nil && !obs.present {
			return false, "unavailable"
		}
		return true, "first_observation"
	}

	expired := !now.Before(rec.ExpiresAt)

	switch {
	case obs.mode > rec.Mode:
		// R5: authenticated or not, an upgrade is safe to take. The only
		// thing an attacker can do with an upgrade is make us stricter.
		return true, "upgrade"

	case obs.mode == rec.Mode && obs.source == rec.Source:
		// Same posture. Renewing the lifetime of an identical policy is
		// not a material change and must not bump the generation; a
		// changed MX set or policy id is.
		if obs.id != rec.PolicyID || !equalStrings(obs.mx, rec.MX) || !equalTLSA(obs.tlsa, rec.TLSA) {
			return true, "policy_refresh_changed"
		}
		return true, "policy_refresh_identity"

	case obs.mode == rec.Mode && obs.source != rec.Source:
		// e.g. STS to DANE with same mode. Prefer DANE; it is DNSSEC
		// authenticated.
		if obs.source == model.SourceDANE {
			return true, "source_upgrade"
		}
		return false, "source_downgrade"

	case obs.authd:
		// R5: an authenticated downgrade is legitimate, but sticky until
		// the old policy expires so a freshly signed-but-rolled-back zone
		// cannot pull protection out from under queued mail.
		if !expired {
			return false, "authenticated_downgrade_waiting_expiry"
		}
		return true, "authenticated_downgrade"

	default:
		// R1/R2: unauthenticated downgrade. Requires two identical
		// observations spanning the stabilization window, and only after
		// expiry.
		if !expired {
			return false, "downgrade_rejected_policy_valid"
		}
		c := rec.Candidate
		if c == nil || c.Mode != obs.mode || c.ID != obs.id || !equalStrings(c.MX, obs.mx) {
			rec.Candidate = &Candidate{
				Mode: obs.mode, Source: obs.source, MX: obs.mx, ID: obs.id,
				First: now, Last: now, Count: 1,
			}
			return false, "downgrade_stabilizing"
		}
		c.Last = now
		c.Count++
		if c.Last.Sub(c.First) >= o.StabilizationWindow {
			rec.Candidate = nil
			return true, "downgrade_stabilized"
		}
		return false, "downgrade_stabilizing"
	}
}

// fetchErrOf reports the policy-file fetch error, if the observation
// carried one. Absence is not a fetch error.
func fetchErrOf(o observation) string {
	if o.err == nil || !o.present {
		return ""
	}
	if o.source == model.SourceDANE {
		return ""
	}
	return o.err.Error()
}

func equalTLSA(a, b map[string][]model.TLSARecord) bool {
	if len(a) != len(b) {
		return false
	}
	for h, ra := range a {
		rb, ok := b[h]
		if !ok || len(ra) != len(rb) {
			return false
		}
		for i := range ra {
			if ra[i].Usage != rb[i].Usage || ra[i].Selector != rb[i].Selector ||
				ra[i].MatchingType != rb[i].MatchingType ||
				!bytes.Equal(ra[i].Data, rb[i].Data) {
				return false
			}
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if !strings.EqualFold(aa[i], bb[i]) {
			return false
		}
	}
	return true
}

// observe gathers DANE and MTA-STS policy for a domain.
func (e *Engine) observe(ctx context.Context, domain string, rec *Record, now time.Time) observation {
	var ev []model.Evidence

	// 1. DANE, if the MX and TLSA sets are DNSSEC secure.
	daneObs, daneOK := e.observeDANE(ctx, domain, now, &ev)
	if daneOK {
		daneObs.evidence = ev
		daneObs.daneStatus = model.DNSSecure
		return daneObs
	}

	// 2. MTA-STS.
	txt, txtErr := sts.LookupTXT(ctx, e.Resolver, domain)
	if txtErr != nil && txt.Status != model.DNSSecure {
		ev = append(ev, model.Ev("sts_txt_error", txtErr.Error()))
	}

	if !txt.Present {
		obs := observation{
			mode:    model.ModeNone,
			source:  model.SourceNone,
			dnssec:  txt.Status,
			present: false,
			authd:   txt.Status == model.DNSSecure,
		}
		if txt.Status == model.DNSSecure {
			ev = append(ev, model.Ev("sts_absent_authenticated", domain))
		} else {
			ev = append(ev, model.Ev("sts_absent_unauthenticated", string(txt.Status)))
			obs.err = errors.New("no authenticated policy record")
			// A lookup that errored or failed validation is a failed
			// refresh, not an authenticated statement of absence. It must
			// not extend the lifetime of a policy we already hold.
			if txtErr != nil {
				obs.refreshFailed = true
			}
		}
		obs.evidence = ev
		return obs
	}

	// Record exists. Fetch the file. Fetching or parsing failing is
	// different from absence: never treat it as a downgrade, keep serving
	// the previous policy (R3).
	pf, ferr := e.fetchPolicy(ctx, domain)
	if ferr != nil {
		ev = append(ev, model.Ev("sts_fetch_failed", ferr.Error()))
		obs := observation{
			mode: rec.Mode, source: rec.Source, mx: rec.MX,
			maxAge: time.Duration(rec.MaxAge) * time.Second,
			id:     rec.PolicyID, dnssec: txt.Status, present: true,
			authd:         false,
			err:           ferr,
			evidence:      ev,
			refreshFailed: true,
		}
		// A failed refresh of an enforcing policy must not change it.
		return obs
	}

	obs := observation{
		mode:    pf.Mode,
		source:  model.SourceMTASTS,
		mx:      pf.MX,
		maxAge:  pf.MaxAge,
		id:      txt.ID,
		dnssec:  txt.Status,
		present: true,
		// The file itself is authentic when the HTTPS fetch verified a
		// certificate for mta-sts.<domain>. We only treat the *change* as
		// authenticated when DNS also validated, because the id and the
		// existence of the record are DNS facts.
		authd: txt.Status == model.DNSSecure,
	}
	if txt.ID != rec.PolicyID && rec.PolicyID != "" {
		ev = append(ev, model.Ev("policy_id_changed", rec.PolicyID+" -> "+txt.ID))
	}
	if pf.Mode < rec.Mode {
		ev = append(ev, model.Ev("mode_downgrade_observed", rec.Mode.String()+" -> "+pf.Mode.String()))
	}
	obs.evidence = ev
	return obs
}

func (e *Engine) fetchPolicy(ctx context.Context, domain string) (*sts.PolicyFile, error) {
	if e.Fetcher == nil {
		return nil, errors.New("policy: no policy fetcher configured")
	}
	f := *e.Fetcher
	if e.Opts.PolicyHostOverride != nil {
		if addr, ok := e.Opts.PolicyHostOverride(domain); ok {
			f.Dial = func(context.Context, string) (string, error) { return addr, nil }
		}
	}
	e.mu.Lock()
	e.fetchCount++
	hook := e.fetchHook
	e.mu.Unlock()
	if hook != nil {
		hook()
	}
	return f.Fetch(ctx, domain)
}

// observeDANE returns a DANE policy when the MX set and TLSA sets are secure.
func (e *Engine) observeDANE(ctx context.Context, domain string, now time.Time, ev *[]model.Evidence) (observation, bool) {
	mxRes := e.Resolver.Lookup(ctx, domain, dns.TypeMX)
	if mxRes.Status != model.DNSSecure || !mxRes.Exists {
		if mxRes.Status == model.DNSBogus {
			*ev = append(*ev, model.Ev("dane_mx_bogus", domain))
		}
		return observation{daneStatus: mxRes.Status}, false
	}
	var hosts []string
	for _, rr := range mxRes.Records {
		if mx, ok := rr.(*dns.MX); ok {
			hosts = append(hosts, strings.ToLower(strings.TrimSuffix(mx.Mx, ".")))
		}
	}
	byHost := map[string][]model.TLSARecord{}
	anySecure := false
	minTTL := time.Hour
	for _, h := range hosts {
		name := fmt.Sprintf("_25._tcp.%s", h)
		res := e.Resolver.Lookup(ctx, name, dns.TypeTLSA)
		if res.Status == model.DNSBogus {
			*ev = append(*ev, model.Ev("dane_tlsa_bogus", h))
			// A signed zone whose TLSA answer does not validate is the
			// strongest single DNS signal there is. Report it and do not
			// fall back to a weaker policy mechanism for this domain.
			return observation{daneStatus: model.DNSBogus}, false
		}
		if res.Status != model.DNSSecure || !res.Exists {
			continue
		}
		anySecure = true
		for _, rr := range res.Records {
			t, ok := rr.(*dns.TLSA)
			if !ok {
				continue
			}
			data, err := hexDecode(t.Certificate)
			if err != nil {
				*ev = append(*ev, model.Ev("dane_tlsa_bad_hex", h))
				continue
			}
			byHost[h] = append(byHost[h], model.TLSARecord{
				Usage: t.Usage, Selector: t.Selector, MatchingType: t.MatchingType,
				Data: data, TTL: time.Duration(t.Hdr.Ttl) * time.Second,
			})
			if ttl := time.Duration(t.Hdr.Ttl) * time.Second; ttl > 0 && ttl < minTTL {
				minTTL = ttl
			}
		}
	}
	if !anySecure || len(byHost) == 0 {
		return observation{daneStatus: model.DNSInsecure}, false
	}
	// RFC 7672 section 2.2: when at least one MX publishes TLSA, hosts that
	// do not publish it are not eligible for DANE delivery. Record only the
	// eligible set.
	n := 0
	for _, v := range byHost {
		n += len(v)
	}
	*ev = append(*ev, model.Ev("dane_policy", fmt.Sprintf("%d TLSA records across %d MX", n, len(byHost))))
	lifetime := minTTL
	if lifetime < 5*time.Minute {
		lifetime = 5 * time.Minute
	}
	if lifetime > 24*time.Hour {
		lifetime = 24 * time.Hour
	}
	return observation{
		mode:    model.ModeEnforce,
		source:  model.SourceDANE,
		mx:      nil, // DANE does not constrain the MX set
		maxAge:  lifetime,
		id:      "dane",
		dnssec:  model.DNSSecure,
		tlsa:    byHost,
		present: true,
		authd:   true,
	}, true
}

func flattenTLSA(m map[string][]model.TLSARecord) []model.TLSARecord {
	var out []model.TLSARecord
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, m[k]...)
	}
	return out
}

func hexDecode(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, err := hexVal(s[2*i])
		if err != nil {
			return nil, err
		}
		lo, err := hexVal(s[2*i+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	if len(s)%2 != 0 {
		return nil, errors.New("odd hex length")
	}
	return out, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("bad hex %q", c)
}

// resolveMXCached memoizes MX resolution per domain for a few minutes. Many
// recipient domains share MX hosts (a partner's tenants, an outsourced mail
// provider), so without this a large fan-out turns into one address lookup
// per domain per send.
func (e *Engine) resolveMXCached(ctx context.Context, domain string) ([]model.MXHost, model.DNSStatus) {
	e.mu.Lock()
	if m, ok := e.mxCache[domain]; ok && e.now().Before(m.until) {
		hosts := append([]model.MXHost(nil), m.hosts...)
		status := m.status
		e.mu.Unlock()
		return hosts, status
	}
	e.mu.Unlock()
	hosts, status := e.resolveMX(ctx, domain)
	e.mu.Lock()
	e.mxCache[domain] = mxEntry{hosts: hosts, status: status, until: e.now().Add(mxCacheTTL)}
	e.mu.Unlock()
	return hosts, status
}

type mxEntry struct {
	hosts  []model.MXHost
	status model.DNSStatus
	until  time.Time
}

// mxCacheTTL bounds how stale an MX list may be. It is deliberately shorter
// than the policy lifetime: MX changes are more common than policy changes,
// and a stale address list is a deliverability problem rather than a
// security one, because the certificate and policy checks still apply.
const mxCacheTTL = 5 * time.Minute

// resolveMX resolves and validates the MX RRset, then A/AAAA for each host.
func (e *Engine) resolveMX(ctx context.Context, domain string) ([]model.MXHost, model.DNSStatus) {
	res := e.Resolver.Lookup(ctx, domain, dns.TypeMX)
	status := res.Status
	if res.Err != nil && res.Status != model.DNSSecure {
		return nil, status
	}
	if !res.Exists {
		// RFC 5321 implicit MX: the domain itself.
		ips, st, err := e.Resolver.Addr(ctx, domain)
		if err != nil {
			return nil, worse(status, st)
		}
		return []model.MXHost{{Host: domain, Pref: 0, Addrs: ipStrings(ips), DNSSEC: st, Source: "dns"}}, worse(status, st)
	}
	var hosts []model.MXHost
	for _, rr := range res.Records {
		mx, ok := rr.(*dns.MX)
		if !ok {
			continue
		}
		h := strings.ToLower(strings.TrimSuffix(mx.Mx, "."))
		if h == "" {
			continue
		}
		// RFC 7505 null MX: the domain accepts no mail. Represent it and
		// let the client reject permanently rather than falling back.
		ips, st, err := e.Resolver.Addr(ctx, h)
		if err != nil {
			hosts = append(hosts, model.MXHost{Host: h, Pref: mx.Preference, DNSSEC: st, Source: "dns"})
			continue
		}
		hosts = append(hosts, model.MXHost{
			Host: h, Pref: mx.Preference, Addrs: ipStrings(ips),
			DNSSEC: worse(res.Status, st), Source: "dns",
		})
	}
	if e.Opts.MXPortOverride != nil {
		for i := range hosts {
			if port, ok := e.Opts.MXPortOverride(hosts[i].Host); ok {
				hosts[i].Port = port
			}
		}
	}
	sort.SliceStable(hosts, func(i, j int) bool {
		if hosts[i].Pref != hosts[j].Pref {
			return hosts[i].Pref < hosts[j].Pref
		}
		return hosts[i].Host < hosts[j].Host
	})
	return hosts, status
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

func worse(a, b model.DNSStatus) model.DNSStatus {
	rank := map[model.DNSStatus]int{
		model.DNSSecure: 0, model.DNSInsecure: 1, model.DNSBogus: 2, model.DNSIndeterminate: 3,
	}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
