// Package queue is the delivery queue and the policy-change gate.
//
// The queue exists to answer one question precisely: when a policy changes
// while mail is waiting, what happens to the mail?
//
// The rule is that a message is never sent under rules weaker than the ones
// that were in force when it was enqueued, and never sent under rules
// *stronger* than the ones in force now in a way that silently drops it. So:
//
//   - A message enqueued under enforce is never sent in cleartext, even if
//     the policy later drops to testing. It waits for TLS; if the domain
//     genuinely withdrew enforce, the transition is authenticated or
//     stabilised, and the message is *released* rather than silently
//     downgraded: the release is recorded, and the sender can be notified.
//
//   - A message enqueued under testing is re-planned when the domain
//     upgrades to enforce. It is not sent opportunistically in the window
//     between the policy change and the queue noticing.
//
//   - The pre-DATA check compares the policy generation the attempt was
//     planned under with the live generation. A change aborts before the
//     envelope, not after it: MID-Transfer downgrade is impossible because
//     the decision point is before MAIL FROM and re-checked before DATA.
package queue

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gateway/internal/classify"
	"gateway/internal/model"
	"gateway/internal/policy"
	"gateway/internal/smtpc"
)

// Entry is one queued message.
type Entry struct {
	ID       string
	Domain   string
	From     string
	To       []string
	Body     []byte
	Enqueued time.Time

	// PlannedGeneration and PlannedMode capture the policy the message was
	// accepted into the queue under. They never change for the life of the
	// entry; that is what makes "no downgrade" checkable.
	PlannedGeneration uint64
	PlannedMode       model.Mode

	Attempts int
	NextTry  time.Time
	LastErr  string
	// Held explains why the entry is not being sent.
	Hold string
	// Released records a deliberate, logged relaxation.
	Released bool
}

// Dispatcher is the policy engine as the queue needs it. It is an interface
// so the queue can be tested without DNS.
type Dispatcher interface {
	Resolve(ctx context.Context, domain string) (*policy.Resolution, error)
	Peek(domain string) *policy.Resolution
}

// Sender is the SMTP client as the queue needs it.
type Sender interface {
	Send(ctx context.Context, mx model.MXHost, msg *smtpc.Message) *smtpc.SendResult
}

// Store persists entries. The gateway ships with a memory store and a JSON
// directory store; a real deployment would use a database.
type Store interface {
	Put(*Entry) error
	Delete(id string) error
	List() ([]*Entry, error)
}

type MemStore struct {
	mu   sync.Mutex
	byID map[string]*Entry
}

func NewMemStore() *MemStore { return &MemStore{byID: map[string]*Entry{}} }

func (m *MemStore) Put(e *Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *e
	cp.To = append([]string(nil), e.To...)
	cp.Body = append([]byte(nil), e.Body...)
	m.byID[e.ID] = &cp
	return nil
}

func (m *MemStore) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, id)
	return nil
}

func (m *MemStore) List() ([]*Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Entry, 0, len(m.byID))
	for _, e := range m.byID {
		cp := *e
		cp.To = append([]string(nil), e.To...)
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Report is what the queue produces for one delivery attempt cycle.
type Report struct {
	Domain  string
	Entry   *Entry
	Verdict classify.Verdict
	// CleartextNotPermitted is the invariant check: true means the queue
	// would have sent in cleartext despite an enforcing plan and refused.
	CleartextRefused bool
	// CleartextSent is set only when the plan was non-enforcing and the
	// policy in force at send time also allowed it.
	CleartextSent bool
	// Released is set when a message enqueued under enforce was sent in
	// cleartext because the domain withdrew enforcement through a
	// sanctioned, authenticated transition.
	Released bool

	// Policy is the effective policy at the time of this attempt, and
	// Observation is what the lookup that produced it actually saw. Both
	// are copied so a report built after the attempt still reflects what
	// the decision was made on.
	Policy      *model.Policy
	Observation policy.Observation
	History     []model.Transition
	// Attempts is every connection tried for this entry in this cycle.
	Attempts []model.Attempt
	// Delivered records the successful attempt, if any.
	Delivered bool
}

// Enqueue accepts a message into the queue under the policy currently in
// force. Stamping the plan here is what makes the no-downgrade guarantee
// meaningful: the plan records what we promised the sender when we took
// responsibility for the message.
func (w *Worker) Enqueue(ctx context.Context, e *Entry) error {
	res, err := w.Engine.Resolve(ctx, e.Domain)
	if err != nil {
		return err
	}
	if e.ID == "" {
		e.ID = fmt.Sprintf("%s/%d", e.Domain, w.now().UnixNano())
	}
	e.Enqueued = w.now()
	e.PlannedMode = res.Policy.Mode
	e.PlannedGeneration = res.Policy.Generation
	if res.Policy.Mode == model.ModeNone {
		// Nothing was promised; opportunistic delivery is allowed.
		e.PlannedMode = model.ModeNone
	}
	if res.Blocked {
		e.Hold = "policy blocked at enqueue: " + reasonOf(res)
	}
	return w.Store.Put(e)
}

// Worker drains the queue.
type Worker struct {
	Engine Dispatcher
	Client Sender
	Store  Store
	// MaxParallel bounds concurrent deliveries per run.
	MaxParallel int
	// Now is injectable.
	Now func() time.Time
	// ClassifyHistory supplies per-host history to the classifier.
	History func(mx string) classify.HostHistory
	// SharedFailures supplies cross-domain failure counts.
	SharedFailures func(mx string) int
	// OnAttempt observes every attempt, for tests and the report.
	OnAttempt func(Report)

	mu       sync.Mutex
	lastPlan map[string]plan
}

type plan struct {
	mode   model.Mode
	gen    uint64
	mx     []model.MXHost
	policy *model.Policy
	hist   []model.Transition
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// RunOnce processes every due entry once and returns the reports.
func (w *Worker) RunOnce(ctx context.Context) ([]Report, error) {
	entries, err := w.Store.List()
	if err != nil {
		return nil, err
	}
	var reports []Report
	for _, e := range entries {
		if w.now().Before(e.NextTry) {
			continue
		}
		r, err := w.deliver(ctx, e)
		if err != nil {
			return reports, err
		}
		reports = append(reports, r...)
	}
	return reports, nil
}

// deliver runs one entry to completion or deferral.
func (w *Worker) deliver(ctx context.Context, e *Entry) ([]Report, error) {
	res, err := w.Engine.Resolve(ctx, e.Domain)
	if err != nil {
		e.LastErr = err.Error()
		e.NextTry = w.now().Add(time.Minute)
		w.Store.Put(e)
		return nil, nil
	}
	if res.Blocked {
		e.Hold = "policy blocked: " + reasonOf(res)
		e.LastErr = e.Hold
		e.NextTry = w.now().Add(15 * time.Minute)
		w.Store.Put(e)
		return []Report{{
			Domain: e.Domain, Entry: e, CleartextRefused: true,
			Verdict: classify.Verdict{
				Fault: model.FaultPolicyUnavailable, Confidence: 0.9,
				Explanation: e.Hold, Retry: true, Escalate: true,
				Signals: res.Evidence,
			},
		}}, nil
	}

	// No-downgrade gate: the plan the entry was accepted under may have
	// been stricter than the policy is now.
	effMode := res.Policy.Mode
	released := false
	if e.PlannedMode == model.ModeEnforce && effMode < model.ModeEnforce {
		// Only a *sanctioned* relaxation lets this message out. A
		// relaxation is sanctioned when the policy engine accepted it via
		// an authenticated change or a stabilised unauthenticated one, and
		// the resulting state is currently in force.
		if !sanctionedRelaxation(res.History) {
			e.Hold = "policy relaxed without a sanctioned transition; holding at the enqueue-time policy"
			e.NextTry = w.now().Add(15 * time.Minute)
			w.Store.Put(e)
			return []Report{{
				Domain: e.Domain, Entry: e, CleartextRefused: true,
				Verdict: classify.Verdict{
					Fault: model.FaultPolicyDowngrade, Confidence: 0.8,
					Explanation: e.Hold, Retry: true, Escalate: true,
					Signals: res.Evidence,
				},
			}}, nil
		}
		released = true
	}
	if released && effMode < model.ModeEnforce {
		// Deliberate, logged relaxation. This is the only path in the whole
		// gateway where a message enqueued under enforce can be sent
		// without TLS.
	}

	// needTLS is true unless the enqueue-time promise has been *released*
	// by a sanctioned, authenticated withdrawal of enforcement. A release
	// is the only path from an enforcing plan to a cleartext send.
	needTLS := effMode == model.ModeEnforce || (e.PlannedMode == model.ModeEnforce && !released)

	// Pick candidate hosts under the current policy.
	hosts := candidateHosts(res)
	if len(hosts) == 0 {
		e.Attempts++
		e.Hold = "no MX host permitted by the current policy"
		e.LastErr = e.Hold
		e.NextTry = w.now().Add(15 * time.Minute)
		w.Store.Put(e)
		return []Report{{
			Domain: e.Domain, Entry: e, CleartextRefused: needTLS,
			Policy: res.Policy, Observation: res.Observation, History: res.History,
			Verdict: classify.Verdict{
				Fault: model.FaultPolicyUnavailable, Confidence: 0.7, Retry: true,
				Explanation: e.Hold, Signals: res.Evidence,
			},
		}}, nil
	}

	var attempts []model.Attempt
	var delivered *smtpc.SendResult
	for _, h := range hosts {
		if len(h.Addrs) == 0 {
			continue
		}
		// Re-check the policy immediately before the connection, and again
		// the client re-checks before DATA. If the engine has nothing
		// cached, refresh rather than proceed on the resolution we started
		// with: an absent entry is not evidence that nothing changed.
		live := w.Engine.Peek(e.Domain)
		if live == nil {
			if fresh, ferr := w.Engine.Resolve(ctx, e.Domain); ferr == nil {
				live = fresh
			}
		}
		if live != nil && live.Policy != nil && e.PlannedMode == model.ModeEnforce &&
			live.Policy.Mode < model.ModeEnforce && !sanctionedRelaxation(live.History) {
			e.Hold = "policy changed to a weaker mode during delivery planning"
			e.NextTry = w.now().Add(15 * time.Minute)
			w.Store.Put(e)
			return []Report{{Domain: e.Domain, Entry: e, CleartextRefused: true,
				Policy: res.Policy, Observation: res.Observation, History: res.History,
				Verdict: classify.Verdict{Fault: model.FaultPolicyDowngrade, Confidence: 0.85,
					Explanation: e.Hold, Retry: true, Escalate: true}}}, nil
		}

		plannedHost := h
		plannedPolicy := res.Policy
		msg := &smtpc.Message{
			From: e.From, To: e.To, Body: e.Body,
			RequireTLS:     needTLS,
			PolicyMX:       res.Policy.MX,
			TLSA:           res.Policy.TLSA,
			MXDNSSECStatus: res.MXStatus,
			BeforeDATA: func() error {
				// Last-moment check: the policy may have changed while
				// the connection was open. Nothing has been transmitted
				// yet, so aborting here costs a retry and nothing else.
				return w.recheckBeforeDATA(ctx, e, plannedPolicy, plannedHost)
			},
		}
		// If the host is not in the policy's DANE set, drop the TLSA map so
		// the client does not attempt a DANE check that cannot pass.
		if len(res.Policy.TLSA) > 0 {
			if _, ok := res.Policy.TLSA[h.Host]; !ok {
				// Not DANE-eligible under RFC 7672 when other hosts are.
				if res.Policy.Source == model.SourceDANE {
					continue
				}
				msg.TLSA = nil
			}
		}
		sr := w.Client.Send(ctx, h, msg)
		attempts = append(attempts, sr.Attempt)
		if sr.Delivered {
			delivered = sr
			break
		}
	}

	rep := w.finishCycle(ctx, e, res, hosts, attempts, delivered, needTLS, released)
	if w.OnAttempt != nil {
		w.OnAttempt(rep)
	}
	return []Report{rep}, nil
}

// finishCycle classifies one delivery cycle and updates the entry.
//
// It produces exactly one Report per message per cycle, listing every
// attempt. Reporting per attempt instead would make one message that tried
// three MX hosts look like three failures, which is precisely the kind of
// miscount that makes an operator distrust the report.
func (w *Worker) finishCycle(ctx context.Context, e *Entry, res *policy.Resolution,
	hosts []model.MXHost, attempts []model.Attempt, delivered *smtpc.SendResult,
	needTLS, released bool) Report {

	in := classify.Input{
		Domain:   e.Domain,
		Policy:   res.Policy,
		Attempts: attempts,
		MXSet:    res.MX,
		PolicyObs: classify.PolicyObservation{
			TXTStatus:        res.Observation.TXTStatus,
			TXTPresent:       res.Observation.TXTPresent,
			DANEStatus:       res.Observation.DANEStatus,
			FetchError:       res.Observation.FetchError,
			PreviouslySecure: res.Policy.DNSSEC == model.DNSSecure,
		},
		Now: w.now(),
	}
	if w.History != nil || len(attempts) > 0 {
		in.History = map[string]classify.HostHistory{}
		for _, a := range attempts {
			if w.History != nil {
				in.History[a.MX] = w.History(a.MX)
			}
		}
	}
	if w.SharedFailures != nil {
		in.SharedHostFailures = map[string]int{}
		for _, a := range attempts {
			in.SharedHostFailures[a.MX] = w.SharedFailures(a.MX)
		}
	}
	v := classify.Classify(in)
	if released {
		// Make the deliberate relaxation an explicit, greppable event. A
		// released message must never be indistinguishable in the report
		// from an ordinary cleartext delivery.
		v.Signals = append(v.Signals, model.Evidence{
			Code: "enforce_released",
			Detail: fmt.Sprintf("enqueued under enforce; delivered in cleartext after the domain withdrew enforcement with an authenticated policy (generation %d)",
				plannedGeneration(res)),
			At: w.now(),
		})
	}

	rep := Report{
		Domain: e.Domain, Entry: e, Verdict: v, Released: released,
		Policy: res.Policy, Observation: res.Observation, History: res.History,
		Attempts: attempts,
	}

	if delivered != nil {
		rep.Delivered = true
		if delivered.Attempt.TLSStarted {
			rep.Entry.LastErr = ""
			rep.Entry.Hold = ""
			w.Store.Delete(e.ID)
		} else {
			if needTLS {
				// Should be impossible: the client asserts it, and this
				// report exists regardless.
				rep.CleartextRefused = true
			} else {
				rep.CleartextSent = true
				rep.Entry.Released = released
				w.Store.Delete(e.ID)
			}
		}
		return rep
	}

	if needTLS && (len(attempts) == 0 || !attempts[len(attempts)-1].TLSStarted) {
		rep.CleartextRefused = true
	}
	if len(attempts) > 0 {
		e.LastErr = attempts[len(attempts)-1].Error
	}
	e.Hold = v.Explanation
	e.Attempts++
	backoff := time.Duration(1<<min(e.Attempts, 6)) * time.Minute
	e.NextTry = w.now().Add(backoff)
	w.Store.Put(e)
	return rep
}

// recheckBeforeDATA is the gate that closes the resolve-to-send window.
//
// It is deliberately *not* "abort on any generation change": a routine
// lifetime renewal or an upgrade must not cancel a message mid-flight. It
// aborts only when the change would make the transmission we are about to
// perform non-compliant.
func (w *Worker) recheckBeforeDATA(ctx context.Context, e *Entry, planned *model.Policy, h model.MXHost) error {
	live := w.Engine.Peek(e.Domain)
	if live == nil || live.Policy == nil {
		// Not cached: force a fresh look rather than assuming the best.
		res, err := w.Engine.Resolve(ctx, e.Domain)
		if err != nil {
			return fmt.Errorf("policy unavailable at send time: %w", err)
		}
		live = res
	}
	lp := live.Policy
	if lp.Generation == planned.Generation {
		return nil
	}

	// 1. A weakening of the mode. Honoured only if the engine sanctioned
	// the transition; otherwise this is the downgrade we refuse.
	if lp.Mode < planned.Mode {
		if !sanctionedRelaxation(live.History) {
			return fmt.Errorf("policy weakened from %s to %s during delivery", planned.Mode, lp.Mode)
		}
		if planned.Mode == model.ModeEnforce {
			// Released explicitly; the caller records the release.
			return nil
		}
	}

	// 2. The permitted MX set no longer includes this host.
	if len(lp.MX) > 0 && !lp.MatchesMX(h.Host) {
		return fmt.Errorf("MX %s no longer permitted by policy", h.Host)
	}

	// 3. The TLSA records for this host changed: the certificate we just
	// validated may no longer be the one the domain publishes.
	if lp.Source == model.SourceDANE {
		old := planned.TLSA[h.Host]
		now := lp.TLSA[h.Host]
		if !sameTLSASet(old, now) {
			return fmt.Errorf("TLSA records for %s changed during delivery", h.Host)
		}
	}
	return nil
}

func plannedGeneration(res *policy.Resolution) uint64 {
	if res.Policy == nil {
		return 0
	}
	return res.Policy.Generation
}

func reasonOf(r *policy.Resolution) string {
	if r.Err != nil {
		return r.Err.Error()
	}
	return "policy unavailable"
}

// sanctionedRelaxation reports whether the domain's history contains an
// accepted transition out of enforce that the policy engine itself approved
// (authenticated, or stabilised across the window).
func sanctionedRelaxation(hist []model.Transition) bool {
	for i := len(hist) - 1; i >= 0; i-- {
		t := hist[i]
		if t.From == model.ModeEnforce && t.To < model.ModeEnforce {
			switch t.Reason {
			case "authenticated_downgrade", "downgrade_stabilized":
				return true
			default:
				return false
			}
		}
	}
	return false
}

// candidateHosts orders MX hosts for an attempt. Under an enforcing policy,
// hosts not permitted by the MX pattern list are dropped entirely rather
// than tried last: trying them is not a fallback, it is the downgrade.
func candidateHosts(res *policy.Resolution) []model.MXHost {
	hosts := append([]model.MXHost(nil), res.MX...)
	if res.Policy != nil && len(res.Policy.MX) > 0 {
		var kept []model.MXHost
		for _, h := range hosts {
			if res.Policy.MatchesMX(h.Host) {
				kept = append(kept, h)
			}
		}
		hosts = kept
	}
	sort.SliceStable(hosts, func(i, j int) bool {
		if hosts[i].Pref != hosts[j].Pref {
			return hosts[i].Pref < hosts[j].Pref
		}
		return hosts[i].Host < hosts[j].Host
	})
	return hosts
}

func sameTLSASet(a, b []model.TLSARecord) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Usage != b[i].Usage || a[i].Selector != b[i].Selector ||
			a[i].MatchingType != b[i].MatchingType || !bytes.Equal(a[i].Data, b[i].Data) {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// String renders an entry for logs.
func (e *Entry) String() string {
	return fmt.Sprintf("%s -> %s (%d rcpt, mode=%s gen=%d, tries=%d)",
		e.From, e.Domain, len(e.To), e.PlannedMode, e.PlannedGeneration, e.Attempts)
}

// FileStore persists entries as one JSON file per message under a
// directory. It is a simple durable store: enough to survive a restart, not
// transactional enough for multi-writer use.
type FileStore struct{ Dir string }

func (f *FileStore) path(id string) string {
	safe := strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(id)
	return filepath.Join(f.Dir, safe+".json")
}

type storedEntry struct {
	ID                string     `json:"id"`
	Domain            string     `json:"domain"`
	From              string     `json:"from"`
	To                []string   `json:"to"`
	Body              []byte     `json:"body"`
	Enqueued          time.Time  `json:"enqueued"`
	PlannedMode       model.Mode `json:"planned_mode"`
	PlannedGeneration uint64     `json:"planned_generation"`
	Attempts          int        `json:"attempts"`
	NextTry           time.Time  `json:"next_try,omitempty"`
	LastErr           string     `json:"last_error,omitempty"`
	Hold              string     `json:"hold,omitempty"`
	Released          bool       `json:"released,omitempty"`
}

func (f *FileStore) Put(e *Entry) error {
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(storedEntry{
		ID: e.ID, Domain: e.Domain, From: e.From, To: e.To, Body: e.Body,
		Enqueued: e.Enqueued, PlannedMode: e.PlannedMode,
		PlannedGeneration: e.PlannedGeneration, Attempts: e.Attempts,
		NextTry: e.NextTry, LastErr: e.LastErr, Hold: e.Hold, Released: e.Released,
	}, "", "  ")
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
	return os.Rename(tmp.Name(), f.path(e.ID))
}

func (f *FileStore) Delete(id string) error {
	err := os.Remove(f.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (f *FileStore) List() ([]*Entry, error) {
	ents, err := os.ReadDir(f.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Entry
	for _, de := range ents {
		if de.IsDir() || strings.HasPrefix(de.Name(), ".") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(f.Dir, de.Name()))
		if err != nil {
			return nil, err
		}
		var se storedEntry
		if err := json.Unmarshal(b, &se); err != nil {
			// A corrupt queue file must not stop the whole queue; log-worthy
			// in production, skipped here with the file left in place.
			continue
		}
		out = append(out, &Entry{
			ID: se.ID, Domain: se.Domain, From: se.From, To: se.To, Body: se.Body,
			Enqueued: se.Enqueued, PlannedMode: se.PlannedMode,
			PlannedGeneration: se.PlannedGeneration, Attempts: se.Attempts,
			NextTry: se.NextTry, LastErr: se.LastErr, Hold: se.Hold, Released: se.Released,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
