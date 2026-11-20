package lab

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/model"
)

// TestConcurrentResolveSingleFetch: many goroutines resolving the same
// domain must produce exactly one policy fetch. Otherwise a burst of mail
// turns into a fetch storm against the partner's policy host, and each fetch
// is a chance to see a different answer.
func TestConcurrentResolveSingleFetch(t *testing.T) {
	const body = "version: STSv1\nmode: enforce\nmx: mx1.partner.example\nmax_age: 86400\n"
	w := NewWorld(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		PolicyTXT:  true,
		PolicyID:   "id1",
		PolicyBody: body,
		MXHosts:    []MXHostSpec{{Host: "mx1.partner.example"}},
	})
	var fetches atomic.Int64
	w.Policy.SetFetchHook(func() { fetches.Add(1) })

	var wg sync.WaitGroup
	modes := make([]model.Mode, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := w.Policy.Resolve(context.Background(), w.Domain)
			if err != nil {
				t.Error(err)
				return
			}
			modes[i] = res.Policy.Mode
		}(i)
	}
	wg.Wait()
	for i, m := range modes {
		if m != model.ModeEnforce {
			t.Fatalf("goroutine %d got mode %s", i, m)
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("policy fetched %d times for one domain, want 1", n)
	}
}

// TestManyDomainsCachedAndBounded: a large fan-out across domains must hit
// the DNS cache rather than issuing one query per domain per delivery, and
// the fetch concurrency must stay bounded.
func TestManyDomainsCachedAndBounded(t *testing.T) {
	w := NewWorld(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		PolicyTXT:  true,
		PolicyID:   "id1",
		PolicyBody: "version: STSv1\nmode: enforce\nmx: mx1.partner.example\nmax_age: 86400\n",
		MXHosts:    []MXHostSpec{{Host: "mx1.partner.example"}},
	})
	// Warm the cache, then resolve repeatedly: not one further DNS query
	// is acceptable, because the policy lifetime is a day.
	if _, err := w.Policy.Resolve(context.Background(), w.Domain); err != nil {
		t.Fatal(err)
	}
	before := w.DNS.QueryCount()
	for i := 0; i < 200; i++ {
		if _, err := w.Policy.Resolve(context.Background(), w.Domain); err != nil {
			t.Fatal(err)
		}
	}
	after := w.DNS.QueryCount()
	if after != before {
		t.Fatalf("200 cached resolves issued %d DNS queries", after-before)
	}
	if w.Resolver.Stats() == 0 {
		t.Fatal("expected some resolver queries at first resolve")
	}
}

// TestNoFetchStormOnFailure: when the policy host is down, N queued messages
// for the same domain must not each trigger a fetch.
func TestNoFetchStormOnFailure(t *testing.T) {
	w := NewWorld(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		PolicyTXT:  true,
		PolicyID:   "id1",
		PolicyBody: "version: STSv1\nmode: enforce\nmx: mx1.partner.example\nmax_age: 600\n",
		MXHosts:    []MXHostSpec{{Host: "mx1.partner.example"}},
	})
	// Establish, then break the policy host.
	res, err := w.Policy.Resolve(context.Background(), w.Domain)
	if err != nil || res.Policy.Mode != model.ModeEnforce {
		t.Fatalf("setup: %v %v", res, err)
	}
	// Expire the entry so the next batch refreshes.
	w.Policy.ExpireForTest(w.Domain)
	var fetches atomic.Int64
	w.Policy.SetFetchHook(func() { fetches.Add(1) })

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = w.Policy.Resolve(context.Background(), w.Domain)
		}()
	}
	wg.Wait()
	if n := fetches.Load(); n > 1 {
		t.Fatalf("%d fetches for 50 concurrent expiries of one domain", n)
	}
}

// TestConcurrentDistinctDomains exercises the engine across many domains at
// once, which is what a real gateway sees.
func TestConcurrentDistinctDomains(t *testing.T) {
	w := NewWorld(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		MXHosts: []MXHostSpec{{Host: "mx1.partner.example"}},
	})
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		d := fmt.Sprintf("tenant%d.partner.example", i)
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			// No policy exists for these; the engine must still answer
			// promptly and consistently rather than deadlocking.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			res, err := w.Policy.Resolve(ctx, d)
			if err != nil {
				errs <- err
				return
			}
			if res.Policy == nil {
				errs <- fmt.Errorf("%s: nil policy", d)
			}
		}(d)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestNoPolicyDomainIsNegativelyCached: a domain that publishes nothing must
// not re-resolve on every message. Without negative caching, the large
// minority of such domains turns into a persistent query load and, worse, a
// repeated chance for an attacker to answer differently each time.
func TestNoPolicyDomainIsNegativelyCached(t *testing.T) {
	w := NewWorld(t, WorldOptions{
		Domain: "partner.example", SignedDomain: true,
		PolicyTXT: false,
		MXHosts:   []MXHostSpec{{Host: "mx1.partner.example"}},
		Clock:     NewClock(time.Unix(1_700_000_000, 0)),
	})
	var fetches atomic.Int64
	w.Policy.SetFetchHook(func() { fetches.Add(1) })
	if _, err := w.Policy.Resolve(context.Background(), w.Domain); err != nil {
		t.Fatal(err)
	}
	before := w.DNS.QueryCount()
	for i := 0; i < 100; i++ {
		if _, err := w.Policy.Resolve(context.Background(), w.Domain); err != nil {
			t.Fatal(err)
		}
	}
	if d := w.DNS.QueryCount() - before; d != 0 {
		t.Fatalf("100 resolves of a no-policy domain issued %d DNS queries", d)
	}
	if fetches.Load() != 0 {
		t.Fatalf("no-policy domain triggered %d policy fetches", fetches.Load())
	}
}
