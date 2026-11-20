package lab

import (
	"sync"
	"time"
)

// Clock is a manually advanced clock. Tests use it to move policy lifetimes,
// stabilization windows and backoff without sleeping.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock starts a clock at a fixed instant.
func NewClock(t time.Time) *Clock { return &Clock{t: t} }

// Now returns the current simulated time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// SetTime sets the clock.
func (c *Clock) SetTime(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}
