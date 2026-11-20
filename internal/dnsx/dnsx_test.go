package dnsx

import (
	"sort"
	"testing"

	"github.com/miekg/dns"
)

// canonicalCompare is load-bearing for NSEC coverage decisions. A wrong
// ordering silently turns "this name does not exist" into "this name might
// exist" or vice versa, in both directions a security outcome.
func TestCanonicalCompare(t *testing.T) {
	names := []string{
		".",
		"a.example.",
		"z.example.",
		"example.",
		"_mta-sts.example.",
		"mx1.example.",
		"a.b.example.",
	}
	want := append([]string(nil), names...)
	sort.Slice(want, func(i, j int) bool { return canonicalCompare(want[i], want[j]) < 0 })
	// Whatever the order, it must be a strict total order consistent with
	// itself, and the root must sort first.
	if want[0] != "." {
		t.Fatalf("root is not first: %v", want)
	}
	for i := 1; i < len(want); i++ {
		if canonicalCompare(want[i-1], want[i]) >= 0 {
			t.Fatalf("not strictly ordered at %d: %v", i, want)
		}
		if canonicalCompare(want[i], want[i-1]) <= 0 {
			t.Fatalf("order not antisymmetric at %d: %v", i, want)
		}
	}
	// Label ordering is octet-wise, so underscore sorts before letters.
	if canonicalCompare("_mta-sts.example.", "mx1.example.") >= 0 {
		t.Fatal("'_' must sort before 'm'")
	}
	// A parent sorts before its child.
	if canonicalCompare("example.", "a.example.") >= 0 {
		t.Fatal("parent must sort before child")
	}
}

func TestInCanonicalInterval(t *testing.T) {
	// A simple non-wrapping interval.
	if !inCanonicalInterval("a.example.", "c.example.", "b.example.") {
		t.Fatal("b should be inside (a, c)")
	}
	if inCanonicalInterval("a.example.", "c.example.", "a.example.") {
		t.Fatal("the lower bound is exclusive")
	}
	if inCanonicalInterval("a.example.", "c.example.", "c.example.") {
		t.Fatal("the upper bound is exclusive")
	}
	// A wrapping interval: the last name in the zone points at the apex.
	// "zz.example." wraps to "a.example.". In canonical order the names
	// are a < b < zy < zz, so a wrapped (zz, a) interval covers only what
	// sorts after zz — and nothing sorts before the apex, so "zy" and "b"
	// are both outside it.
	if !inCanonicalInterval("zz.example.", "a.example.", "zzz.example.") {
		t.Fatal("zzz sorts after zz and should be covered by the wrapped interval")
	}
	if inCanonicalInterval("zz.example.", "a.example.", "zy.example.") {
		t.Fatal("zy sorts between the apex and zz, so it is outside the wrapped interval")
	}
	if inCanonicalInterval("zz.example.", "a.example.", "b.example.") {
		t.Fatal("b is outside a wrapped (zz, a) interval")
	}
	// An interval whose bounds are equal covers nothing.
	if inCanonicalInterval("a.example.", "a.example.", "b.example.") {
		t.Fatal("an empty interval covers nothing")
	}
}

func TestNSECCoverageRejectsOtherZone(t *testing.T) {
	// An NSEC from one zone must not be able to "prove" absence of a name
	// in a different zone: that is how a hostile authoritative server gets
	// a bogus denial accepted.
	n := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeNSEC},
		NextDomain: "z.example.",
	}
	if nsecCovers(n, "evil.other.") {
		t.Fatal("an example-zone NSEC covered a name in another zone")
	}
	if !nsecCovers(n, "m.example.") {
		t.Fatal("m.example should be covered")
	}
	// An exact owner-name match proves the name exists, not that it is
	// absent; the caller distinguishes those by the RRset being empty.
	if !nsecCovers(n, "a.example.") {
		t.Fatal("exact match should report coverage (type absence)")
	}
}
