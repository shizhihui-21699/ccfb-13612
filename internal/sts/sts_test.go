package sts

import (
	"strings"
	"testing"

	"gateway/internal/model"
)

func TestParsePolicyValid(t *testing.T) {
	p, err := ParsePolicy([]byte(`version: STSv1
mode: enforce
mx: mx1.example.com
mx: *.example.com
max_age: 604800
`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != model.ModeEnforce || p.MaxAge != 604800*1e9 {
		t.Fatalf("%+v", p)
	}
	if len(p.MX) != 2 {
		t.Fatalf("mx %v", p.MX)
	}
}

func TestParsePolicyRejects(t *testing.T) {
	cases := map[string]string{
		"mode none":    "version: STSv1\nmode: none\nmx: a.example\nmax_age: 60\n",
		"missing mode": "version: STSv1\nmx: a.example\nmax_age: 60\n",
		"missing age":  "version: STSv1\nmode: enforce\nmx: a.example\n",
		"missing mx":   "version: STSv1\nmode: enforce\nmax_age: 60\n",
		"bad version":  "version: STSv2\nmode: enforce\nmx: a.example\nmax_age: 60\n",
		"negative age": "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: -5\n",
		"zero age":     "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: 0\n",
		"garbage line": "version: STSv1\nmode enforce\nmx: a.example\nmax_age: 60\n",
		"bad mx":       "version: STSv1\nmode: enforce\nmx: http://a.example/x\nmax_age: 60\n",
	}
	for name, body := range cases {
		if _, err := ParsePolicy([]byte(body)); err == nil {
			t.Errorf("%s: accepted, want error", name)
		}
	}
}

func TestParsePolicyUnknownKeysIgnored(t *testing.T) {
	p, err := ParsePolicy([]byte("version: STSv1\nmode: testing\nmx: a.example\nmax_age: 60\nfuture_field: whatever\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != model.ModeTesting {
		t.Fatalf("mode %s", p.Mode)
	}
}

func TestParsePolicyCapsMaxAge(t *testing.T) {
	p, err := ParsePolicy([]byte("version: STSv1\nmode: enforce\nmx: a.example\nmax_age: 31536000\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxAge > MaxPolicyAge {
		t.Fatalf("max_age %v exceeds the local cap %v", p.MaxAge, MaxPolicyAge)
	}
}

func TestParseSTSRecord(t *testing.T) {
	for _, ok := range []string{
		"v=STSv1; id=abc",
		"ID=abc; v=STSv1",
		"v=STSv1;id=abc;",
		"  v=STSv1 ;  id = abc  ",
	} {
		id, good := parseSTSRecord(ok)
		if !good || id != "abc" {
			t.Errorf("%q: got %q %v", ok, id, good)
		}
	}
	for _, bad := range []string{
		"",
		"v=STSv1",
		"v=STSv2; id=abc",
		"id=abc",
		"v=STSv1; id=",
	} {
		if _, good := parseSTSRecord(bad); good {
			t.Errorf("%q: accepted", bad)
		}
	}
}

func TestValidHost(t *testing.T) {
	good := []string{"a.example", "mx-1.example.co.uk", "a_b.example"}
	bad := []string{"", "a..b", "-a.example", strings.Repeat("a", 64) + ".example", "a.example:25"}
	for _, h := range good {
		if !validHost(h) {
			t.Errorf("%q rejected", h)
		}
	}
	for _, h := range bad {
		if validHost(h) {
			t.Errorf("%q accepted", h)
		}
	}
}
