// Command gateway is a mail submission gateway that will not degrade
// transport security.
//
// It reads a queue of messages from a JSON file, resolves each recipient
// domain's transport-security policy (MTA-STS and DANE, DNSSEC-validated),
// attempts delivery, and writes a report separating suspected interception
// from remote misconfiguration.
//
// Usage:
//
//	gateway -queue queue.json -report report.txt -json report.json
//	gateway -queue queue.json -simulate        # run the built-in scenarios
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"

	"gateway/internal/classify"
	"gateway/internal/dnsx"
	"gateway/internal/model"
	"gateway/internal/policy"
	"gateway/internal/queue"
	"gateway/internal/report"
	"gateway/internal/smtpc"
	"gateway/internal/sts"
)

func main() {
	var (
		queueFile  = flag.String("queue", "", "JSON file with messages to send")
		reportText = flag.String("report", "", "write a human-readable report here (default stdout)")
		reportJSON = flag.String("json", "", "write a JSON report here")
		stateDir   = flag.String("state", ".gateway-state", "directory holding persisted policy state")
		resolver   = flag.String("dns", "127.0.0.1:53", "DNS resolver to use")
		helo       = flag.String("helo", "gateway.local", "EHLO name")
		simulate   = flag.Bool("simulate", false, "run the built-in simulation instead of a real queue")
		strict     = flag.Bool("strict-unknown", false, "hold mail for domains with no authenticated policy")
		strictDoms = flag.String("protect", "", "comma-separated domains that get strict-unknown behaviour")
		timeout    = flag.Duration("timeout", 30*time.Second, "per-phase SMTP timeout")
	)
	flag.Parse()

	var (
		textOut = os.Stdout
		jsonOut = os.Stdout
	)
	if *reportText != "" {
		f, err := os.Create(*reportText)
		must(err)
		defer f.Close()
		textOut = f
	}
	if *reportJSON != "" {
		f, err := os.Create(*reportJSON)
		must(err)
		defer f.Close()
		jsonOut = f
	}

	res := dnsx.NewResolver(*resolver)
	// In a real deployment the anchors come from the root's trust anchor
	// file. Failing to load them is fatal: without an anchor every lookup
	// is insecure and the whole enforcement path silently becomes
	// opportunistic.
	anchors, err := loadAnchors(os.Getenv("GATEWAY_TRUST_ANCHORS"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "gateway: trust anchors: %v\n", err)
		os.Exit(2)
	}
	if len(anchors) == 0 && !*simulate {
		fmt.Fprintln(os.Stderr, "gateway: no trust anchors configured (GATEWAY_TRUST_ANCHORS); refusing to run, because every policy would be unauthenticated")
		os.Exit(2)
	}
	for zone, keys := range anchors {
		for _, k := range keys {
			res.AddAnchor(zone, k)
		}
	}

	fetcher := &sts.Fetcher{Resolver: res, Timeout: 15 * time.Second}
	if *simulate {
		// The simulation installs its own engine over a private network;
		// nothing it does touches the real resolver or state directory.
		os.Exit(runSimulation(res, nil, nil, textOut, jsonOut, *stateDir))
	}
	store := &policy.FileStore{Dir: *stateDir}
	opts := policy.Options{
		StrictUnknown:    *strict,
		ProtectedDomains: splitList(*strictDoms),
	}
	eng := policy.New(res, fetcher, store, opts)
	client := smtpc.New(smtpc.Config{HeloName: *helo, Timeout: *timeout})
	worker := &queue.Worker{Engine: eng, Client: client, Store: &queue.FileStore{Dir: filepath.Join(*stateDir, "queue")}}

	if *queueFile == "" {
		fmt.Fprintln(os.Stderr, "gateway: -queue is required (or use -simulate)")
		flag.Usage()
		os.Exit(2)
	}

	msgs, err := loadQueue(*queueFile)
	must(err)
	ctx := context.Background()
	for _, m := range msgs {
		if err := worker.Enqueue(ctx, m); err != nil {
			fmt.Fprintf(os.Stderr, "gateway: enqueue %s: %v\n", m.Domain, err)
		}
	}
	reports, err := worker.RunOnce(ctx)
	must(err)

	var deliveries []report.Delivery
	for _, r := range reports {
		deliveries = append(deliveries, toDelivery(r))
	}
	report.WriteText(textOut, deliveries)
	if *reportJSON != "" {
		must(report.WriteJSON(jsonOut, deliveries))
	}
}

func toDelivery(r queue.Report) report.Delivery {
	// Outcome and Fault answer different questions. Outcome is what
	// happened to the message; Fault is why. A cleartext refusal because
	// the remote is merely broken is still a *deferral* — the message is
	// held and will be retried — and calling it "blocked" would tell the
	// operator a domain is unreachable when it is not. Only a refusal
	// driven by a policy we cannot satisfy is terminal for this cycle in
	// the sense the report means.
	outcome := model.OutDeferred
	switch {
	case r.Delivered && r.CleartextSent:
		outcome = model.OutDeliveredCleartext
	case r.Delivered:
		outcome = model.OutDeliveredTLS
	case r.CleartextRefused && (r.Verdict.Fault == model.FaultPolicyUnavailable ||
		r.Verdict.Fault == model.FaultPolicyDowngrade):
		outcome = model.OutBlocked
	case r.Verdict.Fault == model.FaultAttackSuspected:
		outcome = model.OutBlocked
	}
	e := r.Entry
	return report.Build(e.ID, e.Domain, e.From, e.To, e.Enqueued,
		r.Policy,
		report.Observation{
			TXTStatus:  r.Observation.TXTStatus,
			TXTPresent: r.Observation.TXTPresent,
			FetchError: r.Observation.FetchError,
		},
		r.Attempts, r.Verdict, outcome, r.History, r.Released)
}

func loadQueue(path string) ([]*queue.Entry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		ID     string   `json:"id"`
		To     []string `json:"to"`
		From   string   `json:"from"`
		Domain string   `json:"domain"`
		Body   string   `json:"body"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var out []*queue.Entry
	for _, r := range raw {
		dom := r.Domain
		if dom == "" && len(r.To) > 0 {
			if i := strings.LastIndex(r.To[0], "@"); i >= 0 {
				dom = r.To[0][i+1:]
			}
		}
		out = append(out, &queue.Entry{
			ID: r.ID, Domain: dom, From: r.From, To: r.To,
			Body: []byte(r.Body),
		})
	}
	return out, nil
}

// loadAnchors reads a JSON object mapping zone -> [DNSKEY text records].
func loadAnchors(path string) (map[string][]*dns.DNSKEY, error) {
	if path == "" {
		// A built-in anchor for the lab root is deliberately absent: an
		// operator must supply their own. The simulation command installs
		// its anchors programmatically.
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string][]string
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := map[string][]*dns.DNSKEY{}
	for zone, recs := range raw {
		for _, text := range recs {
			rr, err := dns.NewRR(text)
			if err != nil {
				return nil, fmt.Errorf("anchor for %s: %w", zone, err)
			}
			k, ok := rr.(*dns.DNSKEY)
			if !ok {
				return nil, fmt.Errorf("anchor for %s is not a DNSKEY: %s", zone, text)
			}
			out[zone] = append(out[zone], k)
		}
	}
	return out, nil
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "gateway: %v\n", err)
		os.Exit(1)
	}
}

var _ = classify.Classify
