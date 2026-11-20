package lab

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
)

// PolicyServer is an HTTPS server whose body can be swapped at runtime, so
// a test can model a policy change without restarting anything.
type PolicyServer struct {
	*http.Server
	mu   sync.RWMutex
	body string
}

// SetBody replaces the served policy.
func (p *PolicyServer) SetBody(b string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.body = b
}

// NewHTTPServer starts a policy-file server on loopback, serving body at the
// well-known path and 404 elsewhere.
func NewHTTPServer(pair tls.Certificate, body string) (*PolicyServer, string, error) {
	ps := &PolicyServer{body: body}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/mta-sts.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		ps.mu.RLock()
		b := ps.body
		ps.mu.RUnlock()
		w.Write([]byte(b))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	srv := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{pair},
			MinVersion:   tls.VersionTLS12,
		},
	}
	ps.Server = srv
	go srv.ServeTLS(ln, "", "")
	return ps, ln.Addr().String(), nil
}

// RedirectingHTTPServer serves a 302 for the well-known path, to test that
// the fetcher refuses redirects.
func RedirectingHTTPServer(pair tls.Certificate, target string) (*http.Server, string, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/mta-sts.txt", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	srv := &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}}
	go srv.ServeTLS(ln, "", "")
	return srv, ln.Addr().String(), nil
}
