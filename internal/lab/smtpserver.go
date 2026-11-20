package lab

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// ServerPolicy describes how a simulated MX behaves. Every field maps to a
// real-world failure mode or attacker technique.
type ServerPolicy struct {
	// AdvertiseSTARTTLS controls whether EHLO lists STARTTLS. False is the
	// signature of a capability-stripping attacker.
	AdvertiseSTARTTLS bool
	// STARTTLSReply overrides the reply code to the STARTTLS command
	// (0 = normal 220). 454 models a server that has TLS configured but
	// temporarily cannot use it.
	STARTTLSReply int
	// BreakHandshake closes the connection after the STARTTLS 220, without
	// completing the handshake: a classic active-downgrade probe, and also
	// a buggy middlebox.
	BreakHandshake bool
	// RequireAuth answers 530 to MAIL FROM: a server configured as a
	// submission endpoint by mistake.
	RequireAuth bool
	// Reply5xx answers a fixed 5xx to the final dot.
	Reply5xx string

	// Certs holds the certificate to present. Nil means the server does
	// not support TLS at all (it will advertise it if asked, but fail).
	Certs *CertStore
	// MinVersion is the minimum TLS version the server accepts.
	MinVersion uint16

	// Banner is the 220 text.
	Banner string
}

// Server is a simulated SMTP server.
type Server struct {
	Name string
	Pol  ServerPolicy

	ln    net.Listener
	mu    sync.Mutex
	conns int
	// Received records the (EHLO/MAIL/RCPT/DATA) sequence of the last
	// delivery, for assertions.
	received []string
	// Accepted counts messages accepted at the final dot.
	accepted int
	// CleartextAccepted counts accepted messages that were not encrypted.
	cleartextAccepted int
	// TLSVersions records negotiated versions.
	tlsVersions []uint16
	// FirstByte records whether the first byte written by the client after
	// connect was 0x16 (a TLS handshake record) for every connection; used
	// to prove the client never spoke cleartext to a TLS-only port.
	firstBytes []byte
}

// NewServer starts a server on a loopback port.
func NewServer(name string, pol ServerPolicy) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	if pol.Banner == "" {
		pol.Banner = "EIMS " + name
	}
	if pol.MinVersion == 0 {
		pol.MinVersion = tls.VersionTLS12
	}
	s := &Server{Name: name, Pol: pol, ln: ln}
	go s.serve()
	return s, nil
}

// Addr returns the listener address.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Close stops the server.
func (s *Server) Close() { s.ln.Close() }

// Stats returns counters, safe to call concurrently.
func (s *Server) Stats() (accepted, cleartext int, tlsVersions []uint16, firstBytes []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted, s.cleartextAccepted, append([]uint16(nil), s.tlsVersions...), append([]byte(nil), s.firstBytes...)
}

func (s *Server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	s.mu.Lock()
	s.conns++
	s.mu.Unlock()

	rc := &recordFirst{Conn: c, srv: s}
	br := bufio.NewReader(rc)
	bw := bufio.NewWriter(rc)
	encrypted := false

	write := func(s string) error {
		if _, err := bw.WriteString(s + "\r\n"); err != nil {
			return err
		}
		return bw.Flush()
	}
	write("220 " + s.Pol.Banner)

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.TrimSpace(strings.SplitN(line, " ", 2)[0]))
		switch verb {
		case "EHLO":
			if err := write("250-" + s.Name); err != nil {
				return
			}
			caps := []string{"SIZE 104857600", "8BITMIME", "PIPELINING"}
			if s.Pol.AdvertiseSTARTTLS && !encrypted {
				caps = append([]string{"STARTTLS"}, caps...)
			}
			for i, cp := range caps {
				sep := "-"
				if i == len(caps)-1 {
					sep = " "
				}
				if err := write("250" + sep + cp); err != nil {
					return
				}
			}
		case "HELO":
			if err := write("250 " + s.Name); err != nil {
				return
			}
		case "STARTTLS":
			if !s.Pol.AdvertiseSTARTTLS {
				if err := write("502 5.5.1 command not implemented"); err != nil {
					return
				}
				continue
			}
			if s.Pol.STARTTLSReply != 0 {
				if err := write(fmt.Sprintf("%d 4.7.0 temporary failure", s.Pol.STARTTLSReply)); err != nil {
					return
				}
				continue
			}
			if err := write("220 2.0.0 ready to start TLS"); err != nil {
				return
			}
			if s.Pol.BreakHandshake {
				return
			}
			cert, key, ok := s.Pol.Certs.Get()
			if !ok {
				return
			}
			tc := tls.Server(c, &tls.Config{
				Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}},
				MinVersion:   s.Pol.MinVersion,
			})
			if err := tc.Handshake(); err != nil {
				log.Printf("lab %s: handshake failed: %v", s.Name, err)
				return
			}
			cs := tc.ConnectionState()
			s.mu.Lock()
			s.tlsVersions = append(s.tlsVersions, cs.Version)
			s.mu.Unlock()
			rc.Conn = tc
			br = bufio.NewReader(rc)
			bw = bufio.NewWriter(rc)
			encrypted = true
		case "MAIL":
			if s.Pol.RequireAuth {
				if err := write("530 5.7.0 Authentication required"); err != nil {
					return
				}
				continue
			}
			if err := write("250 2.1.0 ok"); err != nil {
				return
			}
		case "RCPT":
			if err := write("250 2.1.5 ok"); err != nil {
				return
			}
		case "DATA":
			if err := write("354 go ahead"); err != nil {
				return
			}
			if err := readDotData(br); err != nil {
				return
			}
			if s.Pol.Reply5xx != "" {
				if err := write(s.Pol.Reply5xx); err != nil {
					return
				}
				continue
			}
			s.mu.Lock()
			s.accepted++
			if !encrypted {
				s.cleartextAccepted++
			}
			s.mu.Unlock()
			if err := write("250 2.0.0 queued as LAB-" + s.Name); err != nil {
				return
			}
		case "QUIT":
			write("221 bye")
			return
		case "RSET":
			write("250 ok")
		case "NOOP":
			write("250 ok")
		default:
			if err := write("502 5.5.2 unrecognized"); err != nil {
				return
			}
		}
	}
}

// recordFirst records the first byte the client sends on a connection. A
// TLS record starts with 0x16; a cleartext SMTP verb starts with a letter.
// The tests use this to prove the client never spoke before securing the
// channel.
type recordFirst struct {
	net.Conn
	srv  *Server
	once bool
}

func (r *recordFirst) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	if n > 0 && !r.once {
		r.once = true
		r.srv.mu.Lock()
		r.srv.firstBytes = append(r.srv.firstBytes, b[0])
		r.srv.mu.Unlock()
	}
	return n, err
}

func readDotData(br *bufio.Reader) error {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if line == ".\r\n" || line == ".\n" {
			return nil
		}
		if _, err := io.Discard.Write(nil); err != nil {
			return err
		}
	}
}
