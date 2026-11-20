package lab

import (
	"net"
	"strings"
)

func mustIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("bad ip " + s)
	}
	return ip
}

func splitAddr(a string) (host, port string, err error) {
	return net.SplitHostPort(a)
}

// hostOf returns the host part of "host:port", or the input on failure.
func hostOf(a string) string {
	h, _, err := net.SplitHostPort(a)
	if err != nil {
		return a
	}
	return h
}

// PortOf returns the numeric port of "host:port".
func PortOf(a string) int {
	_, p, err := net.SplitHostPort(a)
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range strings.TrimSpace(p) {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
