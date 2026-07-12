package netutil

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// ValidateServerTransport allows HTTPS everywhere and HTTP only for loopback hosts.
func ValidateServerTransport(parsed *url.URL) error {
	if parsed == nil {
		return errors.New("server url is required")
	}

	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(parsed.Hostname()) {
			return nil
		}
		return errors.New("server url must use https outside localhost")
	default:
		return errors.New("server url must use http or https")
	}
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
