// Package proxydialer provides SOCKS5 proxy dialer creation for tunneling
// network traffic through a proxy.
package proxydialer

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/proxy"
)

// ContextDialer dials with context support. Compatible with go-mssqldb's Dialer interface.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// New creates a SOCKS5 proxy dialer from a proxy address string.
// Supported formats:
//   - host:port (plain SOCKS5, no auth)
//   - socks5://host:port
//   - socks5://user:pass@host:port
//
// Returns nil, nil if proxyAddr is empty.
func New(proxyAddr string) (ContextDialer, error) {
	if proxyAddr == "" {
		return nil, nil
	}

	var d proxy.Dialer
	var err error

	if strings.Contains(proxyAddr, "://") {
		u, parseErr := url.Parse(proxyAddr)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyAddr, parseErr)
		}
		if u.Scheme != "socks5" && u.Scheme != "socks5h" {
			return nil, fmt.Errorf("unsupported proxy scheme %q (only socks5 and socks5h are supported)", u.Scheme)
		}
		var auth *proxy.Auth
		if u.User != nil {
			pass, _ := u.User.Password()
			auth = &proxy.Auth{
				User:     u.User.Username(),
				Password: pass,
			}
		}
		d, err = proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
	} else {
		d, err = proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer for %q: %w", proxyAddr, err)
	}

	// The underlying socks.Dialer implements DialContext
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS5 dialer does not implement ContextDialer")
	}

	return cd, nil
}
