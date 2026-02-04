// Package utils provides DNS utility functions
package utils

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DigTraceIP performs a DNS trace lookup and returns the resolved IP addresses
func DigTraceIP(domain string) ([]string, error) {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	var ips []string

	// Try to resolve using system resolver first
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(ctx, strings.TrimSuffix(domain, "."))
	if err == nil && len(addrs) > 0 {
		return addrs, nil
	}

	// Fallback to DNS query using miekg/dns
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	// Try common DNS servers
	dnsServers := []string{"8.8.8.8:53", "114.114.114.114:53", "1.1.1.1:53"}

	for _, server := range dnsServers {
		// Query A records
		m := new(dns.Msg)
		m.SetQuestion(domain, dns.TypeA)
		m.RecursionDesired = true

		r, _, err := c.Exchange(m, server)
		if err != nil {
			continue
		}

		if r.Rcode != dns.RcodeSuccess {
			continue
		}

		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				ips = append(ips, a.A.String())
			}
		}

		// Query AAAA records
		m6 := new(dns.Msg)
		m6.SetQuestion(domain, dns.TypeAAAA)
		m6.RecursionDesired = true

		r6, _, err := c.Exchange(m6, server)
		if err == nil && r6.Rcode == dns.RcodeSuccess {
			for _, ans := range r6.Answer {
				if aaaa, ok := ans.(*dns.AAAA); ok {
					ips = append(ips, aaaa.AAAA.String())
				}
			}
		}

		if len(ips) > 0 {
			break
		}
	}

	if len(ips) == 0 {
		return nil, err
	}

	return ips, nil
}
