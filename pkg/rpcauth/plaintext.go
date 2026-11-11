package rpcauth

import (
	"net"
	"os"
)

// PlaintextAllowed gates unencrypted RPC. The broad flag is a temporary manual
// compatibility override. The narrower flag accepts literal loopback IPs only;
// names are never resolved and URLs are not accepted as host values.
func PlaintextAllowed(hostOrHostPort string) bool {
	if os.Getenv("EDGE_ALLOW_PLAINTEXT_RPC") == "true" {
		return true
	}
	if os.Getenv("EDGE_ALLOW_LOOPBACK_RPC") != "true" {
		return false
	}
	host := hostOrHostPort
	if parsed, _, err := net.SplitHostPort(hostOrHostPort); err == nil {
		host = parsed
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
