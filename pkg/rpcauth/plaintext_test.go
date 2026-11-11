package rpcauth

import "testing"

func TestPlaintextRPCRequiresExplicitScope(t *testing.T) {
	t.Setenv("EDGE_ALLOW_PLAINTEXT_RPC", "")
	t.Setenv("EDGE_ALLOW_LOOPBACK_RPC", "")
	if PlaintextAllowed("127.0.0.1:8001") {
		t.Fatal("plaintext enabled without an explicit flag")
	}
	t.Setenv("EDGE_ALLOW_LOOPBACK_RPC", "true")
	for _, host := range []string{"127.0.0.1", "127.255.255.254", "127.0.0.1:8001", "::1", "[::1]:8001", "::ffff:127.0.0.1"} {
		if !PlaintextAllowed(host) {
			t.Fatalf("literal loopback %q rejected", host)
		}
	}
	for _, host := range []string{"", "localhost", "localhost:8001", "api.example.test", "api.example.test:8001", ":8001", "0.0.0.0", "0.0.0.0:8001", "::", "[::]:8001", "192.0.2.1", "192.0.2.1:8001", "::ffff:192.0.2.1", "127.0.0.1.example.test:8001", "http://127.0.0.1:8001", "http://[::1]:8001", "127.1", "2130706433", " 127.0.0.1", "[::1%lo]:8001"} {
		if PlaintextAllowed(host) {
			t.Fatalf("non-literal-loopback %q enabled plaintext", host)
		}
	}
	t.Setenv("EDGE_ALLOW_LOOPBACK_RPC", "TRUE")
	if PlaintextAllowed("127.0.0.1") {
		t.Fatal("loopback flag must be exactly true")
	}
	t.Setenv("EDGE_ALLOW_PLAINTEXT_RPC", "true")
	if !PlaintextAllowed("192.0.2.1:8001") {
		t.Fatal("explicit broad compatibility override no longer works")
	}
}
