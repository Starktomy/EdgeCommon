package healthcheck

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSignedProbeBindsIdentityRequestFlagsAndLifetime(t *testing.T) {
	when := time.Unix(1800000000, 0)
	req, err := http.NewRequest(http.MethodGet, "http://NODE.EXAMPLE:8080/check?mode=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signAt("node-1", "node-secret", req, true, false, when)
	if err != nil {
		t.Fatal(err)
	}
	basic, accessLog, err := verifyAt(token, "node-1", "node-secret", req, when.Add(30*time.Second))
	if err != nil || !basic || accessLog {
		t.Fatalf("verify = %t %t %v", basic, accessLog, err)
	}
	for _, tc := range []struct {
		name, node, secret, rawURL, method string
		at                                 time.Time
	}{
		{"wrong-node", "node-2", "node-secret", req.URL.String(), http.MethodGet, when},
		{"wrong-secret", "node-1", "wrong", req.URL.String(), http.MethodGet, when},
		{"wrong-uri", "node-1", "node-secret", "http://node.example:8080/check?mode=2", http.MethodGet, when},
		{"wrong-host", "node-1", "node-secret", "http://another.example:8080/check?mode=1", http.MethodGet, when},
		{"wrong-method", "node-1", "node-secret", req.URL.String(), http.MethodHead, when},
		{"expired", "node-1", "node-secret", req.URL.String(), http.MethodGet, when.Add(61 * time.Second)},
		{"future", "node-1", "node-secret", req.URL.String(), http.MethodGet, when.Add(-6 * time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate, _ := http.NewRequest(tc.method, tc.rawURL, nil)
			if _, _, err := verifyAt(token, tc.node, tc.secret, candidate, tc.at); err == nil {
				t.Fatal("accepted mismatched token")
			}
		})
	}
	parts := strings.Split(token, ".")
	parts[1] = "e30"
	if _, _, err := verifyAt(strings.Join(parts, "."), "node-1", "node-secret", req, when); err == nil {
		t.Fatal("accepted tampered claims")
	}
	if _, _, err := verifyAt("eyJvbmx5QmFzaWNSZXF1ZXN0Ijp0cnVlfQ==", "node-1", "node-secret", req, when); err == nil {
		t.Fatal("accepted legacy base64 header")
	}
	if _, err := Sign("node-1", "", req, false, false); err == nil {
		t.Fatal("empty signing secret accepted")
	}
	body, _ := http.NewRequest(http.MethodGet, req.URL.String(), strings.NewReader("entity"))
	if _, err := Sign("node-1", "node-secret", body, true, false); err == nil {
		t.Fatal("probe body accepted")
	}
}
