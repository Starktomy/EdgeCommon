//go:build !plus

package serverconfigs

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityEnabledAuthPolicyFailsClosedWhenInvalid(t *testing.T) {
	t.Setenv("EDGE_AUTH_CA_FILE", "/missing/explicit-auth-ca.pem")
	for _, policy := range []*HTTPAuthPolicy{
		{IsOn: true, Type: "unknown-auth-method"},
		{IsOn: true, Type: HTTPAuthTypeBasicAuth, Params: map[string]any{"users": "invalid-list"}},
		{IsOn: true, Type: HTTPAuthTypeSubRequest, Params: map[string]any{"url": "https://auth.example.test/check"}},
	} {
		if err := policy.Init(); err == nil {
			t.Fatal("malformed authentication policy initialized successfully")
		}
		req := httptest.NewRequest(http.MethodGet, "https://tenant.example.test/private", nil)
		if !policy.MatchRequest(req) {
			t.Fatal("enabled invalid policy was skipped by the Node's match gate")
		}
		if ok, _, _, err := policy.Filter(req, nil, func(s string) string { return s }); ok || err == nil {
			t.Fatal("enabled invalid policy authorized a request")
		}
	}
	policy := &HTTPAuthPolicy{IsOn: true, Type: HTTPAuthTypeBasicAuth}
	req := httptest.NewRequest(http.MethodGet, "https://tenant.example.test/private", nil)
	if !policy.MatchRequest(req) {
		t.Fatal("enabled uninitialized policy was skipped")
	}
	if ok, _, _, err := policy.Filter(req, nil, nil); ok || err == nil {
		t.Fatal("enabled uninitialized policy authorized a request")
	}
}

func TestSecurityDisabledAuthPolicyKeepsNoAuthBehavior(t *testing.T) {
	for _, policy := range []*HTTPAuthPolicy{{}, {IsOn: false, Type: "unknown-auth-method"}} {
		_ = policy.Init()
		req := httptest.NewRequest(http.MethodGet, "https://tenant.example.test/public", nil)
		if policy.MatchRequest(req) {
			t.Fatal("disabled policy unexpectedly matched a request")
		}
		if ok, _, _, err := policy.Filter(req, nil, nil); !ok || err != nil {
			t.Fatalf("disabled policy changed no-auth behavior: ok=%v err=%v", ok, err)
		}
	}
}

func TestSecurityAuthPolicyReinitializationCannotKeepOldMethod(t *testing.T) {
	policy := &HTTPAuthPolicy{IsOn: true, Type: HTTPAuthTypeBasicAuth, Params: map[string]any{
		"users": []map[string]string{{"username": "alice", "password": "example-password"}},
	}}
	if err := policy.Init(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://tenant.example.test/private", nil)
	req.SetBasicAuth("alice", "example-password")
	if ok, _, _, err := policy.Filter(req, nil, nil); !ok || err != nil {
		t.Fatal("valid basic policy rejected its configured credentials")
	}
	policy.Type = "unknown-auth-method"
	if err := policy.Init(); err == nil {
		t.Fatal("unknown replacement policy initialized")
	}
	if !policy.MatchRequest(req) {
		t.Fatal("failed replacement policy was skipped")
	}
	if ok, _, _, err := policy.Filter(req, nil, nil); ok || err == nil {
		t.Fatal("failed replacement kept authorizing with the old method")
	}
}

func TestSecurityMalformedAuthReferencesFailInitialization(t *testing.T) {
	for _, config := range []*HTTPAuthConfig{
		{IsOn: true, PolicyRefs: []*HTTPAuthPolicyRef{nil}},
		{IsOn: true, PolicyRefs: []*HTTPAuthPolicyRef{{IsOn: true, AuthPolicyId: 42}}},
	} {
		if err := config.Init(); err == nil {
			t.Fatal("enabled authentication with a missing policy was accepted")
		}
	}
	if err := (&HTTPAuthPolicyRef{IsOn: false}).Init(); err != nil {
		t.Fatalf("disabled empty reference must remain optional: %v", err)
	}
}
