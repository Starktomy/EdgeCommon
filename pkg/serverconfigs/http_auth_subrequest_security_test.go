package serverconfigs

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func authSecurityRequest(t *testing.T, ctx context.Context) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://tenant.example.test/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer example-private-token")
	req.Header.Set("Cookie", "session=example-private-cookie")
	req.Header.Set("X-Example", "unchanged")
	return req
}

func authSecurityMethod(t *testing.T, target string) *HTTPAuthSubRequestMethod {
	t.Helper()
	method := NewHTTPAuthSubRequestMethod()
	if err := method.Init(map[string]any{"url": target, "method": http.MethodGet}); err != nil {
		t.Fatal(err)
	}
	if method.httpClient != nil {
		t.Cleanup(method.httpClient.CloseIdleConnections)
	}
	return method
}

func TestSecurityAuthSubrequestVerifiesTLSAndPrivateCA(t *testing.T) {
	t.Setenv("EDGE_AUTH_CA_FILE", "")
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") == "" || req.Header.Get("Cookie") == "" {
			t.Error("configured authentication target did not receive authentication headers")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	method := authSecurityMethod(t, server.URL)
	transport := method.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("authentication transport disabled verification or allows obsolete TLS")
	}
	if ok, _, _, err := method.Filter(authSecurityRequest(t, context.Background()), nil, func(s string) string { return s }); err == nil || ok {
		t.Fatal("untrusted authentication certificate was accepted")
	}
	caFile := filepath.Join(t.TempDir(), "auth-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDGE_AUTH_CA_FILE", caFile)
	trusted := authSecurityMethod(t, server.URL)
	if ok, _, _, err := trusted.Filter(authSecurityRequest(t, context.Background()), nil, func(s string) string { return s }); err != nil || !ok {
		t.Fatalf("explicit private CA rejected trusted target: ok=%v err=%v", ok, err)
	}
	t.Setenv("EDGE_AUTH_CA_FILE", filepath.Join(t.TempDir(), "missing.pem"))
	if err := NewHTTPAuthSubRequestMethod().Init(map[string]any{"url": server.URL}); err == nil {
		t.Fatal("missing explicit CA silently fell back to default trust")
	}
	if err := os.WriteFile(caFile, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDGE_AUTH_CA_FILE", caFile)
	if err := NewHTTPAuthSubRequestMethod().Init(map[string]any{"url": server.URL}); err == nil {
		t.Fatal("invalid explicit CA silently fell back to default trust")
	}
}

func TestSecurityAuthSubrequestNeverRedirectsSecretsAcrossOrigins(t *testing.T) {
	t.Setenv("EDGE_AUTH_CA_FILE", "")
	var externalRequests atomic.Int64
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		externalRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer external.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, external.URL, http.StatusFound)
	}))
	defer origin.Close()
	method := authSecurityMethod(t, origin.URL)
	if ok, _, _, err := method.Filter(authSecurityRequest(t, context.Background()), nil, func(s string) string { return s }); err == nil || ok {
		t.Fatal("cross-origin redirect became a successful authentication")
	}
	if externalRequests.Load() != 0 {
		t.Fatal("redirect forwarded the user's headers to an unconfigured target")
	}
	// Formatters may vary a path/query, but must not change the configured
	// authentication authority and forward private headers to another host.
	if ok, _, _, err := method.Filter(authSecurityRequest(t, context.Background()), nil, func(string) string { return external.URL }); err == nil || ok {
		t.Fatal("formatter changed the configured authentication origin")
	}
	if externalRequests.Load() != 0 {
		t.Fatal("formatter sent a request to an unconfigured origin")
	}
	tlsOrigin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, external.URL, http.StatusFound)
	}))
	defer tlsOrigin.Close()
	caFile := filepath.Join(t.TempDir(), "redirect-auth-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsOrigin.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDGE_AUTH_CA_FILE", caFile)
	secureMethod := authSecurityMethod(t, tlsOrigin.URL)
	if ok, _, _, err := secureMethod.Filter(authSecurityRequest(t, context.Background()), nil, func(s string) string { return s }); err == nil || ok {
		t.Fatal("HTTPS-to-HTTP redirect became successful authentication")
	}
	if externalRequests.Load() != 0 {
		t.Fatal("HTTPS-to-HTTP redirect forwarded private headers")
	}
}

func TestSecurityAuthSubrequestPropagatesCancellationAndClonesHeaders(t *testing.T) {
	t.Setenv("EDGE_AUTH_CA_FILE", "")
	started, canceled := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		close(started)
		<-req.Context().Done()
		close(canceled)
	}))
	defer server.Close()
	method := authSecurityMethod(t, server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, _, _, err := method.Filter(authSecurityRequest(t, ctx), nil, func(s string) string { return s })
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("authentication subrequest never started")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("caller cancellation did not cancel authentication: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("authentication ignored caller cancellation")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("remote authentication handler did not see cancellation")
	}

	local := authSecurityMethod(t, "/auth")
	input := authSecurityRequest(t, context.Background())
	_, _, _, err := local.Filter(input, func(req *http.Request) (int, error) {
		req.Header["X-Example"][0] = "modified by authentication"
		req.Header.Set("Authorization", "replacement")
		if req.Context() != input.Context() {
			t.Error("local subrequest lost the caller context")
		}
		return http.StatusNoContent, nil
	}, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	if input.Header.Get("X-Example") != "unchanged" || input.Header.Get("Authorization") != "Bearer example-private-token" {
		t.Fatal("authentication header mutation changed the original request")
	}
}
