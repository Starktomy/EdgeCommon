package rpcauth

import (
	"crypto/tls"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifiedTLSConfigChecksPeerIdentity(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	request := func(config *tls.Config) error {
		transport := &http.Transport{TLSClientConfig: config}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		resp, err := client.Get(server.URL)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	config, err := VerifiedTLSConfig(u.Hostname(), "")
	if err != nil {
		t.Fatal(err)
	}
	if request(config) == nil {
		t.Fatal("untrusted certificate was accepted")
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	config, err = VerifiedTLSConfig(u.Hostname(), caFile)
	if err != nil || config.InsecureSkipVerify || config.MinVersion < tls.VersionTLS12 {
		t.Fatalf("invalid verified TLS configuration: %v", err)
	}
	if err := request(config); err != nil {
		t.Fatalf("trusted private certificate was rejected: %v", err)
	}
	config, err = VerifiedTLSConfig("wrong.example", caFile)
	if err != nil {
		t.Fatal(err)
	}
	if request(config) == nil {
		t.Fatal("trusted certificate for another hostname was accepted")
	}
	if _, err := VerifiedTLSConfig("", caFile); err == nil {
		t.Fatal("missing peer hostname was accepted")
	}
	if err = os.WriteFile(caFile, []byte("invalid PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifiedTLSConfig(u.Hostname(), caFile); err == nil {
		t.Fatal("invalid private CA bundle was accepted")
	}
}
