package rpcauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const testSecret = "security-test-secret-at-least-32-bytes"

func signedPayload(payload []byte) string {
	signed := "v2." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(testSecret))
	_, _ = mac.Write([]byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestTokenRoundTripAndNonce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	token, err := signAt(testSecret, "node-1", "node", 7, now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifyAt(token, testSecret, "node-1", now)
	if err != nil || claims.Type != "node" || claims.UserID != 7 || claims.Audience != APIAudience || claims.Version != 2 {
		t.Fatalf("claims=%+v err=%v", claims, err)
	}
	other, err := signAt(testSecret, "node-1", "node", 7, now)
	if err != nil || other == token {
		t.Fatalf("tokens must have independent random nonces: %v", err)
	}
}

func TestTokenRejectsTamperingAndWrongIdentity(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	token, err := signAt(testSecret, "node-1", "user", 42, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	tampered := "v2." + base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(payload), `"userId":42`, `"userId":43`, 1))) + "." + parts[2]
	for _, test := range []struct{ token, secret, node string }{
		{tampered, testSecret, "node-1"},
		{token, testSecret, "other-node"},
		{token, "a-different-secret-at-least-32-bytes", "node-1"},
		{strings.Replace(token, "v2.", "v1.", 1), testSecret, "node-1"},
		{token + ".extra", testSecret, "node-1"},
		{strings.Repeat("a", MaxTokenSize+1), testSecret, "node-1"},
	} {
		if _, err := verifyAt(test.token, test.secret, test.node, now); err == nil {
			t.Fatal("tampered or incorrectly bound token was accepted")
		}
	}
}

func TestTokenStrictClaimsAndLifetime(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	valid, err := signAt(testSecret, "node-1", "node", 7, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(valid, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var original Claims
	if err = json.Unmarshal(payload, &original); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*Claims)
	}{
		{"wrong audience", func(c *Claims) { c.Audience = "another-api" }},
		{"wrong node", func(c *Claims) { c.NodeID = "node-2" }},
		{"wrong version", func(c *Claims) { c.Version = 1 }},
		{"negative identity", func(c *Claims) { c.UserID = -1 }},
		{"missing nonce", func(c *Claims) { c.Nonce = "" }},
		{"invalid nonce", func(c *Claims) { c.Nonce = strings.Repeat("a", 16) }},
		{"long lifetime", func(c *Claims) { c.ExpiresAt = c.IssuedAt + 121 }},
		{"expired", func(c *Claims) { c.IssuedAt -= 151; c.ExpiresAt -= 151 }},
		{"future issued", func(c *Claims) { c.IssuedAt += 31; c.ExpiresAt += 31 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := original
			test.change(&claims)
			data, _ := json.Marshal(claims)
			if _, err := verifyAt(signedPayload(data), testSecret, "node-1", now); err == nil {
				t.Fatal("invalid signed claims were accepted")
			}
		})
	}
	for _, data := range []string{
		string(payload[:len(payload)-1]) + `,"type":"admin"}`,
		string(payload[:len(payload)-1]) + `,"unknown":true}`,
		string(payload) + `{}`,
		strings.Replace(string(payload), `"userId":7`, `"userId":null`, 1),
		strings.Replace(string(payload), `"userId":7`, `"userId":7.0`, 1),
		strings.Replace(string(payload), `"userId":7,`, ``, 1),
	} {
		if _, err := verifyAt(signedPayload([]byte(data)), testSecret, "node-1", now); err == nil {
			t.Fatalf("noncanonical claims accepted: %s", data)
		}
	}
}
