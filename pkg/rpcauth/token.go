// Package rpcauth authenticates service credentials exchanged with EdgeAPI.
// Signed claims identify a machine and its delegated account; the API must
// separately authorize the claimed role and requested operation.
package rpcauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	APIAudience  = "edge-api"
	Lifetime     = 2 * time.Minute
	ClockSkew    = 30 * time.Second
	MaxTokenSize = 4096
)

type Claims struct {
	Version   int    `json:"v"`
	NodeID    string `json:"nodeId"`
	Audience  string `json:"aud"`
	Type      string `json:"type"`
	UserID    int64  `json:"userId"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Nonce     string `json:"nonce"`
}

var errInvalidToken = errors.New("invalid RPC authentication token")

// Sign creates a short-lived token. It is passed directly as gRPC's token
// metadata value; callers must not wrap it in another Base64 encoding layer.
func Sign(secret string, nodeID string, role string, userID int64) (string, error) {
	return signAt(secret, nodeID, role, userID, time.Now())
}

func signAt(secret string, nodeID string, role string, userID int64, now time.Time) (string, error) {
	if len(secret) < 16 || !validNodeID(nodeID) || !validRole(role) || userID < 0 {
		return "", errInvalidToken
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	claims := Claims{
		Version: 2, NodeID: nodeID, Audience: APIAudience, Type: role, UserID: userID,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(Lifetime).Unix(),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signed := "v2." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Verify checks authenticity, validity and the expected machine/audience. A
// nonce makes issued tokens unique, but reuse within their lifetime is allowed
// for gRPC calls and streams; this function is not a single-use replay store.
func Verify(token string, secret string, nodeID string) (Claims, error) {
	return verifyAt(token, secret, nodeID, time.Now())
}

func verifyAt(token string, secret string, nodeID string, now time.Time) (Claims, error) {
	var empty Claims
	if len(token) == 0 || len(token) > MaxTokenSize || len(secret) < 16 || !validNodeID(nodeID) {
		return empty, errInvalidToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v2" || !validBase64(parts[1]) || !validBase64(parts[2]) {
		return empty, errInvalidToken
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(signature) != sha256.Size {
		return empty, errInvalidToken
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return empty, errInvalidToken
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(payload) > 2048 {
		return empty, errInvalidToken
	}
	claims, err := decodeClaims(payload)
	if err != nil || claims.Version != 2 || claims.NodeID != nodeID || claims.Audience != APIAudience ||
		!validRole(claims.Type) || claims.UserID < 0 || claims.IssuedAt <= 0 ||
		claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > int64(Lifetime/time.Second) ||
		claims.IssuedAt > now.Add(ClockSkew).Unix() || claims.ExpiresAt < now.Add(-ClockSkew).Unix() {
		return empty, errInvalidToken
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(claims.Nonce)
	if err != nil || len(nonce) != 16 || !validBase64(claims.Nonce) {
		return empty, errInvalidToken
	}
	return claims, nil
}

// Decode fields individually to reject duplicate and unknown claim names as
// well as trailing JSON, implicit numeric conversions and nested values.
func decodeClaims(payload []byte) (Claims, error) {
	var claims Claims
	decoder := json.NewDecoder(bytes.NewReader(payload))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return claims, errInvalidToken
	}
	seen := make(map[string]bool, 8)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return claims, errInvalidToken
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return claims, errInvalidToken
		}
		seen[name] = true
		var value any
		switch name {
		case "v":
			value = &claims.Version
		case "nodeId":
			value = &claims.NodeID
		case "aud":
			value = &claims.Audience
		case "type":
			value = &claims.Type
		case "userId":
			value = &claims.UserID
		case "iat":
			value = &claims.IssuedAt
		case "exp":
			value = &claims.ExpiresAt
		case "nonce":
			value = &claims.Nonce
		default:
			return claims, errInvalidToken
		}
		var raw json.RawMessage
		if err = decoder.Decode(&raw); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return claims, errInvalidToken
		}
		if err = json.Unmarshal(raw, value); err != nil {
			return claims, errInvalidToken
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 8 {
		return claims, errInvalidToken
	}
	if _, err = decoder.Token(); err != io.EOF {
		return claims, errInvalidToken
	}
	return claims, nil
}

func validNodeID(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, c := range value {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func validRole(value string) bool {
	if len(value) == 0 || len(value) > 32 {
		return false
	}
	for _, c := range value {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

func validBase64(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
