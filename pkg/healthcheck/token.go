// Package healthcheck authenticates API-to-node HTTP health probes.
package healthcheck

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const tokenDomain = "goedge/http-healthcheck/v1"
const tokenLifetime = 60 * time.Second
const maxTokenLength = 4096

var ErrInvalidToken = errors.New("invalid health check token")

type claims struct {
	NodeID    string `json:"node"`
	Method    string `json:"method"`
	Host      string `json:"host"`
	URI       string `json:"uri"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Nonce     string `json:"nonce"`
	OnlyBasic bool   `json:"basic"`
	AccessLog bool   `json:"log"`
}

// Sign binds a short-lived, independently authenticated token to this request.
func Sign(nodeID, secret string, req *http.Request, onlyBasic, accessLog bool) (string, error) {
	return signAt(nodeID, secret, req, onlyBasic, accessLog, time.Now())
}

// Verify checks identity, signature, request binding and expiration. A receiver
// should additionally reject tokens it has already accepted during the window.
func Verify(token, nodeID, secret string, req *http.Request) (bool, bool, error) {
	return verifyAt(token, nodeID, secret, req, time.Now())
}

func requestBinding(req *http.Request) (string, string, error) {
	if req == nil || req.URL == nil || (req.Method != http.MethodGet && req.Method != http.MethodHead) || req.ContentLength != 0 || (req.Body != nil && req.Body != http.NoBody) {
		return "", "", ErrInvalidToken
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host = strings.ToLower(host)
	uri := req.URL.RequestURI()
	if host == "" || strings.ContainsAny(host, "\r\n\x00") || len(uri) > 2048 {
		return "", "", ErrInvalidToken
	}
	return host, uri, nil
}

func signAt(nodeID, secret string, req *http.Request, onlyBasic, accessLog bool, now time.Time) (string, error) {
	if nodeID == "" || secret == "" {
		return "", ErrInvalidToken
	}
	host, uri, err := requestBinding(req)
	if err != nil {
		return "", err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims{
		NodeID: nodeID, Method: req.Method, Host: host, URI: uri,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(tokenLifetime).Unix(),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), OnlyBasic: onlyBasic, AccessLog: accessLog,
	})
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(tokenDomain + "\x00" + encoded))
	token := "v1." + encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if len(token) > maxTokenLength {
		return "", ErrInvalidToken
	}
	return token, nil
}

func verifyAt(token, nodeID, secret string, req *http.Request, now time.Time) (bool, bool, error) {
	if nodeID == "" || secret == "" || len(token) > maxTokenLength {
		return false, false, ErrInvalidToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return false, false, ErrInvalidToken
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != sha256.Size {
		return false, false, ErrInvalidToken
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(tokenDomain + "\x00" + parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return false, false, ErrInvalidToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false, false, ErrInvalidToken
	}
	var signed claims
	if err = json.Unmarshal(payload, &signed); err != nil {
		return false, false, ErrInvalidToken
	}
	host, uri, err := requestBinding(req)
	if err != nil || signed.NodeID != nodeID || signed.Method != req.Method || signed.Host != host || signed.URI != uri {
		return false, false, ErrInvalidToken
	}
	if signed.IssuedAt <= 0 || signed.ExpiresAt-signed.IssuedAt != int64(tokenLifetime/time.Second) || signed.IssuedAt > now.Unix()+5 || signed.ExpiresAt < now.Unix() {
		return false, false, ErrInvalidToken
	}
	nonce, err := base64.RawURLEncoding.DecodeString(signed.Nonce)
	if err != nil || len(nonce) != 16 {
		return false, false, ErrInvalidToken
	}
	return signed.OnlyBasic, signed.AccessLog, nil
}
