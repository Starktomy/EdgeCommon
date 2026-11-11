package rpcauth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
)

// VerifiedTLSConfig verifies the peer hostname using system trust and,
// optionally, a private CA bundle. Invalid CA configuration fails closed.
func VerifiedTLSConfig(serverName string, optionalCAPath string) (*tls.Config, error) {
	if serverName == "" {
		return nil, errors.New("RPC TLS requires a server hostname")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if optionalCAPath == "" {
		return config, nil
	}
	pemData, err := os.ReadFile(optionalCAPath)
	if err != nil {
		return nil, err
	}
	if len(pemData) == 0 || len(pemData) > 1<<20 {
		return nil, errors.New("invalid RPC CA bundle size")
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, errors.New("RPC CA bundle contains no certificates")
	}
	config.RootCAs = pool
	return config, nil
}
