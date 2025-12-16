package pki

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func ParseX509CertificateFromFile(path string) (*x509.Certificate, []*x509.Certificate, error) {
	pemData, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, nil, err
	}

	block, rest := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, nil, errors.New("certificate decoding error")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	storage := map[int]*x509.Certificate{}
	if len(rest) > 0 {
		if err := parseChain(rest, 0, storage); err != nil {
			return nil, nil, err
		}
	}

	chain := []*x509.Certificate{}
	chain = append(chain, cert)
	for _, v := range storage {
		chain = append(chain, v)
	}

	return cert, chain, nil
}

func parseChain(rest []byte, n int, storage map[int]*x509.Certificate) error {
	n++
	block, r := pem.Decode(rest)
	if block == nil {
		return nil
	}

	if block.Type != "CERTIFICATE" {
		return errors.New("certificate type error")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	storage[n] = cert

	if len(r) > 0 {
		if err := parseChain(r, n, storage); err != nil {
			return err
		}
	}

	return nil
}

func ParseKeyFromFile(path string) (any, error) {
	pemData, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode([]byte(pemData))
	if block == nil || len(rest) > 0 {
		return nil, errors.New("failed to decode PEM block from file")
	}

	// Support multiple key formats
	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		return key, nil

	case "EC PRIVATE KEY":
		// SEC1/EC format
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		return key, nil

	case "RSA PRIVATE KEY":
		// PKCS#1 RSA format
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		return key, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

func Base64EncodeCertificate(cert *x509.Certificate) string {
	reply := base64.RawStdEncoding.EncodeToString(cert.Raw)
	return reply
}
