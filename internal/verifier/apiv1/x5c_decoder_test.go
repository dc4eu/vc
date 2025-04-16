package apiv1

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestToDecode(t *testing.T) {
	x5cList := []string{
		"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",
	}

	for i, x5c := range x5cList {
		fmt.Printf("\n=== Certificate %d ===\n", i+1)

		certDER, err := base64.StdEncoding.DecodeString(x5c)
		if err != nil {
			fmt.Printf("  [ERROR] Failed to decode x5c: %v\n", err)
			continue
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			fmt.Printf("  [ERROR] Failed to parse certificate: %v\n", err)
			continue
		}

		fmt.Printf("  Version: %d\n", cert.Version)
		fmt.Printf("  Serial Number: %s\n", cert.SerialNumber)
		fmt.Printf("  Signature Algorithm: %s\n", cert.SignatureAlgorithm)
		fmt.Printf("  Issuer: %s\n", cert.Issuer.String())
		fmt.Printf("  Subject: %s\n", cert.Subject.String())
		fmt.Printf("  Not Before: %s\n", cert.NotBefore)
		fmt.Printf("  Not After: %s\n", cert.NotAfter)
		fmt.Printf("  Is CA: %v\n", cert.IsCA)
		fmt.Printf("  Key Usage: %v\n", cert.KeyUsage)
		fmt.Printf("  Ext Key Usage: %v\n", cert.ExtKeyUsage)
		fmt.Printf("  Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm)

		fmt.Printf("  DNS Names: %v\n", cert.DNSNames)
		fmt.Printf("  Email Addresses: %v\n", cert.EmailAddresses)
		fmt.Printf("  IP Addresses: %v\n", cert.IPAddresses)
		fmt.Printf("  URIs: %v\n", cert.URIs)

		fmt.Printf("  OCSP Server: %v\n", cert.OCSPServer)
		fmt.Printf("  Issuing Certificate URL: %v\n", cert.IssuingCertificateURL)
		fmt.Printf("  CRL Distribution Points: %v\n", cert.CRLDistributionPoints)
	}
}
