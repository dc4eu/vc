package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"
)

func TestNewIACACertManager(t *testing.T) {
	manager := NewIACACertManager()

	if manager == nil {
		t.Fatal("NewIACACertManager() returned nil")
	}
	if manager.dsCerts == nil {
		t.Error("dsCerts map is nil")
	}
}

func TestIACACertManager_GenerateIACACertificate(t *testing.T) {
	manager := NewIACACertManager()

	req := &IACACertRequest{
		Profile:            ProfileIACA,
		Country:            "SE",
		Organization:       "SUNET",
		OrganizationalUnit: "mDL",
		CommonName:         "Sweden IACA",
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(10, 0, 0),
	}

	cert, key, err := manager.GenerateIACACertificate(req)
	if err != nil {
		t.Fatalf("GenerateIACACertificate() error = %v", err)
	}

	if cert == nil {
		t.Fatal("Certificate is nil")
	}
	if key == nil {
		t.Fatal("Key is nil")
	}

	// Verify certificate properties
	if !cert.IsCA {
		t.Error("Certificate is not a CA")
	}
	if cert.Subject.Country[0] != "SE" {
		t.Errorf("Country = %v, want SE", cert.Subject.Country)
	}
	if cert.Subject.CommonName != "Sweden IACA" {
		t.Errorf("CommonName = %s, want Sweden IACA", cert.Subject.CommonName)
	}
	if cert.Subject.Organization[0] != "SUNET" {
		t.Errorf("Organization = %v, want SUNET", cert.Subject.Organization)
	}
}

func TestIACACertManager_LoadIACA(t *testing.T) {
	manager := NewIACACertManager()

	// Generate a certificate first
	req := &IACACertRequest{
		Profile:      ProfileIACA,
		Country:      "SE",
		Organization: "SUNET",
		CommonName:   "Sweden IACA",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
	}

	cert, key, err := manager.GenerateIACACertificate(req)
	if err != nil {
		t.Fatalf("GenerateIACACertificate() error = %v", err)
	}

	// Create new manager and load the certificate
	manager2 := NewIACACertManager()
	if err := manager2.LoadIACA(cert, key); err != nil {
		t.Fatalf("LoadIACA() error = %v", err)
	}

	if manager2.iacaCert != cert {
		t.Error("iacaCert not set correctly")
	}
}

func TestIACACertManager_LoadIACA_NilCert(t *testing.T) {
	manager := NewIACACertManager()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := manager.LoadIACA(nil, priv)

	if err == nil {
		t.Error("LoadIACA() should fail with nil certificate")
	}
}

func TestIACACertManager_LoadIACA_NilKey(t *testing.T) {
	manager := NewIACACertManager()

	// Generate a valid cert first
	req := &IACACertRequest{
		Profile:    ProfileIACA,
		Country:    "SE",
		CommonName: "Test",
		NotBefore:  time.Now(),
		NotAfter:   time.Now().AddDate(1, 0, 0),
	}
	cert, _, _ := manager.GenerateIACACertificate(req)

	manager2 := NewIACACertManager()
	err := manager2.LoadIACA(cert, nil)

	if err == nil {
		t.Error("LoadIACA() should fail with nil key")
	}
}

func TestIACACertManager_IssueDSCertificate(t *testing.T) {
	manager := NewIACACertManager()

	// First generate IACA
	iacaReq := &IACACertRequest{
		Profile:      ProfileIACA,
		Country:      "SE",
		Organization: "SUNET",
		CommonName:   "Sweden IACA",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
	}

	_, _, err := manager.GenerateIACACertificate(iacaReq)
	if err != nil {
		t.Fatalf("GenerateIACACertificate() error = %v", err)
	}

	// Generate DS key
	dsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Now issue DS certificate
	dsReq := &IACACertRequest{
		Profile:      ProfileDS,
		Country:      "SE",
		Organization: "SUNET",
		CommonName:   "Sweden DS",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		PublicKey:    &dsKey.PublicKey,
	}

	dsCert, err := manager.IssueDSCertificate(dsReq)
	if err != nil {
		t.Fatalf("IssueDSCertificate() error = %v", err)
	}

	if dsCert == nil {
		t.Fatal("DS Certificate is nil")
	}

	// Verify not a CA
	if dsCert.IsCA {
		t.Error("DS Certificate should not be a CA")
	}

	// Verify signed by IACA
	if err := dsCert.CheckSignatureFrom(manager.iacaCert); err != nil {
		t.Errorf("DS Certificate not signed by IACA: %v", err)
	}
}

func TestIACACertManager_IssueDSCertificate_NoIACA(t *testing.T) {
	manager := NewIACACertManager()

	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dsReq := &IACACertRequest{
		Profile:    ProfileDS,
		CommonName: "Test DS",
		PublicKey:  &dsKey.PublicKey,
	}

	_, err := manager.IssueDSCertificate(dsReq)
	if err == nil {
		t.Error("IssueDSCertificate() should fail without IACA")
	}
}

func TestIACACertManager_DScerts_Map(t *testing.T) {
	manager := NewIACACertManager()

	// Generate IACA
	iacaReq := &IACACertRequest{
		Profile:      ProfileIACA,
		Country:      "SE",
		Organization: "SUNET",
		CommonName:   "Sweden IACA",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
	}
	_, _, _ = manager.GenerateIACACertificate(iacaReq)

	// Generate DS key
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dsReq := &IACACertRequest{
		Profile:    ProfileDS,
		Country:    "SE",
		CommonName: "Stockholm DS",
		NotBefore:  time.Now(),
		NotAfter:   time.Now().AddDate(2, 0, 0),
		PublicKey:  &dsKey.PublicKey,
	}
	dsCert, _ := manager.IssueDSCertificate(dsReq)

	// Verify the dsCerts map exists and can be used
	if manager.dsCerts == nil {
		t.Fatal("dsCerts map is nil")
	}

	// Store manually
	manager.dsCerts["stockholm"] = dsCert
	retrieved := manager.dsCerts["stockholm"]

	if retrieved == nil {
		t.Fatal("Retrieved certificate is nil")
	}
	if retrieved != dsCert {
		t.Error("Retrieved certificate doesn't match stored certificate")
	}
}

func TestIACACertManager_DScerts_NotFound(t *testing.T) {
	manager := NewIACACertManager()

	retrieved := manager.dsCerts["nonexistent"]
	if retrieved != nil {
		t.Error("Should return nil for nonexistent ID")
	}
}

func TestIACAProfile_Constants(t *testing.T) {
	if ProfileIACA != "IACA" {
		t.Errorf("ProfileIACA = %s, want IACA", ProfileIACA)
	}
	if ProfileDS != "DS" {
		t.Errorf("ProfileDS = %s, want DS", ProfileDS)
	}
}

func TestCertificateChainValidation(t *testing.T) {
	manager := NewIACACertManager()

	// Generate IACA
	iacaReq := &IACACertRequest{
		Profile:      ProfileIACA,
		Country:      "SE",
		Organization: "SUNET",
		CommonName:   "Sweden IACA",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
	}
	iacaCert, _, _ := manager.GenerateIACACertificate(iacaReq)

	// Generate DS
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dsReq := &IACACertRequest{
		Profile:    ProfileDS,
		Country:    "SE",
		CommonName: "Sweden DS",
		NotBefore:  time.Now(),
		NotAfter:   time.Now().AddDate(2, 0, 0),
		PublicKey:  &dsKey.PublicKey,
	}
	dsCert, _ := manager.IssueDSCertificate(dsReq)

	// Validate chain
	if err := dsCert.CheckSignatureFrom(iacaCert); err != nil {
		t.Errorf("Certificate chain validation failed: %v", err)
	}
}

func TestIACACertRequest_WithCRLAndOCSP(t *testing.T) {
	manager := NewIACACertManager()

	req := &IACACertRequest{
		Profile:            ProfileIACA,
		Country:            "SE",
		Organization:       "SUNET",
		CommonName:         "Sweden IACA",
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(10, 0, 0),
		CRLDistributionURL: "http://crl.sunet.se/mdl.crl",
		OCSPResponderURL:   "http://ocsp.sunet.se/",
	}

	cert, _, err := manager.GenerateIACACertificate(req)
	if err != nil {
		t.Fatalf("GenerateIACACertificate() error = %v", err)
	}

	// Verify CRL and OCSP are set
	if len(cert.CRLDistributionPoints) == 0 {
		t.Error("CRL distribution points not set")
	} else if cert.CRLDistributionPoints[0] != req.CRLDistributionURL {
		t.Errorf("CRL URL = %s, want %s", cert.CRLDistributionPoints[0], req.CRLDistributionURL)
	}

	if len(cert.OCSPServer) == 0 {
		t.Error("OCSP server not set")
	} else if cert.OCSPServer[0] != req.OCSPResponderURL {
		t.Errorf("OCSP URL = %s, want %s", cert.OCSPServer[0], req.OCSPResponderURL)
	}
}

func TestIACACertManager_MultipleDSCertificates(t *testing.T) {
	manager := NewIACACertManager()

	// Generate IACA
	iacaReq := &IACACertRequest{
		Profile:      ProfileIACA,
		Country:      "SE",
		Organization: "SUNET",
		CommonName:   "Sweden IACA",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
	}
	_, _, _ = manager.GenerateIACACertificate(iacaReq)

	// Issue multiple DS certificates for different regions
	regions := []string{"Stockholm", "Göteborg", "Malmö", "Uppsala"}

	for _, region := range regions {
		dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		dsReq := &IACACertRequest{
			Profile:    ProfileDS,
			Country:    "SE",
			CommonName: region + " DS",
			NotBefore:  time.Now(),
			NotAfter:   time.Now().AddDate(2, 0, 0),
			PublicKey:  &dsKey.PublicKey,
		}
		dsCert, err := manager.IssueDSCertificate(dsReq)
		if err != nil {
			t.Fatalf("IssueDSCertificate(%s) error = %v", region, err)
		}
		manager.dsCerts[region] = dsCert
	}

	// Verify all certificates are retrievable
	for _, region := range regions {
		cert := manager.dsCerts[region]
		if cert == nil {
			t.Errorf("DS certificate for %s not found", region)
		}
	}
}

func TestOIDConstants(t *testing.T) {
	// Verify the OID for mDL Document Signer is defined
	if OIDMDLDocumentSigner == nil {
		t.Error("OIDMDLDocumentSigner is nil")
	}
	// Per ISO 18013-5: 1.0.18013.5.1.6 is the DS extended key usage OID
	expected := "1.0.18013.5.1.6"
	actual := OIDMDLDocumentSigner.String()
	if actual != expected {
		t.Errorf("OIDMDLDocumentSigner = %s, want %s", actual, expected)
	}
}

func TestIACACertManager_GetIACACertificate(t *testing.T) {
	manager := NewIACACertManager()

	// Before generating, should return nil
	cert := manager.GetIACACertificate()
	if cert != nil {
		t.Error("GetIACACertificate() should return nil before IACA is generated")
	}

	// Generate IACA
	req := &IACACertRequest{
		Profile:      ProfileIACA,
		Country:      "SE",
		Organization: "SUNET",
		CommonName:   "Sweden IACA",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
	}
	_, _, _ = manager.GenerateIACACertificate(req)

	// Now should return the certificate
	cert = manager.GetIACACertificate()
	if cert == nil {
		t.Error("GetIACACertificate() should return certificate after generation")
	}
}

func TestIACACertManager_GetCertificateChain(t *testing.T) {
	manager := NewIACACertManager()

	// Generate IACA
	iacaReq := &IACACertRequest{
		Profile:      ProfileIACA,
		Country:      "SE",
		Organization: "SUNET",
		CommonName:   "Sweden IACA",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
	}
	_, _, _ = manager.GenerateIACACertificate(iacaReq)

	// Generate DS
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dsReq := &IACACertRequest{
		Profile:    ProfileDS,
		Country:    "SE",
		CommonName: "Sweden DS",
		NotBefore:  time.Now(),
		NotAfter:   time.Now().AddDate(2, 0, 0),
		PublicKey:  &dsKey.PublicKey,
	}
	dsCert, _ := manager.IssueDSCertificate(dsReq)

	// Get chain
	chain := manager.GetCertificateChain(dsCert)
	if len(chain) != 2 {
		t.Errorf("Chain length = %d, want 2", len(chain))
	}
}

func TestIACACertManager_ValidateDSCertificate(t *testing.T) {
	manager := NewIACACertManager()

	// Generate IACA
	iacaReq := &IACACertRequest{
		Profile:      ProfileIACA,
		Country:      "SE",
		Organization: "SUNET",
		CommonName:   "Sweden IACA",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
	}
	_, _, _ = manager.GenerateIACACertificate(iacaReq)

	// Generate DS
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dsReq := &IACACertRequest{
		Profile:    ProfileDS,
		Country:    "SE",
		CommonName: "Sweden DS",
		NotBefore:  time.Now(),
		NotAfter:   time.Now().AddDate(2, 0, 0),
		PublicKey:  &dsKey.PublicKey,
	}
	dsCert, _ := manager.IssueDSCertificate(dsReq)

	// Validate
	err := manager.ValidateDSCertificate(dsCert)
	if err != nil {
		t.Errorf("ValidateDSCertificate() error = %v", err)
	}
}

func TestIACATrustList(t *testing.T) {
	// Create manager and IACA
	manager := NewIACACertManager()
	iacaReq := &IACACertRequest{
		Profile:      ProfileIACA,
		Country:      "SE",
		Organization: "SUNET",
		CommonName:   "Sweden IACA",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
	}
	iacaCert, _, _ := manager.GenerateIACACertificate(iacaReq)

	// Create trust list
	trustList := NewIACATrustList()
	if trustList == nil {
		t.Fatal("NewIACATrustList() returned nil")
	}

	// Add trusted IACA
	err := trustList.AddTrustedIACA(iacaCert)
	if err != nil {
		t.Fatalf("AddTrustedIACA() error = %v", err)
	}

	// Check if trusted (pass as chain)
	chain := []*x509.Certificate{iacaCert}
	err = trustList.IsTrusted(chain)
	if err != nil {
		t.Errorf("IsTrusted() error = %v", err)
	}

	// Get trusted issuers
	issuers := trustList.GetTrustedIssuers()
	if len(issuers) != 1 {
		t.Errorf("GetTrustedIssuers() count = %d, want 1", len(issuers))
	}

	// Get trust info
	infos := trustList.GetTrustInfo()
	if len(infos) != 1 {
		t.Errorf("GetTrustInfo() count = %d, want 1", len(infos))
	}
	if infos[0].Country != "SE" {
		t.Errorf("TrustInfo Country = %s, want SE", infos[0].Country)
	}
}

func TestIACATrustList_UntrustedCert(t *testing.T) {
	trustList := NewIACATrustList()

	// Create untrusted IACA
	manager := NewIACACertManager()
	iacaReq := &IACACertRequest{
		Profile:      ProfileIACA,
		Country:      "FI",
		Organization: "Traficom",
		CommonName:   "Finland IACA",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
	}
	untrustedCert, _, _ := manager.GenerateIACACertificate(iacaReq)

	// Should not be trusted (returns error for untrusted)
	chain := []*x509.Certificate{untrustedCert}
	err := trustList.IsTrusted(chain)
	if err == nil {
		t.Error("IsTrusted() should return error for untrusted certificate")
	}
}

func TestExportCertificateChainPEM(t *testing.T) {
	manager := NewIACACertManager()

	// Generate IACA
	iacaReq := &IACACertRequest{
		Profile:      ProfileIACA,
		Country:      "SE",
		Organization: "SUNET",
		CommonName:   "Sweden IACA",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
	}
	iacaCert, _, _ := manager.GenerateIACACertificate(iacaReq)

	// Export to PEM
	chain := []*x509.Certificate{iacaCert}
	pem := ExportCertificateChainPEM(chain)

	if len(pem) == 0 {
		t.Error("ExportCertificateChainPEM() returned empty")
	}

	// Should contain PEM header
	if !bytes.Contains(pem, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Error("PEM should contain certificate header")
	}
}
