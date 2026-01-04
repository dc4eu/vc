# Singapore Test Vectors

This directory contains official W3C Verifiable Credentials from Singapore issuers.
These credentials can be used to test interoperability with Singapore's digital credentials ecosystem.

## Test Vectors

### 1. Accredify Credentials (EdDSA-RDFC-2022)

These credentials use the `eddsa-rdfc-2022` cryptosuite with Ed25519 keys.

| File | Type | Status | Notes |
|------|------|--------|-------|
| `citizen_idvc.json` | CitizenIDCredential | ✅ Valid | Verifies successfully with current issuer key |
| `corporate_idvc.json` | CorporateIDCredential | ⚠️ Expired | Has expired (validUntil: 2025-11-30). May fail verification due to key rotation |

**Issuer DID:** `did:web:vc-issuer.accredify.io:organizations:9c7308e9-a770-4be8-bc0d-21d9cac585bc`

**Key Type:** Ed25519 (Ed25519VerificationKey2020 with publicKeyMultibase)

### 2. Singapore Academy of Law eApostilles (ECDSA-SD-2023)

These credentials use the `ecdsa-sd-2023` cryptosuite with ECDSA keys for selective disclosure.

| File | Type | Status | Notes |
|------|------|--------|-------|
| `enc_eapostille_1.json` | VerifiableCredential (eApostille) | Structure Valid | Contains embedded PDF content |
| `enc_eapostille_2.json` | VerifiableCredential (eApostille) | Structure Valid | Contains embedded PDF content |

**Issuer DID:** `did:web:legalisation.sal.sg`

**Key Type:** ECDSA (Multikey format)

## Cryptosuites

### eddsa-rdfc-2022

- **Standard:** W3C Data Integrity EdDSA Cryptosuite v1.0
- **Algorithm:** Ed25519
- **Canonicalization:** RDF Dataset Canonicalization (RDFC) 2022
- **Signature Encoding:** Multibase (base58-btc, 'z' prefix)

### ecdsa-sd-2023

- **Standard:** W3C ECDSA Selective Disclosure Cryptosuite v1.0
- **Algorithm:** ECDSA with P-256/P-384
- **Features:** Selective disclosure, base/derived proofs
- **Signature Encoding:** CBOR with Multibase (base64url, 'u' prefix)

## Running Tests

```bash
# Run all Singapore test vector tests
go test -tags=vc20 -v -run "TestSingapore" ./pkg/keyresolver/...

# Run only structure validation (no network required)
go test -tags=vc20 -v -run "TestSingaporeCredentials_Structure" ./pkg/keyresolver/...

# Run full verification with live did:web resolution
go test -tags=vc20 -v -run "TestSingaporeCredentials_EdDSA_DirectVerify" ./pkg/keyresolver/...

# Run benchmarks
go test -tags=vc20 -bench="BenchmarkSingapore" -benchmem ./pkg/keyresolver/...
```

## Network Requirements

Some tests require network access to contact the actual Singapore issuers:

- `https://vc-issuer.accredify.io/organizations/9c7308e9-a770-4be8-bc0d-21d9cac585bc/did.json`
- `https://legalisation.sal.sg/.well-known/did.json`

Tests that require network access will be skipped in short mode (`-short` flag).

## Known Issues

1. **Corporate ID Credential Key Rotation:** The `corporate_idvc.json` credential was signed with
   a key that may have been rotated at the issuer. The verification method ID matches, but the
   actual key bytes may differ. This demonstrates the real-world challenge of key management
   in long-lived credentials.

2. **Corporate ID Credential Expiration:** The corporate credential has expired as of
   2025-11-30T00:00:00Z.

## Credential Details

### Citizen ID Credential (citizen_idvc.json)

- **ID:** `urn:uuid:47d7e1d5-5e82-48b9-b91d-fd6e4aa78ff6`
- **Valid From:** 2025-08-25T00:00:00Z
- **Valid Until:** 2026-08-25T00:00:00Z
- **Created:** 2025-08-25T03:01:05Z
- **Subject:** Test citizen data (Tan Ah Kow)

### Corporate ID Credential (corporate_idvc.json)

- **ID:** `urn:uuid:fa1d513c-85ac-498b-85b5-96788dfb5b26`
- **Valid From:** 2025-10-30T00:00:00Z
- **Valid Until:** 2025-11-30T00:00:00Z (EXPIRED)
- **Created:** 2025-10-30T05:14:38Z
- **Subject:** Corporate representative authorization

### eApostille Credentials

- **Issuer:** Singapore Academy of Law
- **Content:** Embedded legalised documents (PDF in Base64)
- **Features:** Credential status checking, embedded renderer
