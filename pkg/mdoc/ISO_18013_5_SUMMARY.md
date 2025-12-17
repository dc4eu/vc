# ISO/IEC 18013-5:2021 - Mobile Driving Licence (mDL) Standard

## Overview

ISO/IEC 18013-5:2021 defines the interface and implementation for Mobile Driving Licences (mDLs) - digital versions of physical driving licences stored on mobile devices.

## Document Type & Namespace

- **DocType**: `org.iso.18013.5.1.mDL`
- **Namespace**: `org.iso.18013.5.1`

## Data Elements

### Mandatory Elements

| Identifier | Meaning | Encoding |
|------------|---------|----------|
| `family_name` | Family name | tstr (max 150 chars, Latin1) |
| `given_name` | Given names | tstr (max 150 chars, Latin1) |
| `birth_date` | Date of birth | full-date |
| `issue_date` | Date of issue | tdate or full-date |
| `expiry_date` | Date of expiry | tdate or full-date |
| `issuing_country` | Issuing country | tstr (ISO 3166-1 alpha-2) |
| `issuing_authority` | Issuing authority | tstr (max 150 chars) |
| `document_number` | Licence number | tstr (max 150 chars) |
| `portrait` | Portrait of mDL holder | bstr (JPEG/JPEG2000) |
| `driving_privileges` | Vehicle categories/restrictions | See 7.2.4 |
| `un_distinguishing_sign` | UN distinguishing sign | tstr |

### Optional Elements

| Identifier | Meaning | Encoding |
|------------|---------|----------|
| `administrative_number` | Administrative number | tstr |
| `sex` | Sex | uint (ISO/IEC 5218) |
| `height` | Height in cm | uint |
| `weight` | Weight in kg | uint |
| `eye_colour` | Eye colour | tstr |
| `hair_colour` | Hair colour | tstr |
| `birth_place` | Place of birth | tstr |
| `resident_address` | Permanent residence | tstr |
| `portrait_capture_date` | Portrait timestamp | tdate |
| `age_in_years` | Age in years | uint |
| `age_birth_year` | Birth year | uint |
| `age_over_NN` | Age attestation (e.g., age_over_21) | bool |
| `issuing_jurisdiction` | Issuing jurisdiction | tstr (ISO 3166-2) |
| `nationality` | Nationality | tstr (ISO 3166-1 alpha-2) |
| `resident_city` | Resident city | tstr |
| `resident_state` | Resident state/province | tstr |
| `resident_postal_code` | Postal code | tstr |
| `resident_country` | Resident country | tstr |
| `biometric_template_xx` | Biometric template | bstr |
| `family_name_national_character` | Family name (UTF-8) | tstr |
| `given_name_national_character` | Given name (UTF-8) | tstr |
| `signature_usual_mark` | Signature image | bstr |

## Data Retrieval Methods

### Device Retrieval
Direct communication between mDL and mDL reader.

**Transmission Technologies:**
- **BLE (Bluetooth Low Energy)**: Primary method, supports central client and peripheral server modes
- **NFC**: Near Field Communication using ISO/IEC 7816-4 APDUs
- **Wi-Fi Aware**: For higher bandwidth transfers

**Device Engagement:**
- QR Code or NFC for initiating connection
- Contains ephemeral device key (`EDeviceKey`)
- Supported transfer methods and options

### Server Retrieval
Communication via issuing authority infrastructure.

**Methods:**
- **WebAPI**: JSON-based request/response with JWT
- **OIDC**: OpenID Connect flow

## Security Mechanisms (Clause 9)

### Security Goals

| Goal | Device Retrieval | Server Retrieval |
|------|------------------|------------------|
| Protection against forgery | Issuer data authentication | JWS |
| Protection against cloning | mdoc authentication | mdoc authentication |
| Protection against eavesdropping | Session encryption | TLS |
| Protection against unauthorized access | Device engagement + mdoc reader auth | TLS client auth |

### Session Encryption (9.1.1)

- ECDH key agreement using ephemeral keys from both mDL and mDL reader
- Session keys derived using HKDF with SHA-256
- AES-256-GCM for encryption
- Separate keys for mDL→reader and reader→mDL directions

### Issuer Data Authentication (9.1.2)

- **Mobile Security Object (MSO)**: Contains digests of all data elements
- **COSE_Sign1**: Signed by Document Signer (DS) certificate
- Digest algorithm: SHA-256 or SHA-512

**MSO Structure:**
```cddl
MobileSecurityObject = {
  "version": tstr,
  "digestAlgorithm": tstr,
  "valueDigests": ValueDigests,
  "deviceKeyInfo": DeviceKeyInfo,
  "docType": DocType,
  "validityInfo": ValidityInfo
}
```

### mdoc Authentication (9.1.3)

- Device signs session transcript using device key
- Proves mDL is not cloned (key never leaves device)
- Uses ECDSA or MAC (with HMAC-SHA-256)

### mdoc Reader Authentication (9.1.4) - Optional

- Reader presents certificate chain
- Signs `ReaderAuthentication` structure
- mDL can restrict data access based on reader identity

## Supported Cryptographic Algorithms

### Elliptic Curves (9.1.5.2)

| Curve | Usage |
|-------|-------|
| P-256 | ECDH/ECDSA |
| P-384 | ECDH/ECDSA |
| P-521 | ECDH/ECDSA |
| brainpoolP256r1 | ECDH/ECDSA |
| brainpoolP320r1 | ECDH |
| brainpoolP384r1 | ECDH/ECDSA |
| brainpoolP512r1 | ECDH/ECDSA |
| Ed25519 | EdDSA |
| Ed448 | EdDSA |

### TLS Cipher Suites (9.2.1)

**TLS 1.2:**
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

**TLS 1.3:**
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256

### JWS Algorithms (9.2.2)

- ES256: ECDSA using P-256 and SHA-256
- ES384: ECDSA using P-384 and SHA-384
- ES512: ECDSA using P-521 and SHA-512

## Certificate Profiles (Annex B)

### IACA Root Certificate (B.1.2)
- Self-signed root certificate for issuing authority
- Max validity: 20 years
- Key usage: keyCertSign, cRLSign

### Document Signer Certificate (B.1.4)
- Signs mDL data (MSO)
- Max validity: 1187 days (~3.25 years)
- Extended key usage: `1.0.18013.5.1.2` (id-mdl-kp-mdlDS)

### JWS Signer Certificate (B.1.5)
- Signs JWT responses for server retrieval
- Extended key usage: `1.0.18013.5.1.3` (id-mdl-kp-mdlJWS)

### mdoc Reader Authentication Certificate (B.1.7)
- For reader authentication
- Extended key usage: `1.0.18013.5.1.6` (id-mdl-kp-mdlReaderAuth)

## VICAL - Verified Issuer Certificate Authority List (Annex C)

Framework for distributing trusted IACA certificates:
- Signed list of IACA certificates from verified issuers
- Policy requirements for VICAL providers
- Security controls for key management
- Audit and logging requirements

## Privacy Considerations (Annex E)

### Privacy Principles
1. **Transparency**: Holders should see all data and consent requests
2. **Data Minimization**: Request only necessary data elements
3. **Collection Limitation**: Verifiers should not request all elements
4. **Unlinkability**: Transactions should not be linkable across verifiers

### Key Recommendations
- Rotate mDL authentication keys frequently
- Use ephemeral session keys for forward secrecy
- Randomize BLE/Wi-Fi addresses
- Implement transaction-time informed consent
- Don't track mDL usage

### Age Attestation
Supports age verification without revealing exact birth date:
- `age_over_NN` returns true/false for specific age thresholds
- Example: `age_over_21 = true` without revealing actual age

## Request/Response Structures

### Device Request (CBOR)
```cddl
DeviceRequest = {
  "version": tstr,
  "docRequests": [+ DocRequest]
}

DocRequest = {
  "itemsRequest": ItemsRequestBytes,
  ? "readerAuth": ReaderAuth
}
```

### Device Response (CBOR)
```cddl
DeviceResponse = {
  "version": tstr,
  ? "documents": [+ Document],
  ? "documentErrors": [+ DocumentError],
  "status": uint
}

Document = {
  "docType": DocType,
  "issuerSigned": IssuerSigned,
  "deviceSigned": DeviceSigned
}
```

## References

- ISO/IEC 18013-1: Physical driving licence
- ISO/IEC 18013-2: Machine-readable technologies
- ISO/IEC 18013-3: Access control and authentication (IDL with chip)
- RFC 8152: CBOR Object Signing and Encryption (COSE)
- RFC 7519: JSON Web Token (JWT)
- RFC 8610: Concise Data Definition Language (CDDL)
- Bluetooth Core Specification v5.2
- Wi-Fi Alliance Neighbor Awareness Networking Specification
