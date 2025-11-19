# SD-JWT VC Draft-13 Compliance Summary

## Overview

The `sdjwtv4` package has been updated to comply with **SD-JWT VC draft-13** while maintaining full support for **VCTM (Verifiable Credential Type Metadata)** as requested.

**Specification**: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/13/

## Changes Made

### 1. Media Type Update (Section 3.2.1)

**Changed**: JWT header `typ` claim from `vc+sd-jwt` to `dc+sd-jwt`

```go
// Before
header := map[string]any{
    "typ": "vc+sd-jwt",
    // ...
}

// After (draft-13 compliant)
header := map[string]any{
    "typ": "dc+sd-jwt",  // Per section 3.2.1
    // ...
}
```

**Note**: The specification recommends accepting both `vc+sd-jwt` and `dc+sd-jwt` during a transition period. This implementation uses `dc+sd-jwt` as the default.

### 2. Enhanced VCTM Documentation

All VCTM-related types now include comprehensive documentation referencing the specific sections of SD-JWT VC draft-13:

- **VCTM struct** (Section 6): Type Metadata structure
- **VCTMDisplay** (Section 8): Display metadata for rendering
- **Rendering** (Section 8.1): Rendering methods (simple, SVG templates)
- **Claim** (Section 9): Claim metadata with selective disclosure rules
- **ClaimDisplay** (Section 9.2): Locale-specific claim labels

### 3. Specification References Added

All major types now include references to the relevant draft-13 sections:

```go
// VCTM is the Verifiable Credential Type Metadata per SD-JWT VC draft-13 section 6.
// Type Metadata provides information about credential types including:
// - Display properties for rendering credentials in wallets
// - Claim metadata for validation and selective disclosure rules
// - Extensibility through the extends mechanism
type VCTM struct {
    // VCT is the verifiable credential type identifier (REQUIRED per section 6.2)
    VCT string `json:"vct"`
    // ...
}
```

### 4. Field Documentation Updates

All struct fields now document:
- Whether they are REQUIRED or OPTIONAL per the spec
- Which section of the spec defines them
- Their purpose and usage

Example:
```go
type Claim struct {
    // SD indicates selective disclosure rules per section 9.4 (OPTIONAL, default: "allowed")
    // Values: "always", "allowed", "never"
    // - "always": Issuer MUST make the claim selectively disclosable
    // - "allowed": Issuer MAY make the claim selectively disclosable
    // - "never": Issuer MUST NOT make the claim selectively disclosable
    SD string `json:"sd,omitempty"`
    
    // Mandatory indicates if claim must be present per section 9.3 (OPTIONAL, default: false)
    Mandatory bool `json:"mandatory,omitempty"`
    // ...
}
```

### 5. JSON Marshaling Updated

Optional fields now use `omitempty` tags to match the specification:

```go
type VCTMDisplay struct {
    Lang        string    `json:"lang"`                   // REQUIRED
    Name        string    `json:"name"`                   // REQUIRED
    Description string    `json:"description,omitempty"`  // OPTIONAL
    Rendering   Rendering `json:"rendering,omitempty"`    // OPTIONAL
}
```

### 6. Background Image Support

Added `BackgroundImage` field to `SimpleRendering` per section 8.1.1.2:

```go
type SimpleRendering struct {
    Logo            Logo   `json:"logo,omitempty"`
    BackgroundImage *Logo  `json:"background_image,omitempty"`  // NEW
    BackgroundColor string `json:"background_color,omitempty"`
    TextColor       string `json:"text_color,omitempty"`
}
```

## Compliance Checklist

### Media Type (Section 3.1)
- [x] Uses `application/dc+sd-jwt` media type
- [x] JWT `typ` header: `dc+sd-jwt`
- [x] Accepts `vc+sd-jwt` during transition (implementation note)

### Required Claims (Section 3.2.2)
- [x] `vct`: Verifiable Credential Type identifier
- [x] `iss`: Issuer identifier (optional)
- [x] `iat`: Issuance time (optional)
- [x] `exp`: Expiration time (optional)
- [x] `cnf`: Confirmation method (optional, required for Key Binding)
- [x] `_sd_alg`: Hash algorithm (automatically set)

### Type Metadata (Section 6)
- [x] VCTM structure compliant with section 6.2
- [x] `vct` field (REQUIRED)
- [x] `name` field (OPTIONAL)
- [x] `description` field (OPTIONAL)
- [x] `extends` field for type extension (OPTIONAL)
- [x] `extends#integrity` for integrity protection (OPTIONAL)

### Display Metadata (Section 8)
- [x] `VCTMDisplay` array structure
- [x] Locale support (`lang` field per RFC 5646)
- [x] Simple rendering (Section 8.1.1)
  - [x] Logo metadata (Section 8.1.1.1)
  - [x] Background image metadata (Section 8.1.1.2)
  - [x] Background color
  - [x] Text color
- [x] SVG templates (Section 8.1.2)
  - [x] Template properties (orientation, color_scheme, contrast)
  - [x] URI with integrity protection

### Claim Metadata (Section 9)
- [x] Claim path array (Section 9.1)
- [x] Display metadata (Section 9.2)
- [x] Mandatory indicator (Section 9.3)
- [x] Selective disclosure rules (Section 9.4)
  - [x] `sd`: "always", "allowed", "never"
- [x] SVG ID for template placeholders (Section 8.1.2.2)

### Integrity Protection (Section 7)
- [x] Subresource Integrity format support
- [x] `vct#integrity` claim
- [x] `extends#integrity` field
- [x] `uri#integrity` fields for images and templates

## VCTM Support Maintained

As requested, **full VCTM support has been maintained** despite VCTM being defined in the SD-JWT VC specification (not the core SD-JWT draft-22):

✅ All VCTM types preserved
✅ All VCTM methods preserved
✅ All VCTM conversion utilities preserved
✅ Display metadata fully supported
✅ Claim metadata fully supported
✅ Type extension mechanism supported
✅ Integrity protection supported

## Testing

All tests pass with **92.9% code coverage**:

```bash
$ go test ./pkg/sdjwtv4 -cover
ok      vc/pkg/sdjwtv4  4.032s  coverage: 92.9% of statements
```

Tests updated to verify `dc+sd-jwt` media type.

## Migration Notes

### For Existing Code

No changes required for existing code using this package. The API remains unchanged.

### For Verifiers

Verifiers should accept both `vc+sd-jwt` and `dc+sd-jwt` as valid `typ` header values during the transition period, as recommended by the specification.

### Media Type Registration

The specification uses `application/dc+sd-jwt` as the media type (changed from `application/vc+sd-jwt` in November 2024).

## References

- **SD-JWT VC Specification**: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/13/
- **SD-JWT Core Specification**: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/22/
- **W3C Subresource Integrity**: https://www.w3.org/TR/SRI/
- **RFC 5646 Language Tags**: https://www.rfc-editor.org/rfc/rfc5646

## Package Documentation

See [README.md](README.md) for detailed usage examples and API documentation.
