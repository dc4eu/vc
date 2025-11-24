# Migration from sdjwt3 to sdjwtvc

## Overview

The `sdjwtvc` package is the current implementation compliant with:
- **SD-JWT VC draft-13**: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/13/
- **SD-JWT draft-22**: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/22/

The `sdjwt3` package has been removed. All functionality is now in `sdjwtvc`.

## API Changes

### SplitToken: Function → Method

**Before (deprecated):**
```go
header, body, sig, sd, kb, err := sdjwtvc.SplitToken(tokenString)
```

**After (recommended):**
```go
header, body, sig, sd, kb, err := sdjwtvc.Token(tokenString).Split()
```

The function form `SplitToken()` is still available for backward compatibility but is deprecated.

### Construct: Use Token.Parse() Instead

**Before (deprecated):**
```go
credential, err := sdjwtvc.Construct(ctx, tokenString)
// or
credential, err := sdjwtvc.CredentialParser(ctx, tokenString)
```

**After (recommended):**
```go
parsed, err := sdjwtvc.Token(tokenString).Parse()
if err != nil {
    return err
}
claims := parsed.Claims  // map[string]any with all disclosed claims
```

`Construct()` and `CredentialParser()` are deprecated. Use `Token.Parse()` for parsing credentials with selective disclosures, or use `ParseAndVerify()` for full verification including signature validation.

## VCTM Migration

### Before (sdjwt3)

```go
import "vc/pkg/sdjwt3"

vctm := &sdjwt3.VCTM{
    VCT:  "https://example.com/credentials/identity",
    Name: "Identity Credential",
    // ... other fields
}
```

### After (sdjwtvc)

```go
import "vc/pkg/sdjwtvc"

vctm := &sdjwtvc.VCTM{
    VCT:  "https://example.com/credentials/identity",
    Name: "Identity Credential",
    // ... other fields
}
```

## Converting Between Versions

### From sdjwt3 to sdjwtvc

```go
import (
    "vc/pkg/sdjwt3"
    "vc/pkg/sdjwtvc"
)

// Load legacy VCTM
var v3VCTM sdjwt3.VCTM
// ... load from file or config

// Convert to v4
v4VCTM, err := sdjwtvc.ConvertVCTM(&v3VCTM)
if err != nil {
    // Handle error
}

// Use with sdjwtvc
client := sdjwtvc.New()
credential, err := client.BuildCredential(
    issuer,
    keyID,
    privateKey,
    credentialType,
    documentData,
    holderJWK,
    v4VCTM,  // Use converted VCTM
    nil,
)
```

### From sdjwtvc to sdjwt3 (for compatibility)

```go
// If you need to work with legacy code
v3VCTM, err := sdjwtvc.ConvertToSDJWT3VCTM(v4VCTM)
if err != nil {
    // Handle error
}
```

## Key Differences

### Enhanced Fields in sdjwtvc.VCTM

The sdjwtvc.VCTM includes additional fields per SD-JWT VC draft-13:

1. **BackgroundImage** in SimpleRendering (section 8.1.1.2)
   ```go
   Simple: SimpleRendering{
       Logo: Logo{...},
       BackgroundImage: &Logo{
           URI: "https://example.com/bg.jpg",
           AltText: "Background",
       },
   }
   ```

2. **Mandatory** field in Claim (section 9.3)
   ```go
   Claims: []Claim{
       {
           Path: []*string{&claimName},
           Mandatory: true,  // Claim must be present
           SD: "always",
       },
   }
   ```

3. **Comprehensive documentation**
   - All fields documented with spec references
   - REQUIRED/OPTIONAL markers
   - Section references to draft-13

### Media Type Change

- **sdjwt3**: Used `vc+sd-jwt` (deprecated)
- **sdjwtvc**: Uses `dc+sd-jwt` (current per draft-13 §3.2.1)
  - Still accepts `vc+sd-jwt` during transition period

## Verification Support

**sdjwtvc** adds comprehensive verification capabilities not present in sdjwt3:

```go
client := sdjwtvc.New()

// Parse and verify SD-JWT
result, err := client.ParseAndVerify(
    sdJWT,
    issuerPublicKey,
    &sdjwtvc.VerificationOptions{
        ValidateTime:      true,
        RequireKeyBinding: false,
    },
)

if err != nil {
    log.Fatal(err)
}

// Access verified data
fmt.Println("Valid:", result.Valid)
fmt.Println("Issuer:", result.Claims["iss"])
fmt.Println("Disclosed claims:", result.DisclosedClaims)
```

## Recommended Migration Path

### For New Code

Use `sdjwtvc` directly:

```go
import "vc/pkg/sdjwtvc"

client := sdjwtvc.New()
// Use sdjwtvc APIs
```

### For Existing Code

#### Option 1: Gradual Migration

Keep existing config/storage using `sdjwt3.VCTM`, convert when needed:

```go
// Config still loads sdjwt3.VCTM
var configVCTM *sdjwt3.VCTM

// Convert when creating credentials
v4VCTM, err := sdjwtvc.ConvertVCTM(configVCTM)
if err != nil {
    return err
}

// Use with sdjwtvc
client := sdjwtvc.New()
credential, err := client.BuildCredential(..., v4VCTM, nil)
```

#### Option 2: Full Migration

1. Update config structs to use `sdjwtvc.VCTM`
2. Update VCTM JSON files if needed (add new fields)
3. Update all code to use `sdjwtvc` package
4. Remove `sdjwt3` dependency

## Backward Compatibility

The conversion functions ensure:
- All `sdjwt3.VCTM` fields are preserved when converting to `sdjwtvc.VCTM`
- All `sdjwtvc.VCTM` core fields are preserved when converting back
- JSON marshaling/unmarshaling maintains compatibility
- Existing VCTM JSON files work with both versions

## Deprecation Timeline

- **Current**: `sdjwt3` is deprecated, all types marked with `// Deprecated` comments
- **Recommended**: Use `sdjwtvc` for all new development
- **Support**: `sdjwt3` will remain for backward compatibility until all code is migrated

## See Also

- [sdjwtvc README](./README.md) - Full usage guide
- [sdjwtvc COMPLIANCE](./COMPLIANCE.md) - Spec compliance details
- [SD-JWT VC draft-13](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/13/)
