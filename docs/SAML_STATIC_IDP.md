# SAML Static IdP Configuration

This document describes how to configure the SAML Service Provider (SP) with a single static Identity Provider (IdP) as an alternative to using an MDQ (Metadata Query Protocol) service.

## Overview

The SAML SP supports two modes for IdP metadata discovery:

1. **MDQ Mode** (default): Dynamically fetches IdP metadata from an MDQ server
2. **Static IdP Mode**: Uses a single pre-configured IdP with metadata loaded from a file or URL

Static IdP mode is useful for:
- Simple deployments with a single IdP
- Environments without MDQ infrastructure
- Testing and development scenarios
- Deployments where IdP metadata rarely changes

## Configuration

### MDQ Mode (Dynamic)

```yaml
apigw:
  saml:
    enabled: true
    entity_id: "https://sp.example.com"
    mdq_server: "https://md.example.org/entities/"
    certificate_path: "/path/to/sp-cert.pem"
    private_key_path: "/path/to/sp-key.pem"
    acs_endpoint: "https://sp.example.com/saml/acs"
    credential_mappings:
      pid:
        credential_config_id: "urn:eudi:pid:1"
        attributes:
          # ... attribute mappings
```

### Static IdP Mode (From File)

```yaml
apigw:
  saml:
    enabled: true
    entity_id: "https://sp.example.com"
    static_idp_metadata:
      entity_id: "https://idp.example.com"
      metadata_path: "/path/to/idp-metadata.xml"
    certificate_path: "/path/to/sp-cert.pem"
    private_key_path: "/path/to/sp-key.pem"
    acs_endpoint: "https://sp.example.com/saml/acs"
    credential_mappings:
      pid:
        credential_config_id: "urn:eudi:pid:1"
        attributes:
          # ... attribute mappings
```

### Static IdP Mode (From URL)

```yaml
apigw:
  saml:
    enabled: true
    entity_id: "https://sp.example.com"
    static_idp_metadata:
      entity_id: "https://idp.example.com"
      metadata_url: "https://idp.example.com/metadata"
    certificate_path: "/path/to/sp-cert.pem"
    private_key_path: "/path/to/sp-key.pem"
    acs_endpoint: "https://sp.example.com/saml/acs"
    credential_mappings:
      pid:
        credential_config_id: "urn:eudi:pid:1"
        attributes:
          # ... attribute mappings
```

## Configuration Fields

### `static_idp_metadata`

Configuration for a single static IdP. Mutually exclusive with `mdq_server`.

- `entity_id` (required): The IdP entity identifier
- `metadata_path` (optional): Path to IdP metadata XML file
- `metadata_url` (optional): HTTP(S) URL to fetch IdP metadata from

**Note**: Exactly one of `metadata_path` or `metadata_url` must be specified.

## Validation Rules

The configuration is validated on startup:

1. ✅ Either `mdq_server` or `static_idp_metadata` must be configured (when SAML is enabled)
2. ❌ Cannot specify both `mdq_server` and `static_idp_metadata`
3. ✅ `static_idp_metadata.entity_id` is required
4. ✅ Either `metadata_path` or `metadata_url` must be specified
5. ❌ Cannot specify both `metadata_path` and `metadata_url`

## Behavior Differences

### MDQ Mode
- Supports multiple IdPs
- Fetches metadata on-demand per IdP
- Caches metadata with configurable TTL
- Requires `idp_entity_id` parameter in authentication requests

### Static IdP Mode
- Single IdP only
- Metadata loaded once at startup
- No metadata caching needed (already in memory)
- `idp_entity_id` parameter is optional (uses static IdP if omitted)
- Logs info message if different IdP is requested

## Example IdP Metadata File

```xml
<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" 
                  entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>
            <!-- IdP certificate here -->
          </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService 
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" 
        Location="https://idp.example.com/sso"/>
    <SingleSignOnService 
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
        Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>
```

## Migration from MDQ to Static IdP

If you're migrating from MDQ to static IdP mode:

1. Download IdP metadata:
   ```bash
   curl https://md.example.org/entities/https%3A%2F%2Fidp.example.com > idp-metadata.xml
   ```

2. Update configuration:
   ```yaml
   # Remove:
   # mdq_server: "https://md.example.org/entities/"
   
   # Add:
   static_idp_metadata:
     entity_id: "https://idp.example.com"
     metadata_path: "/path/to/idp-metadata.xml"
   ```

3. Restart the service

## Troubleshooting

### Metadata File Not Found
```
Error: failed to initialize static IdP metadata: failed to read metadata file: open /path/to/idp-metadata.xml: no such file or directory
```
- Verify the `metadata_path` is correct and the file exists
- Check file permissions

### Invalid Metadata XML
```
Error: failed to initialize static IdP metadata: failed to parse IdP metadata XML
```
- Ensure the XML is valid SAML metadata
- Verify it contains an `IDPSSODescriptor` element
- Check for SingleSignOnService endpoints

### Both MDQ and Static IdP Configured
```
Error: invalid SAML configuration: SAML configuration cannot have both mdq_server and static_idp_metadata
```
- Remove either `mdq_server` or `static_idp_metadata` from configuration

### EntityID Mismatch Warning
```
INFO: configured entityID differs from metadata entityID
```
- The entityID in configuration doesn't match the entityID in the metadata XML
- This is a warning, not an error - the service will use the configured entityID
- Verify the entityID is correct

## API Endpoints

The SAML endpoints remain the same regardless of IdP mode:

- `GET /saml/metadata` - SP metadata
- `POST /saml/initiate` - Initiate authentication
- `POST /saml/acs` - Assertion Consumer Service

In static IdP mode, the `idp_entity_id` parameter in the `/saml/initiate` request is optional and will default to the configured static IdP.
