#!/usr/bin/env python3
"""
OpenID Connect Conformance Suite Automated Validator

This script validates that the verifier-proxy OIDC endpoints are
ready for conformance testing.
"""
import subprocess
import time
import requests
import json
import sys
from typing import Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class TestResult:
    """Result of a validation test"""
    name: str
    passed: bool
    message: str
    details: Optional[Dict[str, Any]] = None


class ConformanceTester:
    """OIDC Conformance validator"""
    
    def __init__(self, ngrok_url: str):
        self.ngrok_url = ngrok_url.rstrip('/')
        self.discovery_url = f"{self.ngrok_url}/.well-known/openid-configuration"
        self.metadata: Optional[Dict[str, Any]] = None
        
    def run_all_tests(self) -> list[TestResult]:
        """Run all validation tests"""
        results = []
        
        # Test 1: Discovery endpoint
        results.append(self.test_discovery())
        
        if not results[-1].passed:
            return results
        
        # Test 2: JWKS endpoint
        results.append(self.test_jwks())
        
        # Test 3: Registration endpoint
        results.append(self.test_registration())
        
        # Test 4: Registration CRUD
        results.append(self.test_registration_crud())
        
        # Test 5: Metadata compliance
        results.append(self.test_metadata_compliance())
        
        return results
    
    def test_discovery(self) -> TestResult:
        """Test OpenID Provider discovery endpoint"""
        try:
            resp = requests.get(self.discovery_url, timeout=10)
            resp.raise_for_status()
            self.metadata = resp.json()
            
            # Verify required fields per OpenID Connect Discovery
            required_fields = [
                "issuer",
                "authorization_endpoint",
                "token_endpoint",
                "jwks_uri",
                "response_types_supported",
                "subject_types_supported",
                "id_token_signing_alg_values_supported"
            ]
            
            missing = [f for f in required_fields if f not in self.metadata]
            if missing:
                return TestResult(
                    name="Discovery Endpoint",
                    passed=False,
                    message=f"Missing required fields: {', '.join(missing)}",
                    details=self.metadata
                )
            
            # Verify issuer matches
            if self.metadata["issuer"] != self.ngrok_url:
                return TestResult(
                    name="Discovery Endpoint",
                    passed=False,
                    message=f"Issuer mismatch: {self.metadata['issuer']} != {self.ngrok_url}",
                    details=self.metadata
                )
            
            return TestResult(
                name="Discovery Endpoint",
                passed=True,
                message="All required fields present",
                details={
                    "issuer": self.metadata["issuer"],
                    "endpoints": {
                        "authorization": self.metadata["authorization_endpoint"],
                        "token": self.metadata["token_endpoint"],
                        "jwks": self.metadata["jwks_uri"],
                        "registration": self.metadata.get("registration_endpoint", "N/A")
                    }
                }
            )
            
        except Exception as e:
            return TestResult(
                name="Discovery Endpoint",
                passed=False,
                message=f"Failed: {str(e)}"
            )
    
    def test_jwks(self) -> TestResult:
        """Test JWKS endpoint"""
        try:
            if not self.metadata:
                return TestResult(
                    name="JWKS Endpoint",
                    passed=False,
                    message="Discovery must pass first"
                )
            
            jwks_uri = self.metadata.get("jwks_uri")
            if not jwks_uri:
                return TestResult(
                    name="JWKS Endpoint",
                    passed=False,
                    message="No jwks_uri in discovery"
                )
            
            resp = requests.get(jwks_uri, timeout=10)
            resp.raise_for_status()
            jwks = resp.json()
            
            if "keys" not in jwks:
                return TestResult(
                    name="JWKS Endpoint",
                    passed=False,
                    message="JWKS missing 'keys' field"
                )
            
            if len(jwks["keys"]) == 0:
                return TestResult(
                    name="JWKS Endpoint",
                    passed=False,
                    message="JWKS has no keys"
                )
            
            # Validate key structure
            for i, key in enumerate(jwks["keys"]):
                required_key_fields = ["kty", "use", "kid"]
                missing = [f for f in required_key_fields if f not in key]
                if missing:
                    return TestResult(
                        name="JWKS Endpoint",
                        passed=False,
                        message=f"Key {i} missing fields: {', '.join(missing)}"
                    )
            
            return TestResult(
                name="JWKS Endpoint",
                passed=True,
                message=f"Valid JWKS with {len(jwks['keys'])} key(s)",
                details={
                    "key_count": len(jwks["keys"]),
                    "key_types": [k.get("kty") for k in jwks["keys"]],
                    "algorithms": [k.get("alg") for k in jwks["keys"]]
                }
            )
            
        except Exception as e:
            return TestResult(
                name="JWKS Endpoint",
                passed=False,
                message=f"Failed: {str(e)}"
            )
    
    def test_registration(self) -> TestResult:
        """Test dynamic client registration"""
        try:
            if not self.metadata:
                return TestResult(
                    name="Registration Endpoint",
                    passed=False,
                    message="Discovery must pass first"
                )
            
            reg_endpoint = self.metadata.get("registration_endpoint")
            if not reg_endpoint:
                return TestResult(
                    name="Registration Endpoint",
                    passed=False,
                    message="No registration_endpoint in discovery"
                )
            
            # Test client registration
            client_metadata = {
                "redirect_uris": ["https://example.com/callback"],
                "client_name": "Conformance Validator Test Client",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "client_secret_basic"
            }
            
            resp = requests.post(
                reg_endpoint,
                json=client_metadata,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            resp.raise_for_status()
            
            client = resp.json()
            
            # Verify required response fields per RFC 7591
            required_resp_fields = ["client_id"]
            missing = [f for f in required_resp_fields if f not in client]
            if missing:
                return TestResult(
                    name="Registration Endpoint",
                    passed=False,
                    message=f"Response missing fields: {', '.join(missing)}",
                    details=client
                )
            
            # For confidential clients, client_secret should be present
            if client.get("token_endpoint_auth_method") != "none":
                if "client_secret" not in client:
                    return TestResult(
                        name="Registration Endpoint",
                        passed=False,
                        message="Missing client_secret for confidential client",
                        details=client
                    )
            
            return TestResult(
                name="Registration Endpoint",
                passed=True,
                message="Client registered successfully",
                details={
                    "client_id": client["client_id"][:8] + "...",
                    "has_secret": "client_secret" in client,
                    "has_registration_token": "registration_access_token" in client
                }
            )
            
        except Exception as e:
            return TestResult(
                name="Registration Endpoint",
                passed=False,
                message=f"Failed: {str(e)}"
            )
    
    def test_registration_crud(self) -> TestResult:
        """Test full CRUD operations on registration endpoint"""
        try:
            if not self.metadata:
                return TestResult(
                    name="Registration CRUD",
                    passed=False,
                    message="Discovery must pass first"
                )
            
            reg_endpoint = self.metadata.get("registration_endpoint")
            if not reg_endpoint:
                return TestResult(
                    name="Registration CRUD",
                    passed=False,
                    message="No registration_endpoint in discovery"
                )
            
            # Create client
            client_metadata = {
                "redirect_uris": ["https://example.com/callback"],
                "client_name": "CRUD Test Client",
                "grant_types": ["authorization_code"],
                "response_types": ["code"]
            }
            
            resp = requests.post(reg_endpoint, json=client_metadata, timeout=10)
            resp.raise_for_status()
            client = resp.json()
            
            client_id = client["client_id"]
            reg_token = client.get("registration_access_token")
            
            if not reg_token:
                return TestResult(
                    name="Registration CRUD",
                    passed=False,
                    message="No registration_access_token in response"
                )
            
            # Read client (GET)
            get_url = f"{reg_endpoint}/{client_id}"
            resp = requests.get(
                get_url,
                headers={"Authorization": f"Bearer {reg_token}"},
                timeout=10
            )
            resp.raise_for_status()
            retrieved = resp.json()
            
            if retrieved["client_id"] != client_id:
                return TestResult(
                    name="Registration CRUD",
                    passed=False,
                    message="Retrieved client_id mismatch"
                )
            
            # Update client (PUT)
            update_metadata = {
                "redirect_uris": ["https://example.com/callback", "https://example.com/cb2"],
                "client_name": "Updated CRUD Test Client"
            }
            
            resp = requests.put(
                get_url,
                json=update_metadata,
                headers={"Authorization": f"Bearer {reg_token}"},
                timeout=10
            )
            resp.raise_for_status()
            updated = resp.json()
            
            if len(updated["redirect_uris"]) != 2:
                return TestResult(
                    name="Registration CRUD",
                    passed=False,
                    message="Client update failed"
                )
            
            # Delete client (DELETE)
            resp = requests.delete(
                get_url,
                headers={"Authorization": f"Bearer {reg_token}"},
                timeout=10
            )
            
            if resp.status_code != 204:
                return TestResult(
                    name="Registration CRUD",
                    passed=False,
                    message=f"Delete returned {resp.status_code}, expected 204"
                )
            
            return TestResult(
                name="Registration CRUD",
                passed=True,
                message="All CRUD operations successful",
                details={
                    "create": "✓",
                    "read": "✓",
                    "update": "✓",
                    "delete": "✓"
                }
            )
            
        except Exception as e:
            return TestResult(
                name="Registration CRUD",
                passed=False,
                message=f"Failed: {str(e)}"
            )
    
    def test_metadata_compliance(self) -> TestResult:
        """Test OpenID Connect metadata compliance"""
        try:
            if not self.metadata:
                return TestResult(
                    name="Metadata Compliance",
                    passed=False,
                    message="Discovery must pass first"
                )
            
            issues = []
            
            # Check response_types_supported
            if "code" not in self.metadata.get("response_types_supported", []):
                issues.append("Missing 'code' in response_types_supported")
            
            # Check grant_types_supported
            grant_types = self.metadata.get("grant_types_supported", [])
            if "authorization_code" not in grant_types:
                issues.append("Missing 'authorization_code' in grant_types_supported")
            
            # Check token_endpoint_auth_methods_supported
            auth_methods = self.metadata.get("token_endpoint_auth_methods_supported", [])
            if not auth_methods:
                issues.append("No token_endpoint_auth_methods_supported")
            
            # Check scopes_supported
            if not self.metadata.get("scopes_supported"):
                issues.append("No scopes_supported")
            elif "openid" not in self.metadata["scopes_supported"]:
                issues.append("Missing 'openid' scope")
            
            # Check subject_types_supported
            subject_types = self.metadata.get("subject_types_supported", [])
            if not subject_types:
                issues.append("No subject_types_supported")
            
            # Check signing algorithms
            algs = self.metadata.get("id_token_signing_alg_values_supported", [])
            if "RS256" not in algs:
                issues.append("Missing 'RS256' in id_token_signing_alg_values_supported")
            
            if issues:
                return TestResult(
                    name="Metadata Compliance",
                    passed=False,
                    message=f"Found {len(issues)} compliance issue(s)",
                    details={"issues": issues}
                )
            
            return TestResult(
                name="Metadata Compliance",
                passed=True,
                message="Metadata is OpenID Connect compliant",
                details={
                    "response_types": self.metadata["response_types_supported"],
                    "grant_types": self.metadata.get("grant_types_supported"),
                    "scopes": self.metadata.get("scopes_supported"),
                    "subject_types": self.metadata["subject_types_supported"]
                }
            )
            
        except Exception as e:
            return TestResult(
                name="Metadata Compliance",
                passed=False,
                message=f"Failed: {str(e)}"
            )


def print_results(results: list[TestResult]):
    """Print test results in a formatted way"""
    print("\n" + "="*70)
    print("OpenID Connect Conformance Validation Results")
    print("="*70 + "\n")
    
    passed_count = sum(1 for r in results if r.passed)
    total_count = len(results)
    
    for result in results:
        status = "✅ PASS" if result.passed else "❌ FAIL"
        print(f"{status} | {result.name}")
        print(f"       {result.message}")
        
        if result.details and result.passed:
            for key, value in result.details.items():
                if isinstance(value, dict):
                    print(f"       {key}:")
                    for k, v in value.items():
                        print(f"         - {k}: {v}")
                elif isinstance(value, list):
                    print(f"       {key}: {', '.join(str(v) for v in value)}")
                else:
                    print(f"       {key}: {value}")
        
        print()
    
    print("="*70)
    print(f"Results: {passed_count}/{total_count} tests passed")
    print("="*70 + "\n")
    
    if passed_count == total_count:
        print("🎉 All tests passed! Ready for OpenID Connect Conformance Suite.")
        print()
        print("Next steps:")
        print("  1. Go to https://www.certification.openid.net/")
        print("  2. Create test plan: oidcc-basic-certification-test-plan")
        print("  3. Use your ngrok URL for server discovery")
        return 0
    else:
        print("⚠️  Some tests failed. Please fix issues before conformance testing.")
        return 1


def main():
    if len(sys.argv) < 2:
        print("Usage: ./conformance_validator.py <ngrok-url>")
        print()
        print("Example:")
        print("  ./conformance_validator.py https://abc123.ngrok.io")
        sys.exit(1)
    
    ngrok_url = sys.argv[1].rstrip('/')
    
    print(f"\n🔍 Validating OIDC Provider at: {ngrok_url}\n")
    
    tester = ConformanceTester(ngrok_url)
    results = tester.run_all_tests()
    
    exit_code = print_results(results)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
