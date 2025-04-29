package openid_federation

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

type EntityConfiguration struct {
	ISS            string   `json:"iss"`
	SUB            string   `json:"sub"`
	IAT            int64    `json:"iat"`
	EXP            int64    `json:"exp"`
	Metadata       Metadata `json:"metadata"`
	JWKS           Keys     `json:"jwks"`
	AuthorityHints []string `json:"authority_hints"`
}

type Metadata struct {
	FederationEntity FederationEntity `json:"federation_entity"`
	OpenidProvider   OpenidProvider   `json:"openid_provider"`
}

type FederationEntity struct {
	Contacts                []string `json:"contacts"`
	FederationFetchEndpoint string   `json:"federation_fetch_endpoint"`
	HomepageURI             string   `json:"homepage_uri"`
	OrganizationName        string   `json:"organization_name"`
}

type OpenidProvider struct {
	Issuer                            string   `json:"issuer"`
	SignedJWKSURI                     string   `json:"signed_jwks_uri"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	ClientRegistrationTypesSupported  []string `json:"client_registration_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	LogoURI                           string   `json:"logo_uri"`
	OPPolicyURI                       string   `json:"op_policy_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	FederationRegistrationEndpoint    string   `json:"federation_registration_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

type Keys struct {
	Keys []Key `json:"keys"`
}

type Key struct {
	ALG string `json:"alg"`
	KID string `json:"kid"`
	E   string `json:"e"`
	N   string `json:"n"`
	KTY string `json:"kty"`
	Use string `json:"use"`
}

func NewEntityConfiguration(iss, sub string, iat, exp int64, metadata Metadata) *EntityConfiguration {
	return &EntityConfiguration{
		ISS:      iss,
		SUB:      sub,
		IAT:      iat,
		EXP:      exp,
		Metadata: metadata,
	}
}

func (e *EntityConfiguration) JWT(signingKey any) (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}

	claims := &jwt.MapClaims{}
	if err := json.Unmarshal(b, claims); err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}
