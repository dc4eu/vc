package openid_federation

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

var mockEntityConfiguration = EntityConfiguration{
	ISS: "https://openid.sunet.se",
	SUB: "https://openid.sunet.se",
	IAT: 1516239022,
	EXP: 1516298022,
	Metadata: Metadata{
		FederationEntity: FederationEntity{
			Contacts: []string{
				"ops@sunet.se",
			},
			FederationFetchEndpoint: "https://sunet.se/openid/fedapi",
			HomepageURI:             "https://www.sunet.se",
			OrganizationName:        "SUNET",
		},
		OpenidProvider: OpenidProvider{
			Issuer:                "https://openid.sunet.se",
			SignedJWKSURI:         "https://openid.sunet.se/jwks.jose",
			AuthorizationEndpoint: "https://openid.sunet.se/authorization",
			ClientRegistrationTypesSupported: []string{
				"automatic",
				"explicit",
			},
			GrantTypesSupported: []string{
				"authorization_code",
			},
			IDTokenSigningAlgValuesSupported: []string{"ES256", "RS256"},
			LogoURI:                          "https://www.umu.se/img/umu-logo-left-neg-SE.svg",
			OPPolicyURI:                      "https://www.umu.se/en/website/legal-information/",
			ResponseTypesSupported:           []string{"code"},
			SubjectTypesSupported: []string{
				"pairwise",
				"public",
			},
			TokenEndpoint:                     "https://openid.sunet.se/token",
			FederationRegistrationEndpoint:    "https://op.umu.se/openid/fedreg",
			TokenEndpointAuthMethodsSupported: []string{"private_key_jwt"},
		},
	},
	JWKS: Keys{
		[]Key{
			{
				ALG: "RS256",
				KID: "key1",
				E:   "AQAB",
				N:   "pnXBOusEANuug6ewezb9J_...",
				KTY: "RSA",
				Use: "sig",
			},
		},
	},
	AuthorityHints: []string{
		"https://edugain.org/federation",
	},
}

func TestEntityConfiguration(t *testing.T) {
	t.Run("TestNewEntityConfiguration", func(t *testing.T) {

		b, err := json.Marshal(mockEntityConfiguration)
		assert.NoError(t, err)

		bb := golden.Get(t, "entity_configuration.golden")

		assert.JSONEq(t, string(bb), string(b), "JSON should be equal")

	})
}

func TestEntityConfigurationJWT(t *testing.T) {
	t.Run("TestEntityConfigurationJWT", func(t *testing.T) {
		jwt, err := mockEntityConfiguration.JWT(nil)
		assert.NoError(t, err)

		bb := golden.Get(t, "entity_configuration_jwt.golden")

		assert.Equal(t, string(bb), jwt, "JWT should be equal")
	})
}
