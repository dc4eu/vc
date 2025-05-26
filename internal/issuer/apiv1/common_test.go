package apiv1

import (
	"context"
	"testing"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/issuer/auditlog"
	"vc/pkg/education"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/socialsecurity"
	"vc/pkg/trace"

	"github.com/stretchr/testify/assert"
)

var mockJWK = &apiv1_issuer.Jwk{
	Kid: "default_signing_key_id",
	Crv: "P-256",
	Kty: "EC",
	X:   "cyViIENmqo4D2CVOc2uGZbe5a8NheCyvN9CsF7ui3tk",
	Y:   "XA0lVXgjgZzFTDwkndZEo-zVr9ieO2rY9HGiiaaASog",
	D:   "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE",
}

var (
	mockPID = &model.Identity{
		FamilyName: "test_family-name",
		GivenName:  "test_given-name",
		BirthDate:  "2000-01-01",
	}

	mockPDA1 = &socialsecurity.PDA1Document{
		PersonalAdministrativeNumber: "1234",
		Employer: socialsecurity.Employer{
			ID:   "09809384",
			Name: "SUNET",
		},
		WorkAddress: socialsecurity.WorkAddress{
			Formatted:      "Tulegatan 11",
			Street_address: "Tulegatan 11",
			House_number:   "11",
			Postal_code:    "11353",
			Locality:       "Stockholm",
			Region:         "Stockholm",
			Country:        "SE",
		},
		IssuingAuthority: socialsecurity.IssuingAuthority{
			ID:   "123123",
			Name: "SUNET",
		},
		LegislationCountry: "SE",
		DateOfExpiry:       "2023-01-01",
		DateOfIssuance:     "2021-01-01",
		DocumentNumber:     "09809834",
	}

	mockDiploma = map[string]any{}

	mockEHIC = &socialsecurity.EHICDocument{
		PersonalAdministrativeNumber: "",
		IssuingAuthority:             socialsecurity.IssuingAuthority{},
		IssuingCountry:               "",
		DateOfExpiry:                 "",
		DateOfIssuance:               "",
		DocumentNumber:               "",
	}

	mockELM = &education.ELMDocument{}

	mockMicroCredential = map[string]any{}
)

func mockNewClient(ctx context.Context, t *testing.T, keyType string, log *logger.Log) *Client {
	cfg := &model.Cfg{
		CredentialConstructor: map[string]*model.CredentialConstructor{
			"diploma": {
				VCT:          model.CredentialTypeUrnEduiDiploma1,
				VCTMFilePath: "testdata/vctm_test.json",
			},
			"pid": {
				VCT:          model.CredentialTypeUrnEuEuropaEcEudiPid1,
				VCTMFilePath: "testdata/vctm_test.json",
			},
			"ehic": {
				VCT:          model.CredentialTypeUrnEudiEhic1,
				VCTMFilePath: "testdata/vctm_test.json",
			},
			"pda1": {
				VCT:          model.CredentialTypeUrnEudiPda11,
				VCTMFilePath: "testdata/vctm_test.json",
			},
			"micro_credential": {
				VCT:          model.CredentialTypeUrnEduiMicroCredential1,
				VCTMFilePath: "testdata/vctm_test.json",
			},
			"openbadge_complete": {
				VCT:          "openbadge_complete",
				VCTMFilePath: "testdata/vctm_test.json",
			},
			"openbadge_basic": {
				VCT:          "openbadge_basic",
				VCTMFilePath: "testdata/vctm_test.json",
			},
			"openbadge_endorsements": {
				VCT:          "openbadge_endorsements",
				VCTMFilePath: "testdata/vctm_test.json",
			},
			"elm": {
				VCT:          model.CredentialTypeUrnEduiElm1,
				VCTMFilePath: "testdata/vctm_test.json",
			},
		},
		Issuer: model.Issuer{
			APIServer:      model.APIServer{},
			Identifier:     "",
			GRPCServer:     model.GRPCServer{},
			SigningKeyPath: "testdata/signing_test.key",
			JWTAttribute: model.JWTAttribute{
				Issuer:                   "https://test-issuer.sunet.se",
				EnableNotBefore:          false,
				ValidDuration:            0,
				VerifiableCredentialType: "",
				Status:                   "",
				Kid:                      "",
			},
		},
	}

	tracer, err := trace.NewForTesting(ctx, "test", log.New("trace"))
	assert.NoError(t, err)

	audit, err := auditlog.New(ctx, cfg, log.New("audit"))
	assert.NoError(t, err)

	client, err := New(ctx, audit, cfg, tracer, log.New("apiv1"))
	assert.NoError(t, err)

	return client
}
