package apiv1

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
	"vc/internal/issuer/auditlog"
	"vc/pkg/ehic"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/pda1"
	"vc/pkg/sdjwt3"
	"vc/pkg/trace"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
)

var nonRandomSeed = bytes.NewReader([]byte("1234567890abcdefghijklmnopqrstuvxyz1234567890abcdefghijklmnopqrstuvxyz1234567890abcdefghijklmnopqrstuvxyz"))

func mockKey(t *testing.T, keyType string) string {
	tempFolder := t.TempDir()
	keyPath := filepath.Join(tempFolder, "signing.key")

	switch keyType {
	case "ecdsa":
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), nonRandom)
		assert.NoError(t, err)

		keyEncoded, err := x509.MarshalECPrivateKey(privKey)
		assert.NoError(t, err)

		pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE", Bytes: keyEncoded})

		os.WriteFile(keyPath, pemEncoded, 0644)

	default:
		assert.Fail(t, "unknown key type")
	}

	return keyPath
}

func mockNewClient(ctx context.Context, t *testing.T, keyType string, log *logger.Log) *Client {
	keyPath := mockKey(t, keyType)

	cfg := &model.Cfg{
		Issuer: model.Issuer{
			APIServer:      model.APIServer{},
			Identifier:     "",
			GRPCServer:     model.GRPCServer{},
			SigningKeyPath: keyPath,
			JWTAttribute:   model.JWTAttribute{},
		},
	}

	tracer, err := trace.NewForTesting(ctx, "test", log.New("trace"))
	assert.NoError(t, err)

	audit, err := auditlog.New(ctx, cfg, log.New("audit"))

	client, err := New(ctx, audit, cfg, tracer, log.New("apiv1"))
	assert.NoError(t, err)

	return client
}

func TestPDA1Credential(t *testing.T) {
	doc := &pda1.Document{
		Person: pda1.Person{
			Forename:    "Kalle",
			FamilyName:  "Karlsson",
			DateOfBirth: "1980-01-01",
			OtherElements: pda1.OtherElements{
				Sex:               "01",
				ForenameAtBirth:   "Kalle",
				FamilyNameAtBirth: "Karlsson",
			},
		},
		SocialSecurityPin: "1234",
		Nationality:       []string{"SE"},
		DetailsOfEmployment: []pda1.DetailsOfEmployment{
			{
				TypeOfEmployment: "01",
				Name:             "Corp inc.",
				Address: pda1.AddressWithCountry{
					Street:   "street",
					PostCode: "12345",
					Town:     "town",
					Country:  "SE",
				},
				IDsOfEmployer: []pda1.IDsOfEmployer{
					{
						EmployerID: "123",
						TypeOfID:   "01",
					},
				},
			},
		},
		PlacesOfWork: []pda1.PlacesOfWork{
			{
				NoFixedPlaceOfWorkExist: false,
				CountryWork:             "SE",
				PlaceOfWork: []pda1.PlaceOfWork{
					{
						CompanyVesselName: "M/S Transpaper",
						FlagStateHomeBase: "Göteborg",
						IDsOfCompany: []pda1.IDsOfCompany{
							{
								CompanyID: "123",
								TypeOfID:  "01",
							},
						},
						Address: pda1.Address{
							Street:   "street",
							PostCode: "1235",
							Town:     "town",
						},
					},
				},
			},
		},
		DecisionLegislationApplicable: pda1.DecisionLegislationApplicable{
			MemberStateWhichLegislationApplies: "",
			TransitionalRuleApply:              false,
			StartingDate:                       "1970-01-01",
			EndingDate:                         "2038-01-19",
		},
		StatusConfirmation:           "01",
		UniqueNumberOfIssuedDocument: "asldmnjklh123laa123",
		CompetentInstitution: pda1.CompetentInstitution{
			InstitutionID:   "SE:123",
			InstitutionName: "SUNET",
			CountryCode:     "SE",
		},
	}

	want := map[string]any{
		"_sd": []any{
			"pXlwfRuomneyJj_C_6Bsy9x4gxwXSCj0MwhQQ15Tkiw",
			"UrDQQc6nuN5gmwdeAJ0gUgg36b92xPAC_KvAlhWNtnk",
			"GR6rmSmjAOUN6PlUjAUqN3f0nBDY_d-yX5JSzOQmeMY",
			"p3vexe1bxf34Nl7-wBE3uriHvxjhsgRdgEx58EncS5c",
			"35c64JIKknuzwLO_IiNsp0DCiRd5QoovEbjj2nNudTs",
			"3LhxTU59mAEfm2c_Uak0N9k-Y4YFOMHnjcgxpeaA1Zs",
			"PNaFacPiRz7h7vDbeFQreExX7h14rcbTDO32ijPyQPI",
			"DGsF4bRRLiZuG9rvpJMTP71mhoS-ZlenEU9uRVkvaJI",
			"z5w4xUj40A-LTZJe6rl1jZdGIr8Li_11zggU5VCFBcI",
		},
		"_sd_alg": "sha-256",
		"nbf":     int64(time.Now().Unix()),
		"exp":     int64(time.Now().Add(24 * 365 * time.Hour).Unix()),
		"iss":     "SUNET",
		"vct":     "https://issuer.sunet.se/credential/pda1/1.0",
		"cnf": map[string]any{
			"jwk": map[string]any{
				"kty": "EC",
				"crv": "P-256",
				"kid": "default_signing_key_id",
				"d":   "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE",
				"x":   "cyViIENmqo4D2CVOc2uGZbe5a8NheCyvN9CsF7ui3tk",
				"y":   "XA0lVXgjgZzFTDwkndZEo-zVr9ieO2rY9HGiiaaASog",
			},
		},
	}
	ctx := context.Background()
	log := logger.NewSimple("test")
	client := mockNewClient(ctx, t, "ecdsa", log)
	deterministicSalt := string("salt")

	t.Run("Create", func(t *testing.T) {
		token, err := client.pda1Client.sdjwt(ctx, doc, nil, &deterministicSalt)
		assert.NoError(t, err)

		_, bodyEncoded, _, _, err := sdjwt3.SplitToken(token)
		assert.NoError(t, err)

		body, err := sdjwt3.Base64Decode(bodyEncoded)

		got, err := sdjwt3.Unmarshal(body)

		excludeCNF := cmpopts.IgnoreMapEntries(func(k string, v any) bool {
			switch k {
			case "cnf":
				return true
			case "nbf":
				return true
			case "exp":
				return true
			default:
				return false
			}
		})
		if diff := cmp.Diff(want, got, excludeCNF); diff != "" {
			t.Errorf("(-want +got):\n%s", diff)
		}
	})

	t.Run("Validate", func(t *testing.T) {
		token, err := client.pda1Client.sdjwt(ctx, doc, nil, &deterministicSalt)
		assert.NoError(t, err)

		valid, err := sdjwt3.Validate(token, client.publicKey)
		assert.NoError(t, err)
		assert.True(t, valid)

		fmt.Printf("\nsigned sdjwt token: \n%s\n", token)

		k, err := x509.MarshalPKIXPublicKey(client.publicKey)
		assert.NoError(t, err)

		keyBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: k,
		}

		p := pem.EncodeToMemory(keyBlock)
		fmt.Printf("\npublicKey pem:\n%s\n", string(p))
	})
}

func TestEHICCredential(t *testing.T) {
	doc := &ehic.Document{
		Subject:           ehic.Subject{Forename: "kalle", FamilyName: "karlsson", DateOfBirth: "1980-01-01", OtherElements: ehic.OtherElements{Sex: "M", ForenameAtBirth: "", FamilyNameAtBirth: ""}},
		SocialSecurityPin: "12334",
		PeriodEntitlement: ehic.PeriodEntitlement{
			StartingDate: "1970-01-01",
			EndingDate:   "2038-01-19",
		},
		DocumentID: "7f87b4c4-9d0a-11ef-bc21-3b0ccffe7106",
		CompetentInstitution: ehic.CompetentInstitution{
			InstitutionID:      "SE:123",
			InstitutionName:    "SUNET",
			InstitutionCountry: "SE",
		},
	}

	want := map[string]any{
		"_sd": []any{
			"AKm91SsGqiBINVoRoUGBUT8vGjj8zPwH4dVlqdTEFXw",
			"9s08O0RuxyTVgdglSxpr_bs8t6xvITHiNheNpkgwDM4",
			"vTqOrfO1sNZpv2oP6U19f-cH72rbG0geb8xJo7uqXDM",
			"getWi9qfw-uPmFOj1-tSOeFTZEYTfzWt5lfTOfB21Gg",
			"4UQafMVlEB6uyfiiFM0ToRdmX-1sI5MbRHljUMAOA8I",
		},
		"_sd_alg": "sha-256",
		"nbf":     int64(time.Now().Unix()),
		"exp":     int64(time.Now().Add(24 * 365 * time.Hour).Unix()),
		"iss":     "SUNET",
		"vct":     "https://issuer.sunet.se/credential/ehic/1.0",
		"cnf": map[string]any{
			"jwk": map[string]any{
				"kty": "EC",
				"crv": "P-256",
				"kid": "default_signing_key_id",
				"d":   "",
			},
		},
	}
	ctx := context.Background()
	log := logger.NewSimple("test")
	client := mockNewClient(ctx, t, "ecdsa", log)
	deterministicSalt := string("salt")

	t.Run("Create", func(t *testing.T) {
		token, err := client.ehicClient.sdjwt(ctx, doc, nil, &deterministicSalt)
		assert.NoError(t, err)

		_, bodyEncoded, _, _, err := sdjwt3.SplitToken(token)
		assert.NoError(t, err)

		body, err := sdjwt3.Base64Decode(bodyEncoded)

		got, err := sdjwt3.Unmarshal(body)

		excludeCNF := cmpopts.IgnoreMapEntries(func(k string, v any) bool {
			switch k {
			case "cnf":
				return true
			case "nbf":
				return true
			case "exp":
				return true
			default:
				return false
			}
		})
		if diff := cmp.Diff(want, got, excludeCNF); diff != "" {
			t.Errorf("(-want +got):\n%s", diff)
		}
	})

	t.Run("Validate", func(t *testing.T) {
		token, err := client.ehicClient.sdjwt(ctx, doc, nil, &deterministicSalt)
		assert.NoError(t, err)

		valid, err := sdjwt3.Validate(token, client.publicKey)
		assert.NoError(t, err)
		assert.True(t, valid)

		fmt.Printf("\nsigned sdjwt token: \n%s\n", token)

		k, err := x509.MarshalPKIXPublicKey(client.publicKey)
		assert.NoError(t, err)

		keyBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: k,
		}

		p := pem.EncodeToMemory(keyBlock)
		fmt.Printf("\npublicKey pem:\n%s\n", string(p))
	})
}
