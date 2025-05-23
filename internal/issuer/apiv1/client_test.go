package apiv1

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"
	"vc/pkg/logger"
	"vc/pkg/sdjwt3"
	"vc/pkg/socialsecurity"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
)

func TestPDA1Credential(t *testing.T) {
	want := map[string]any{
		"_sd": []any{
			"2D0ScjxNWXCvr9bcj1rVWLAW4xZRsHHq4rzB00RbapI",
			"UrDQQc6nuN5gmwdeAJ0gUgg36b92xPAC_KvAlhWNtnk",
			"GR6rmSmjAOUN6PlUjAUqN3f0nBDY_d-yX5JSzOQmeMY",
			"p3vexe1bxf34Nl7-wBE3uriHvxjhsgRdgEx58EncS5c",
			"35c64JIKknuzwLO_IiNsp0DCiRd5QoovEbjj2nNudTs",
			"3LhxTU59mAEfm2c_Uak0N9k-Y4YFOMHnjcgxpeaA1Zs",
			"PNaFacPiRz7h7vDbeFQreExX7h14rcbTDO32ijPyQPI",
			"DGsF4bRRLiZuG9rvpJMTP71mhoS-ZlenEU9uRVkvaJI",
			"xp2G87arqZ6Nogcnck4gWgKFKX8kpHQHkGbZMKB26tg",
		},
		"_sd_alg": "sha-256",
		"nbf":     int64(time.Now().Unix()),
		"exp":     int64(time.Now().Add(24 * 365 * time.Hour).Unix()),
		"iss":     "https://test-issuer.sunet.se",
		"vct":     "https://test-issuer.sunet.se/credential/pda1/1.0",
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
		token, err := client.pda1Client.sdjwt(ctx, mockPDA1, nil, &deterministicSalt)
		assert.NoError(t, err)

		_, bodyEncoded, _, _, err := sdjwt3.SplitToken(token)
		assert.NoError(t, err)

		body, err := sdjwt3.Base64Decode(bodyEncoded)
		assert.NoError(t, err)

		got, err := sdjwt3.Unmarshal(body)
		assert.NoError(t, err)

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
		token, err := client.pda1Client.sdjwt(ctx, mockPDA1, nil, &deterministicSalt)
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
	doc := &socialsecurity.EHICDocument{
		PersonalAdministrativeNumber: "0918230998123",
		IssuingAuthority: socialsecurity.IssuingAuthority{
			ID:   "1234",
			Name: "SUNET",
		},
		IssuingCountry: "SE",
		DateOfExpiry:   "2038-01-19",
		DateOfIssuance: "2021-01-19",
		DocumentNumber: "7f87b4c4-9d0a-11ef-bc21-3b0ccffe7106",
	}

	want := map[string]any{
		"_sd": []any{
			"6_MtCEPup3vZs8zt37C96rLEGbsNK_bixWzQTCdqfEg",
			"9s08O0RuxyTVgdglSxpr_bs8t6xvITHiNheNpkgwDM4",
			"vTqOrfO1sNZpv2oP6U19f-cH72rbG0geb8xJo7uqXDM",
			"getWi9qfw-uPmFOj1-tSOeFTZEYTfzWt5lfTOfB21Gg",
			"4UQafMVlEB6uyfiiFM0ToRdmX-1sI5MbRHljUMAOA8I",
		},
		"_sd_alg": "sha-256",
		"nbf":     int64(time.Now().Unix()),
		"exp":     int64(time.Now().Add(24 * 365 * time.Hour).Unix()),
		"iss":     "https://test-issuer.sunet.se",
		"vct":     "https://test-issuer.sunet.se/credential/ehic/1.0",
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
		assert.NoError(t, err)

		got, err := sdjwt3.Unmarshal(body)
		assert.NoError(t, err)

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
