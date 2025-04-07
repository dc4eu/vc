package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/sdjwt3"
	"vc/pkg/trace"

	"github.com/stretchr/testify/assert"
)

func mockECKeyPair(t *testing.T) (string, *ecdsa.PrivateKey, string, *ecdsa.PublicKey) {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	privateRaw, err := x509.MarshalECPrivateKey(p)
	assert.NoError(t, err)

	privateBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateRaw,
	}

	privateFS, err := os.CreateTemp("", "private.pem")
	assert.NoError(t, err)
	err = pem.Encode(privateFS, privateBlock)
	assert.NoError(t, err)

	publicRaw, err := x509.MarshalECPrivateKey(p)
	assert.NoError(t, err)

	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicRaw,
	}

	publicFS, err := os.CreateTemp("", "public.pem")
	assert.NoError(t, err)
	err = pem.Encode(publicFS, publicBlock)
	assert.NoError(t, err)

	return privateFS.Name(), p, publicFS.Name(), &p.PublicKey
}

func TestDiploma(t *testing.T) {
	type want struct {
		vctm           *VCTM
		validSignature bool
	}
	tts := []struct {
		name          string
		document_type string
		want          want
	}{
		{
			name:          "Diploma",
			document_type: "Diploma",
			want: want{
				vctm: &VCTM{
					VCT:         "DiplomaCredential",
					Name:        "",
					Description: "",
					Display: []VCTMDisplay{
						{
							Lang:        "",
							Name:        "",
							Description: "",
							Rendering: Rendering{
								Simple: SimpleRendering{
									Logo: Logo{
										URI:          "",
										URIIntegrity: "",
										AltText:      "",
									},
									BackgroundColor: "",
									TextColor:       "",
								},
								SVGTemplates: []SVGTemplates{
									{
										URI:          "",
										URLIntegrity: "",
										Properties: SVGTemplateProperties{
											Orientation: "",
											ColorScheme: "",
											Contrast:    "",
										},
									},
								},
							},
						},
					},
					Claims:             []Claim{},
					SchemaURL:          "",
					SchemaURLIntegrity: "",
					Extends:            "",
					ExtendsIntegrity:   "",
				},
				validSignature: true,
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			signingKey, _, _, publicKey := mockECKeyPair(t)

			cfg := &model.Cfg{Issuer: model.Issuer{SigningKeyPath: signingKey}}

			log := logger.NewSimple("test")

			tp, err := trace.NewForTesting(ctx, "test", log)
			assert.NoError(t, err)

			client, err := New(ctx, nil, cfg, tp, log)
			assert.NoError(t, err)

			var salt string = "salt_1234"

			jwk := &apiv1_issuer.Jwk{
				Kid: "test_kid",
				Crv: "256",
				Kty: "key_id",
				X:   "123",
				Y:   "123",
				D:   "123",
			}

			body := map[string]any{}

			signedJWT := ""

			switch tt.document_type {
			case "Diploma":
				signedJWT, err = client.diplomaClient.sdjwt(ctx, body, jwk, &salt)
				assert.NoError(t, err)

			default:
				assert.Fail(t, "unknown document type")
			}

			valid, err := sdjwt3.Validate(signedJWT, publicKey)
			assert.NoError(t, err)
			assert.Equal(t, tt.want.validSignature, valid)

			//header := strings.Split(signedJWT, ".")[0]
			header, err := base64.RawStdEncoding.DecodeString(strings.Split(signedJWT, ".")[0])
			assert.NoError(t, err)
			assert.NotEmpty(t, header)

			fmt.Println("header: ", string(header))

			headerMap := map[string]any{}
			err = json.Unmarshal(header, &headerMap)
			assert.NoError(t, err)

			vctm := headerMap["vctm"]
			fmt.Println("vctm raw: ", vctm)

			vctmStr, ok := vctm.([]string)
			if !ok {
				assert.Fail(t, "vctm is not a string")
			}

			v, err := base64.RawStdEncoding.DecodeString(vctmStr[0])
			assert.NoError(t, err)

			t.Logf("vctm: %s", string(v))
			//
			//			vctmT := &VCTM{}
			//			err = json.Unmarshal(v, &vctmT)
			//			assert.NoError(t, err)
			//
			//			assert.Equal(t, tt.want.vctm, vctmT)
			//
			//			fmt.Println("header: ", headerMap)

			//assert.Equal(t, tt.want.vctm, gotVCTM)

			//fmt.Println(signedJWT)

		})
	}
}
