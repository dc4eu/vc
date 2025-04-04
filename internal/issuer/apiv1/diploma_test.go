package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/stretchr/testify/assert"
)

func mockX509KeyPair(t *testing.T) string {
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
	//defer os.Remove(privateFS.Name())
	err = pem.Encode(privateFS, privateBlock)
	assert.NoError(t, err)

	//publicFS, err := os.CreateTemp("", "public.pem")
	//assert.NoError(t, err)
	//defer os.Remove(publicFS.Name())
	//_, err = publicFS.WriteString("public key")
	//assert.NoError(t, err)
	//err = publicFS.Close()
	//assert.NoError(t, err)

	return privateFS.Name()
}

func TestDiploma(t *testing.T) {
	tts := []struct {
		name string
	}{
		{
			name: "Diploma",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			privPath := mockX509KeyPair(t)
			cfg := &model.Cfg{
				Common:           model.Common{},
				AuthenticSources: map[string]model.AuthenticSource{},
				APIGW:            model.APIGW{},
				Issuer: model.Issuer{
					APIServer:          model.APIServer{},
					Identifier:         "",
					GRPCServer:         model.GRPCServer{},
					SigningKeyPath:     privPath,
					JWTAttribute:       model.JWTAttribute{},
					IssuerURL:          "",
					CredentialOfferURL: "",
				},
				Verifier:   model.Verifier{},
				Datastore:  model.Datastore{},
				Registry:   model.Registry{},
				Persistent: model.Persistent{},
				MockAS:     model.MockAS{},
				UI:         model.UI{},
				Portal:     model.Portal{},
			}

			log := logger.NewSimple("test")

			tp, err := trace.NewForTesting(ctx, "test", log)
			assert.NoError(t, err)

			client, err := New(ctx, nil, cfg, tp, log)
			assert.NoError(t, err)

			diplomaClient, err := newDiplomaClient(client, tp, log)
			if err != nil {
				t.Fatalf("newDiplomaClient() error = %v", err)
			}

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

			signedJWT, err := diplomaClient.sdjwt(ctx, body, jwk, &salt)
			assert.NoError(t, err)

			fmt.Println(signedJWT)

		})
	}
}
