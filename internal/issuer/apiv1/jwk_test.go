package apiv1

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"
	"vc/internal/issuer/auditlog"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

var nonRandom = bytes.NewReader([]byte("01234567890123456789012345678901234567890123456789ABCDEF"))

func mockGenerateECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), nonRandom)
	assert.NoError(t, err)

	return privateKey
}

func TestGenereateECDSAKey(t *testing.T) {
	tts := []struct {
		name string
	}{
		{
			name: "Test 1",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			mockGenerateECDSAKey(t)
		})
	}
}

func mockClient(t *testing.T) *Client {
	ctx := context.TODO()
	cfg := &model.Cfg{
		Common: model.Common{
			HTTPProxy:  "",
			Production: false,
			Log:        model.Log{},
			Mongo:      model.Mongo{},
			Tracing: model.OTEL{
				Addr:    "",
				Type:    "jaeger",
				Timeout: 0,
			},
			Queues:   model.Queues{},
			KeyValue: model.KeyValue{},
			QR:       model.QRCfg{},
			Kafka:    model.Kafka{},
		},
		AuthenticSources: map[string]model.AuthenticSource{},
		APIGW:            model.APIGW{},
		Issuer:           model.Issuer{},
		Verifier:         model.Verifier{},
		Datastore:        model.Datastore{},
		Registry:         model.Registry{},
		Persistent:       model.Persistent{},
		MockAS:           model.MockAS{},
		UI:               model.UI{},
	}

	auditlog, err := auditlog.New(ctx, cfg, logger.NewSimple("testing_apiv1"))
	assert.NoError(t, err)

	tracer, err := trace.New(ctx, cfg, logger.NewSimple("testing_apiv1"), "projectName", "serviceName")
	assert.NoError(t, err)

	client := &Client{
		cfg:        cfg,
		log:        logger.NewSimple("testing_apiv1"),
		tp:         tracer,
		auditLog:   auditlog,
		privateKey: mockGenerateECDSAKey(t),
	}

	client.createJWK(ctx)

	return client
}

// Sometimes this test does not behave deterministically
func TestCreateJWK(t *testing.T) {
	tts := []struct {
		name string
		want jwt.MapClaims
	}{
		{
			name: "Test 1",
			want: jwt.MapClaims{
				"jwk": jwt.MapClaims{
					"crv": "P-256",
					"kid": "singing_",
					"kty": "EC",
					"d":   "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI",
					"x":   "YiPlXIq3VAfGMMoVzAKB2wYLy0e5n9nYkjmAbBCIdBs",
					"y":   "d2P8TyUlmM1jop1yUH-fHBYXgbijF0IY4fPA7bQZuDE",
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			client := mockClient(t)

			err := client.createJWK(context.Background())
			assert.NoError(t, err)

			if diff := cmp.Diff(tt.want, client.jwkClaim); diff != "" {
				t.Errorf("MakeGatewayInfo() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}