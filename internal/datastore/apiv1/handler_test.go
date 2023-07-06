package apiv1

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"vc/internal/datastore/db"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func mockClient(t *testing.T, caURL string) *Client {
	ctx := context.Background()
	log := logger.NewSimple("testing")
	cfg := &model.Cfg{
		Issuer: model.Issuer{
			CA: model.CA{
				Addr:     caURL,
				Token:    "test-token",
				KeyLabel: "test-key-label",
				KeyType:  "secp256r1",
			},
		},
	}

	pool, err := dockertest.NewPool("")
	assert.NoError(t, err)

	resource, err := pool.Run("mongo", "5.0", []string{
		"MONGO_INITDB_ROOT_USERNAME=root",
		"MONGO_INITDB_ROOT_PASSWORD=password",
	})
	assert.NoError(t, err)
	var dbService *db.Service

	if err = pool.Retry(func() error {
		dockerDB, err := mongo.Connect(
			context.TODO(),
			options.Client().ApplyURI(fmt.Sprintf("mongodb://root:password@localhost:%s", resource.GetPort("27017/tcp"))),
		)
		assert.NoError(t, err)

		dbService := &db.Service{
			DBClient: dockerDB,
		}

		dbService.EHICColl = &db.EHICColl{
			Service: dbService,
			Coll:    dbService.DBClient.Database("datastore").Collection("ehic"),
		}
		dbService.PDA1Coll = &db.PDA1Coll{
			Service: dbService,
			Coll:    dbService.DBClient.Database("datastore").Collection("pda1"),
		}
		return nil
	}); err != nil {
		assert.NoError(t, err)
	}

	c, err := New(ctx, dbService, cfg, log)
	assert.NoError(t, err)

	return c
}

func mockGenericEndpointServer(t *testing.T, mux *http.ServeMux, token, method, url string, reply []byte, statusCode int) {
	mux.HandleFunc(url,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "Application/json")
			w.WriteHeader(statusCode)
			testMethod(t, r, method)
			testURL(t, r, url)
			w.Write(reply)
		},
	)
}

func testMethod(t *testing.T, r *http.Request, want string) {
	assert.Equal(t, want, r.Method)
}

func testURL(t *testing.T, r *http.Request, want string) {
	assert.Equal(t, want, r.RequestURI)
}

func testBody(t *testing.T, r *http.Request, want string) {
	buffer := new(bytes.Buffer)
	_, err := buffer.ReadFrom(r.Body)
	assert.NoError(t, err)

	got := buffer.String()
	require.JSONEq(t, want, got)
}

func mockSetup(t *testing.T) (*http.ServeMux, *httptest.Server, *Client) {
	mux := http.NewServeMux()

	server := httptest.NewServer(mux)

	client := mockClient(t, server.URL)

	return mux, server, client
}
