package vcclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"vc/pkg/model"
	"vc/pkg/socialsecurity"

	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

func mockHappyHttServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/document", func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, req.URL.Path, "/api/v1/document")
		assert.Equal(t, req.Method, http.MethodPost)
		rw.Write(golden.Get(t, "documentGetReplyOK.golden"))
	})

	mux.HandleFunc("/api/v1/document/list", func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, req.URL.Path, "/api/v1/document/list")
		assert.Equal(t, req.Method, http.MethodPost)
		rw.Write(golden.Get(t, "documentListReplyOK.golden"))
	})

	mux.HandleFunc("/authorize", func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, req.URL.Path, "/authorize")
		assert.Equal(t, req.Method, http.MethodGet)
		rw.WriteHeader(http.StatusFound)
		//assert.Equal(t, req.Header.Get("Content-Type"), "application/json")
		rw.Write(golden.Get(t, "oidcAuthorizeReplyOK.golden"))
	})

	mux.HandleFunc("/op/par", func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, req.URL.Path, "/op/par")
		assert.Equal(t, req.Method, http.MethodPost)
		//rw.WriteHeader(http.StatusFound)
		//assert.Equal(t, req.Header.Get("Content-Type"), "application/json")
		rw.Write(golden.Get(t, "oidcAuthorizeReplyOK.golden"))
	})

	server := httptest.NewServer(mux)
	return server
}

func mockClient(ctx context.Context, t *testing.T, url string) *Client {
	_, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	client, err := New(&Config{
		URL: url,
	})
	if err != nil {
		t.FailNow()
		return nil
	}

	return client
}

func TestGet(t *testing.T) {
	tts := []struct {
		name                 string
		query                *DocumentGetQuery
		expected             *model.Document
		expectedDocumentData *socialsecurity.EHICDocument
	}{
		{
			name: "success",
			query: &DocumentGetQuery{
				AuthenticSource: "test_authentic_source",
				DocumentType:    "test_document_type",
				DocumentID:      "test_document_id",
			},
			expected: &model.Document{
				Meta: &model.MetaData{
					AuthenticSource: "SUNET",
					DocumentVersion: "1.0.0",
					DocumentType:    "EHIC",
					DocumentID:      "test_document_id",
					RealData:        false,
					Collect: &model.Collect{
						ID:         "test_collect_id",
						ValidUntil: 1731767173,
					},
					Revocation: &model.Revocation{
						ID:      "test_revocation_id",
						Revoked: false,
						Reference: model.RevocationReference{
							AuthenticSource: "SUNET",
							DocumentType:    "EHIC",
							DocumentID:      "test_document_id",
						},
						RevokedAt: 0,
						Reason:    "",
					},
					CredentialValidFrom:       695706629,
					CredentialValidTo:         -1730367911,
					DocumentDataValidationRef: "",
				},
			},
			expectedDocumentData: &socialsecurity.EHICDocument{
				PersonalAdministrativeNumber: "123123123",
				IssuingAuthority: socialsecurity.IssuingAuthority{
					ID:   "1231231",
					Name: "SUNET",
				},
				IssuingCountry: "SE",
				DateOfExpiry:   "2038-01-19",
				DateOfIssuance: "2021-01-19",
				DocumentNumber: "123123123",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			httpServer := mockHappyHttServer(t)
			defer httpServer.Close()

			client := mockClient(ctx, t, httpServer.URL)
			got, _, err := client.Document.Get(ctx, tt.query)
			assert.NoError(t, err)

			documentData, err := tt.expectedDocumentData.Marshal()
			assert.NoError(t, err)
			tt.expected.DocumentData = documentData

			assert.Equal(t, tt.expected, got)
		})
	}
}
