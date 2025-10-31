package httphelpers

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func mockClient(ctx context.Context, t *testing.T) *Client {
	t.Helper()

	log := logger.NewSimple("httphelper")

	tracer, err := trace.NewForTesting(ctx, "httphelper", log)
	assert.NoError(t, err)

	cfg := &model.Cfg{}

	client, err := New(ctx, tracer, cfg, log)
	assert.NoError(t, err)

	return client
}

type mockBindingURI struct {
	ID string `uri:"id"`
}

func TestBindingRequest(t *testing.T) {
	tts := []struct {
		name            string
		inputStructName string
		httpMethod      string
		httpURL         *url.URL
		acceptHeader    string
		want            any
	}{
		{
			name:            "test1",
			httpMethod:      http.MethodGet,
			httpURL:         &url.URL{Path: "/statuslists/12345"},
			inputStructName: "mockBindingURI",
			acceptHeader:    "application/json",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			client := mockClient(ctx, t)

			ginContext := &gin.Context{
				Request: &http.Request{
					Method: tt.httpMethod,
					URL:    tt.httpURL,
					Header: http.Header{
						"Accept": []string{tt.acceptHeader},
					},
				},
				Writer: nil,
				Params: gin.Params{},
				Keys:   map[any]any{},
			}

			switch tt.inputStructName {
			case "mockBindingURI":
				req := &mockBindingURI{}
				err := client.Binding.Request(ctx, ginContext, req)
				assert.NoError(t, err)

				t.Logf("output: %s", req)
			default:
				t.Fatalf("unknown input struct name: %s", tt.inputStructName)
			}

		})
	}
}
