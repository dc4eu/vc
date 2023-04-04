package apiv1

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"wallet/internal/issuer/ca"
	"wallet/internal/issuer/db"
	"wallet/pkg/logger"
	"wallet/pkg/model"

	"github.com/google/uuid"
	"github.com/masv3971/gosunetca/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var mockBase64PDF = `JVBERi0xLjcKJeLjz9MKNyAwIG9iago8PC9OYW1lczw8L0VtYmVkZGVkRmlsZXM8PC9OYW1lc1td
Pj4+Pi9QYWdlcyAxIDAgUi9UeXBlL0NhdGFsb2c+PgplbmRvYmoKNCAwIG9iago8PC9GaWx0ZXIv
RmxhdGVEZWNvZGUvTGVuZ3RoIDE0MD4+CnN0cmVhbQp4AaTOsarCMBQG4D1P8Y/3Lsf/pE3SrIUq
uAlnl2qSYhFFF1/fzV18gY+P2DtidZSQ8HKjYbNtofhSQ+vmpDHnufYnX4ZOU67RF+Ya27lXH6FR
SFjDZI5CEjtHIYnlB+nLg5fP4QEKu4wFo0ElJgxUCT2s4O/+XC63+XrUf9iKyXBw7wAAAP//hj8+
JgplbmRzdHJlYW0KZW5kb2JqCjkgMCBvYmoKPDwvRmlsdGVyL0ZsYXRlRGVjb2RlL0xlbmd0aCAx
NDA+PgpzdHJlYW0KeAGkzrGqwjAUBuA9T/GP9y7HP2lz0qyFKrgJZ5dqkmIRRRdf381dfIGPj9g7
YnWUmPByo2GzbbGEUmPr5uQ157n2p1CGzqdcNRTmqu3c+6DwKiSsYTJHIYmdo5DE8oP05SHI5/AA
hV3GgtHgRRMGeok9rODv/lwut/l6DP+wFZPh4N4BAAD//4ZKPicKZW5kc3RyZWFtCmVuZG9iagox
NiAwIG9iago8PC9GaWx0ZXIvRmxhdGVEZWNvZGUvTGVuZ3RoIDE0MT4+CnN0cmVhbQp4AaTOvarC
QBRF4X6eYpf3Fh73mWQmmTYQBTvhvEB0fjCFKBa+vtjYi92qFh9xcMTqKGHA002G7a6G7HMJtVsG
jSktpT/5PHY6pBJ9Ziqxnnv1ERqFhFXM5igksXcUkmg/nL40ePkY7qCwS2iY7J2KkSqhh2X8PS7t
urktrfzDVsyGo3sFAAD//4OgPhgKZW5kc3RyZWFtCmVuZG9iagoyMiAwIG9iago8PC9GaWx0ZXIv
RmxhdGVEZWNvZGUvRmlyc3QgNjEvTGVuZ3RoIDM0Ny9OIDEwL1R5cGUvT2JqU3RtPj4Kc3RyZWFt
CniczJLPitswEIdfZV6gK43+WQZjqNOGLqXUbBZaCDko1iS4pNJiK2X79kW2STe59VCIL8MYZj7/
Po8EDgK0BQ1oDVgQRgIqkEICSlAaATVoVYBAMNyC4FBIAwhWyqpiqxgShTSCAg5PrHUDhQQ4NU80
xvPQ0Qhi6p9/vxBr3ZHqepo8xWHz4jqqqrpm6xhSVbH1QXvhSR+kK9CUpSO1F95KLEoywvOSzKFT
KAzovLOuWTvEbkNpy9oPa/ZMr4k9/nRHauaymsvjjn3/uv9BXcqwid+4kTKUfaLTL0p959418eTZ
x9BF34cj+9aH92HsL/3mvE85QY6Bc5g8v4RZNJRXGuSNB1R3KGIVz/lb2efej1ubl+3YF/K9a+Lr
lgMHXeoHYfnlAavwwZZ/X+yu//sl3njtBs1bOYLfHgneuxzU/8NOBsgZMN3LcjaLoH+nvQX8CQAA
//+tVxvvCmVuZHN0cmVhbQplbmRvYmoKNiAwIG9iago8PC9DcmVhdGlvbkRhdGUoRDoyMDIzMDMw
MjIwNTU0OSswMCcwMCcpL01vZERhdGUoRDoyMDIzMDMwMjIwNTU0OSswMCcwMCcpL1Byb2R1Y2Vy
KHBkZmNwdSB2MC40LjAgZGV2KT4+CmVuZG9iagoxNyAwIG9iago8PC9GaWx0ZXIvRmxhdGVEZWNv
ZGUvSURbPGI0ZGRiZTAyNjgyMTBkY2YzYWExYjlkNjliYTM5NmY1PiA8YjRkZGJlMDI2ODIxMGRj
ZjNhYTFiOWQ2OWJhMzk2ZjU+XS9JbmRleFswIDIzXS9JbmZvIDYgMCBSL0xlbmd0aCA4MC9Sb290
IDcgMCBSL1NpemUgMjMvVHlwZS9YUmVmL1dbMSAyIDJdPj4Kc3RyZWFtCnicJMvtCYAwDITh99LW
bxAUnMORHMjpXKhy5M9DLrnA0ntwMRsZxAOeQvV13DMW6QY4EGyG/GimmkHhZSu+na6sWZnMqPjg
DwAA//+YqQV8CmVuZHN0cmVhbQplbmRvYmoKc3RhcnR4cmVmCjEyODMKJSVFT0YK`

func mockClient(t *testing.T, caURL string) *Client {
	ctx := context.Background()
	log := logger.NewSimple("testing")
	cfg := &model.Cfg{
		Issuer: model.Issuer{
			CA: model.CA{
				ServerURL: caURL,
				Token:     "test-token",
				KeyLabel:  "test-key-label",
				KeyType:   "secp256r1",
			},
		},
	}
	ca, err := ca.New(ctx, cfg, log)
	assert.NoError(t, err)

	db, err := db.New(ctx, cfg, log)
	assert.NoError(t, err)

	c, err := New(ctx, ca, db, cfg, log)
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

func TestSignPDF(t *testing.T) {
	tts := []struct {
		name string
		have *SignPDFRequest
		want *SignPDFReply
	}{
		{
			name: "OK",
			have: &SignPDFRequest{
				PDF: mockBase64PDF,
			},
			want: &SignPDFReply{
				TransactionID: "xyz",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			mux, server, client := mockSetup(t)
			defer server.Close()

			mockGenericEndpointServer(t, mux, client.cfg.Issuer.CA.Token, http.MethodPost, "/pkcs11_sign", mocks.JSONSignDocumentReply200, http.StatusOK)

			got, err := client.SignPDF(context.Background(), tt.have)
			assert.NoError(t, err)
			_, err = uuid.Parse(got.TransactionID)
			assert.NoError(t, err)

		})
	}
}
