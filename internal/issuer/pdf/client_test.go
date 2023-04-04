package pdf

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"testing"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"go.mozilla.org/pkcs7"

	pdflog "github.com/pdfcpu/pdfcpu/pkg/log"
	pdftypes "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
	"github.com/stretchr/testify/assert"
)

var (
	estimateSignatureLength int = 2
)

func TestSign(t *testing.T) {
	t.SkipNow()
	tts := []struct {
		name string
		hash string
	}{
		{
			name: "OK",
			hash: "c50070c14a22b7f4f737e744d1d5fea8603f1cc605adff914ecdf84513ed63b0",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			//cert, err := createTestCertificate(x509.SHA256WithRSA)
			//assert.NoError(t, err)

			//		got, err := sign([]byte(tt.hash), cert.Certificate, *cert.PrivateKey)
			//		assert.NoError(t, err)
			//		assert.NotEmpty(t, got)
		})
	}
}

func TestSignFile(t *testing.T) {
	tts := []struct {
		run bool
		in  string
		out string
	}{
		{
			run: false,
			in:  "1.pdf",
			out: "1-s.pdf",
		},
		{
			run: true,
			in:  "3.pdf",
			out: "3-x.pdf",
		},
	}
	for _, tt := range tts {
		t.Run(tt.in, func(t *testing.T) {
			if !tt.run {
				t.SkipNow()
			}
			signer := Pkcs7Signer{}
			err := pdfapi.SignFile(tt.in, tt.out, nil, signer)
			assert.NoError(t, err)
			pdflog.SetDefaultWriteLogger()
		})
	}
}

// Pkcs7Signer is a signer for pkcs7
type mockSigner struct {
	pdfapi.Signer
}

// EstimateSignatureLength returns the estimated length of the signature
func (s mockSigner) EstimateSignatureLength() int {
	return estimateSignatureLength
}

// Sign signs the given reader
func (s mockSigner) Sign(r io.Reader) ([]byte, error) {
	cert, key := mockCert(&testing.T{})
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	hash := h.Sum(b)

	// Initialize a SignedData struct with content to be signed
	signedData, err := pkcs7.NewSignedData(hash)
	if err != nil {
		return nil, fmt.Errorf("Cannot initialize signed data: %s", err)
	}

	signedData.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)

	// Add the signing cert and private key
	fmt.Println(reflect.TypeOf(key))
	if err := signedData.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("Cannot add signer: %s", err)
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		return nil, fmt.Errorf("Cannot finish signing data: %s", err)
	}

	//if err := pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: detachedSignature}); err != nil {
	//	return nil, err
	//}
	return detachedSignature, nil
}

//func TestPrepareSignature_sig(t *testing.T) {
//	type want struct {
//		sig string
//	}
//	tts := []struct {
//		name string
//		want pdftypes.Dict
//	}{
//		{
//			name: "test",
//			want: pdftypes.Dict{
//				"Type":      pdftypes.Name("Sig"),
//				"Filter":    pdftypes.Name("Adobe.PPKLite"),
//				"SubFilter": pdftypes.Name("adbe.pkcs7.detached"),
//				"Contents":  pdftypes.HexLiteral(`0000`),
//				"ByteRange": pdftypes.NewNumberArray(0, 0, 0, 0),
//				"M":         pdftypes.StringLiteral("D:20210101000000+00'00'"),
//			},
//		},
//	}
//	for _, tt := range tts {
//		t.Run(tt.name, func(t *testing.T) {
//			ctx, err := pdfapi.ReadContextFile("1.pdf")
//			estimateSignatureLength = 2
//			assert.NoError(t, err)
//
//			signer := mockSigner{}
//			got, err := pdfapi.PrepareSignature(ctx, signer)
//			assert.NoError(t, err)
//
//			for k, v := range tt.want {
//				g := *got
//				switch k {
//				case "M":
//					assert.NotEmpty(t, g[k])
//				default:
//					assert.Equal(t, v, g[k])
//				}
//			}
//		})
//	}
//}

func TestPrepareSignature_root(t *testing.T) {
	tts := []struct {
		name string
		have string
		want pdftypes.Dict
	}{
		{
			name: "OK",
			have: "1.pdf",
			want: pdftypes.Dict{
				"AcroForm": *pdftypes.NewIndirectRef(10, 0),
				"Names": pdftypes.Dict{
					"EmbeddedFiles": pdftypes.Dict{
						"Names": pdftypes.NewNumberArray(),
					},
				},
				"Pages": *pdftypes.NewIndirectRef(1, 0),
				"Type":  pdftypes.Name("Catalog"),
			},
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx, err := pdfapi.ReadContextFile(tt.have)
			estimateSignatureLength = 2
			assert.NoError(t, err)

			signer := mockSigner{}
			err = pdfapi.PrepareSignature(ctx, signer)
			assert.NoError(t, err)

			rootDict, err := ctx.XRefTable.Catalog()
			assert.NoError(t, err)
			assert.Equal(t, tt.want, rootDict)
		})
	}
}
