package pdf

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"

	"github.com/madflojo/testcerts"
	"go.mozilla.org/pkcs7"
)

var b64 = []byte(`JVBERi0xLjcKJeLjz9MKNyAwIG9iago8PC9OYW1lczw8L0VtYmVkZGVkRmlsZXM8PC9OYW1lc1td
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
DwAA//+YqQV8CmVuZHN0cmVhbQplbmRvYmoKc3RhcnR4cmVmCjEyODMKJSVFT0YK`)

// Client is the client object for pdf
type Client struct {
}

// New creates a new pdf client
func New() *Client {
	c := &Client{}

	return c
}

// Pkcs7Signer is a signer for pkcs7
type Pkcs7Signer struct {
	pdfapi.Signer
}

// EstimateSignatureLength returns the estimated length of the signature
func (s Pkcs7Signer) EstimateSignatureLength() int {
	return 10000
}

func pki() (*x509.Certificate, *rsa.PrivateKey, error) {
	c, k, err := testcerts.GenerateCerts()
	if err != nil {
		return nil, nil, err
	}

	certDecode, _ := pem.Decode(c)
	keyDecode, _ := pem.Decode(k)

	cert, err := x509.ParseCertificate(certDecode.Bytes)
	if err != nil {
		return nil, nil, err
	}

	key, err := x509.ParsePKCS1PrivateKey(keyDecode.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// Sign signs the given reader
func (s Pkcs7Signer) Sign(r io.Reader) ([]byte, error) {
	cert, key, err := pki()
	if err != nil {
		return nil, err
	}

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

func (c *Client) sign(in, out string) {
	signer := Pkcs7Signer{}
	pdfapi.SignFile(in, out, nil, signer)
}

func cert() ([]byte, []byte, error) {
	c, k, err := testcerts.GenerateCerts()
	if err != nil {
		return nil, nil, err
	}
	return c, k, nil
}
