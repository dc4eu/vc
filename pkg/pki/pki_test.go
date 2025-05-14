package pki

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseCertificateFromFile(t *testing.T) {
	tts := []struct {
		name          string
		fileName      string
		numberOfCerts int
	}{
		{
			name:          "one cert, no chain",
			fileName:      "testdata/chain_1.golden",
			numberOfCerts: 1,
		},
		{
			name:          "one cert, one root",
			fileName:      "testdata/chain_2.golden",
			numberOfCerts: 2,
		},
		{
			name:          "one cert, one intermediate, one root",
			fileName:      "testdata/chain_3.golden",
			numberOfCerts: 3,
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			cert, chain, err := ParseX509CertificateFromFile(tt.fileName)
			assert.NoError(t, err)
			assert.NotNil(t, cert)
			assert.NotNil(t, chain)
			assert.Equal(t, tt.numberOfCerts, len(chain))
			for i, v := range chain {
				fmt.Println(i, v.Subject, v.NotAfter, v.DNSNames)
			}
		})
	}
}
