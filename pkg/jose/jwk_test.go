package jose

import "testing"

func TestJWK(t *testing.T) {
	tts := []struct {
		name           string
		signingKeyPath string
	}{
		{
			name:           "test1",
			signingKeyPath: "../../developer_tools/private_ec256.pem",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			jwk, _, err := CreateJWK(tt.signingKeyPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Log(jwk)
		})
	}
}
