package openid4vp

import (
	"github.com/skip2/go-qrcode"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateQR(t *testing.T) {
	type args struct {
		uri           string
		recoveryLevel qrcode.RecoveryLevel
		size          int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Simple qr code",
			args: args{
				uri:           "openid4vp://authorize?key=val",
				recoveryLevel: qrcode.Medium,
				size:          256,
			},
			wantErr: false,
		},
		{
			name: "Simple qr code with error",
			args: args{
				uri:           "ej_en_uri",
				recoveryLevel: qrcode.Medium,
				size:          256,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateQR(tt.args.uri, tt.args.recoveryLevel, tt.args.size)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateQR() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && !tt.wantErr {
				t.Errorf("GenerateQR() returned unexpected error: %v", err)
			}

			if err == nil && tt.wantErr {
				t.Errorf("GenerateQR() expected an error but got none")
			}

			if err != nil && tt.wantErr {
				return
			}

			assert.Equal(t, tt.args.uri, got.URI)
			assert.NotEmpty(t, got.Base64Image)
		})
	}
}
