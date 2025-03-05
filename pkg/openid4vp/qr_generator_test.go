package openid4vp

import (
	"github.com/skip2/go-qrcode"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateQR(t *testing.T) {
	type args struct {
		url           string
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
				url:           "https://www.someexampledomain.com/path1/path2/path3?value=Hello",
				recoveryLevel: qrcode.Medium,
				size:          256,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateQR(tt.args.url, tt.args.recoveryLevel, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateQR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.args.url, got.URL)
			assert.NotEmpty(t, got.Base64Image)
		})
	}
}
