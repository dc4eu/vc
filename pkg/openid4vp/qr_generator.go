package openid4vp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"net/url"

	"github.com/skip2/go-qrcode"
)

func GenerateQR(uri *url.URL, recoveryLevel qrcode.RecoveryLevel, size int) (*QRReply, error) {
	if size == 0 {
		size = 256
	}

	var buf bytes.Buffer
	qrCode, err := qrcode.New(uri.String(), recoveryLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to create QRReply-code: %w", err)
	}

	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	if err := png.Encode(encoder, qrCode.Image(size)); err != nil {
		return nil, err
	}

	if err := encoder.Close(); err != nil {
		return nil, err
	}

	return &QRReply{
		Base64Image: buf.String(),
		URI:         uri.String(),
	}, nil
}
