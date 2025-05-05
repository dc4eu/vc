package openid4vp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/skip2/go-qrcode"
	"image/png"
	"net/url"
)

func GenerateQR(qrURI string, recoveryLevel qrcode.RecoveryLevel, size int) (*QRReply, error) {
	parsedURI, err := url.ParseRequestURI(qrURI)
	if err != nil || parsedURI.Scheme == "" || parsedURI.Host == "" {
		return nil, errors.New("invalid URL format")
	}

	if size == 0 {
		size = 256
	}

	maxChars := getMaxChars(recoveryLevel)
	if len(qrURI) > maxChars {
		return nil, fmt.Errorf("URL is too long, max allowed: %d characters for this error correction level", maxChars)
	}

	var buf bytes.Buffer
	qrCode, err := qrcode.New(qrURI, recoveryLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to create QRReply-code: %w", err)
	}

	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	err = png.Encode(encoder, qrCode.Image(size))
	encoder.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to convert QRReply-code to PNG: %w", err)
	}

	return &QRReply{
		Base64Image: buf.String(),
		URI:         qrURI,
	}, nil
}

func getMaxChars(recoveryLevel qrcode.RecoveryLevel) int {
	switch recoveryLevel {
	case qrcode.Low:
		return 2953
	case qrcode.Medium:
		return 2331
	case qrcode.High:
		return 1663
	case qrcode.Highest:
		return 1273
	default:
		return 1273
	}
}
