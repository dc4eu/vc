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

// QR is a collection of fields representing a QR code
type QR struct {
	Base64Image string `json:"base64_image" bson:"base64_image" validate:"required"`
	URL         string `json:"url" bson:"url" validate:"required"`
}

func GenerateQR(inputURL string, recoveryLevel qrcode.RecoveryLevel, size int) (*QR, error) {
	parsedURL, err := url.ParseRequestURI(inputURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, errors.New("invalid URL format")
	}

	if size == 0 {
		size = 256
	}

	maxChars := getMaxChars(recoveryLevel)
	if len(inputURL) > maxChars {
		return nil, fmt.Errorf("URL is too long, max allowed: %d characters for this error correction level", maxChars)
	}

	var buf bytes.Buffer
	qrCode, err := qrcode.New(inputURL, recoveryLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to create QR-code: %w", err)
	}

	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	err = png.Encode(encoder, qrCode.Image(size))
	encoder.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to convert QR-code to PNG: %w", err)
	}

	return &QR{
		Base64Image: buf.String(),
		URL:         inputURL,
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
