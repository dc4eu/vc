package httphelpers

import (
	"context"
	"crypto/tls"
	"vc/pkg/logger"
)

type tlsHandler struct {
	client *Client
	log    *logger.Log
}

func (t *tlsHandler) Standard(ctx context.Context) *tls.Config {
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
	}

	return cfg
}
