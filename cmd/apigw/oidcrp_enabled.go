//go:build oidcrp

package main

import (
	"context"
	"vc/internal/apigw/httpserver"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/oidcrp"
)

func initOIDCRPService(ctx context.Context, cfg *model.Cfg, log *logger.Log) (httpserver.OIDCRPService, error) {
	if !cfg.APIGW.OIDCRP.Enabled {
		return nil, nil
	}

	oidcrpService, err := oidcrp.New(ctx, &cfg.APIGW.OIDCRP, log)
	if err != nil {
		return nil, err
	}

	log.Info("OIDC RP service initialized", "issuer_url", cfg.APIGW.OIDCRP.IssuerURL)
	return oidcrpService, nil
}
