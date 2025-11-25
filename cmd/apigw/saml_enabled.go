//go:build saml

package main

import (
	"context"
	"vc/internal/apigw/httpserver"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/saml"
)

func initSAMLService(ctx context.Context, cfg *model.Cfg, log *logger.Log) (httpserver.SAMLService, error) {
	if !cfg.APIGW.SAML.Enabled {
		return nil, nil
	}

	samlService, err := saml.New(ctx, &cfg.APIGW.SAML, log)
	if err != nil {
		return nil, err
	}

	log.Info("SAML service initialized", "entity_id", cfg.APIGW.SAML.EntityID)
	return samlService, nil
}
