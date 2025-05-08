package vcclient

import (
	"context"
	"fmt"
	"net/http"
	"vc/pkg/logger"
	"vc/pkg/model"
)

type rootHandler struct {
	client             *Client
	serviceBaseURL     string
	log                *logger.Log
	defaultContentType string
}

type UploadRequest struct {
	Meta                *model.MetaData        `json:"meta" validate:"required"`
	Identities          []model.Identity       `json:"identities,omitempty" validate:"dive"`
	DocumentDisplay     *model.DocumentDisplay `json:"document_display,omitempty"`
	DocumentData        map[string]any         `json:"document_data" validate:"required"`
	DocumentDataVersion string                 `json:"document_data_version,omitempty" validate:"required,semver"`
}

func (s *rootHandler) Upload(ctx context.Context, body *UploadRequest) (*http.Response, error) {
	s.log.Info("Upload")

	url := fmt.Sprintf("%s/%s", s.serviceBaseURL, "upload")

	resp, err := s.client.call(ctx, http.MethodPost, url, s.defaultContentType, body, nil, false)
	if err != nil {
		return resp, err
	}
	return resp, nil
}
