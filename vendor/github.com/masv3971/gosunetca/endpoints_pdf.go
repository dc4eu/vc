package gosunetca

import (
	"context"
	"fmt"
	"net/http"

	"github.com/masv3971/gosunetca/types"
)

// PDFService is the service for signing
type PDFService struct {
	client  *Client
	baseURL string
}

// Sign signs documents
func (s *PDFService) Sign(ctx context.Context, body *types.Document) (*types.Document, *http.Response, error) {
	body.Reason = s.client.reason
	body.Location = s.client.location

	if err := check(body); err != nil {
		return nil, nil, err
	}

	s.client.Log.Info("PDF sign", "transaction_id", body.TransactionID)

	reply := &types.Document{}

	resp, err := s.client.call(
		ctx,
		http.MethodPost,
		fmt.Sprintf("%s/sign", s.baseURL),
		body,
		reply,
	)
	if err != nil {
		return nil, resp, err
	}
	return reply, resp, nil
}

// Validate validates documents
func (s *PDFService) Validate(ctx context.Context, body *types.Document) (*types.Validation, *http.Response, error) {
	s.client.Log.Info("PDF validate")

	reply := &types.Validation{}

	resp, err := s.client.call(
		ctx,
		http.MethodPost,
		fmt.Sprintf("%s/validate", s.baseURL),
		body,
		reply,
	)
	if err != nil {
		return nil, resp, err
	}

	return reply, resp, nil
}
