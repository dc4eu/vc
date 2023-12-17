package gosunetca

import (
	"context"
	"fmt"
	"net/http"

	"github.com/masv3971/gosunetca/types"
)

// DocumentService is the service for signing
type DocumentService struct {
	client  *Client
	baseURL string
}

// Sign signs documents
func (s *DocumentService) PDFSign(ctx context.Context, body *types.Document) (*types.Document, *http.Response, error) {
	body.Reason = s.client.reason
	body.Location = s.client.location
	body.ContactInfo = s.client.contactInfo
	body.Name = s.client.name

	if err := check(body); err != nil {
		return nil, nil, err
	}

	s.client.Log.Info("PDF sign", "transaction_id", body.TransactionID)

	reply := &types.Document{}

	resp, err := s.client.call(
		ctx,
		http.MethodPost,
		fmt.Sprintf("%s/pdf/sign", s.baseURL),
		body,
		reply,
	)
	if err != nil {
		return nil, resp, err
	}
	return reply, resp, nil
}

// Validate validates documents
func (s *DocumentService) PDFValidate(ctx context.Context, body *types.Document) (*types.Validation, *http.Response, error) {
	s.client.Log.Info("PDF validate", "base64PDF", fmt.Sprintf("%s...%s", body.Data[:5], body.Data[len(body.Data)-5:]))

	reply := &types.Validation{}

	resp, err := s.client.call(
		ctx,
		http.MethodPost,
		fmt.Sprintf("%s/pdf/validate", s.baseURL),
		body,
		reply,
	)
	if err != nil {
		return nil, resp, err
	}

	return reply, resp, nil
}
