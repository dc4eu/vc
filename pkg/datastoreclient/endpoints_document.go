package datastoreclient

import (
	"context"
	"fmt"
	"net/http"
	"vc/pkg/model"
)

type documentService struct {
	client  *Client
	service string
}

// DocumentGetQuery is the query for GetDocument
type DocumentGetQuery struct {
	AuthenticSource string `json:"authentic_source"`
	DocumentType    string `json:"document_type"`
	DocumentID      string `json:"document_id"`
}

// Get gets a document
func (s *documentService) Get(ctx context.Context, query *DocumentGetQuery) (*model.Document, *http.Response, error) {
	url := fmt.Sprintf("%s", s.service)
	reply := &model.Document{}
	resp, err := s.client.call(ctx, http.MethodPost, url, nil, reply)
	if err != nil {
		return nil, resp, err
	}
	return reply, resp, nil
}

// DocumentListQuery is the query for ListDocument
type DocumentListQuery struct {
	AuthenticSource string          `json:"authentic_source"`
	Identity        *model.Identity `json:"identity"`
	DocumentType    string          `json:"document_type"`
	ValidTo         int64           `json:"valid_to"`
	ValidFrom       int64           `json:"valid_from"`
}

func (s *documentService) List(ctx context.Context, query *DocumentListQuery) ([]model.DocumentList, *http.Response, error) {
	url := fmt.Sprintf("%s/%s", s.service, "list")
	reply := []model.DocumentList{}
	resp, err := s.client.call(ctx, http.MethodPost, url, nil, reply)
	if err != nil {
		return nil, resp, err
	}
	return reply, resp, nil
}

// DocumentCollectIDQuery is the query for CollectID
type DocumentCollectIDQuery struct {
	AuthenticSource string          `json:"authentic_source"`
	DocumentType    string          `json:"document_type"`
	CollectID       string          `json:"collect_id"`
	Identity        *model.Identity `json:"identity"`
}

// DocumentCollectIDReply is the reply for CollectID
type DocumentCollectIDReply struct {
	DocumentData any `json:"document_data"`
}

func (s *documentService) CollectID(ctx context.Context, query *DocumentCollectIDQuery) (*DocumentCollectIDReply, *http.Response, error) {
	url := fmt.Sprintf("%s/%s", s.service, "collect_id")
	reply := &DocumentCollectIDReply{}
	resp, err := s.client.call(ctx, http.MethodPost, url, nil, reply)
	if err != nil {
		return nil, resp, err
	}
	return reply, resp, nil
}
