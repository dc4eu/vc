package vcclient

import (
	"context"
	"fmt"
	"net/http"
	"vc/pkg/logger"
	"vc/pkg/model"
)

type documentHandler struct {
	client             *Client
	serviceBaseURL     string
	log                *logger.Log
	defaultContentType string
}

// DocumentGetQuery is the query for GetDocument
type DocumentGetQuery struct {
	AuthenticSource string `json:"authentic_source"`
	DocumentType    string `json:"document_type"`
	DocumentID      string `json:"document_id"`
}

// Get gets a document
func (s *documentHandler) Get(ctx context.Context, query *DocumentGetQuery) (*model.Document, *http.Response, error) {
	reply := &model.Document{}
	resp, err := s.client.call(ctx, http.MethodPost, s.serviceBaseURL, s.defaultContentType, nil, reply, true)
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

func (s *documentHandler) List(ctx context.Context, query *DocumentListQuery) ([]model.DocumentList, *http.Response, error) {
	s.log.Info("List")

	url := fmt.Sprintf("%s/%s", s.serviceBaseURL, "list")
	reply := []model.DocumentList{}
	resp, err := s.client.call(ctx, http.MethodPost, url, s.defaultContentType, nil, reply, true)
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

func (s *documentHandler) CollectID(ctx context.Context, query *DocumentCollectIDQuery) (*model.Document, *http.Response, error) {
	s.log.Info("CollectID")
	s.log.Debug("CollectID", "query", query)

	url := fmt.Sprintf("%s/%s", s.serviceBaseURL, "collect_id")
	reply := &model.Document{}
	resp, err := s.client.call(ctx, http.MethodPost, url, s.defaultContentType, query, reply, true)
	if err != nil {
		s.log.Error(err, "failed to call CollectID")
		return nil, resp, err
	}
	return reply, resp, nil
}

func (s *documentHandler) Search(ctx context.Context, query *model.SearchDocumentsRequest) (*model.SearchDocumentsReply, *http.Response, error) {
	s.log.Debug("Search (Documents)")

	url := fmt.Sprintf("%s/%s", s.serviceBaseURL, "search")
	reply := &model.SearchDocumentsReply{
		Documents: []*model.CompleteDocument{},
	}
	resp, err := s.client.call(ctx, http.MethodPost, url, s.defaultContentType, query, reply, false)
	if err != nil {
		return nil, resp, err
	}
	return reply, resp, nil
}
