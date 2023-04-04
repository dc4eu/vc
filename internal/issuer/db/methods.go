package db

import (
	"context"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/mongo/options"
)

// SaveTransaction saves a transaction
func (s *Service) SaveTransaction(ctx context.Context, doc *model.Transaction) error {
	_, err := s.CollIssuerTransactions.InsertOne(ctx, doc, options.InsertOne().SetBypassDocumentValidation(true))
	return err
}

// GetTransation gets a transaction
func (s *Service) GetTransation(ctx context.Context, transationID string) (*model.Transaction, error) {
	reply := &model.Transaction{}
	err := s.CollIssuerTransactions.FindOne(ctx, model.Transaction{TransactionID: transationID}).Decode(reply)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
