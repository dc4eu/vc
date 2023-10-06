package ca

import (
	"context"
	"errors"

	"github.com/masv3971/gosunetca/types"
)

// SignDocument sends documents to the CA to be signed
func (c *Client) SignDocument(ctx context.Context, document *types.Document) error {
	c.log.Debug("SignDocuments", "transactionID", document.TransactionID)

	signDocument, _, err := c.caClient.PDF.Sign(ctx, document)
	if err != nil {
		return err
	}

	c.log.Debug("SignDocuments", "transactionID:", document.TransactionID, "data", signDocument.Data, "error", signDocument.Error)

	if err := c.kv.Doc.SaveSigned(ctx, signDocument); err != nil {
		return err
	}
	if err := c.kv.Doc.AddTTLUnsigned(ctx, document.TransactionID); err != nil {
		return err
	}

	return nil
}

// ValidateDocument sends documents to the CA to be validated
func (c *Client) ValidateDocument(ctx context.Context, document *types.Document) (*types.Validation, error) {
	c.log.Info("ValidateDocument")
	if c.kv.Doc.IsRevoked(ctx, document.TransactionID) {
	        return nil, errors.New("document is revoked")
	}
	verifyDocument, _, err := c.caClient.PDF.Validate(ctx, document)
	if err != nil {
		return nil, err
	}

	if verifyDocument.Error != "" {
		return nil, errors.New("error verifying document, error: " + verifyDocument.Error)
	}
	c.log.Debug("validateDocument", "message", verifyDocument.Valid)
	return verifyDocument, nil
}
