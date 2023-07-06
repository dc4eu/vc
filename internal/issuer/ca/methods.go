package ca

import (
	"context"

	"github.com/masv3971/gosunetca/types"
)

// SignDocuments sends documents to the CA to be signed
func (c *Client) SignDocuments(ctx context.Context, document *types.Document) error {
	c.log.Debug("sending document to CA")
	c.log.Debug("SignDocuments", "transactionID", document.TransactionID)

	signDocument, _, err := c.caClient.Sign.Documents(ctx, document)
	if err != nil {
		return err
	}

	c.log.Debug("SignDocuments", "transactionID:", document.TransactionID, "data", signDocument.Data)

	if err := c.kv.Doc.SaveSigned(ctx, signDocument); err != nil {
		return err
	}
	if err := c.kv.Doc.AddTTLUnsigned(ctx, document.TransactionID); err != nil {
		return err
	}

	return nil
}
