package ca

import (
	"context"
	"vc/pkg/model"

	"github.com/masv3971/gosunetca/types"
)

// SignDocuments sends documents to the CA to be signed
func (c *Client) SignDocuments(ctx context.Context, document *model.UnsignedDocument, transactionID string) error {
	c.log.Info("sending document to CA")
	body := &types.SignRequest{
		Meta: types.SignMetaRequest{
			TransactionID: transactionID,
			Version:       1,
			KeyLabel:      c.cfg.Issuer.CA.KeyLabel,
			KeyType:       c.cfg.Issuer.CA.KeyType,
		},
		Document: types.Document{
			TransactionID: transactionID,
			TS:            document.TS,
			Data:          document.Data,
		},
	}

	caResp, _, err := c.caClient.Sign.Documents(ctx, body)
	if err != nil {
		return err
	}

	if err := c.kv.Doc.SaveSigned(ctx, transactionID, caResp.Document.Data, caResp.Document.TS); err != nil {
		return err
	}
	if err := c.kv.Doc.AddTTLUnsigned(ctx, transactionID); err != nil {
		return err
	}

	return nil
}
