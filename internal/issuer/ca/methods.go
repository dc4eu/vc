package ca

import (
	"context"

	"github.com/masv3971/gosunetca/types"
)

// SignDocuments sends documents to the CA to be signed
func (c *Client) SignDocuments(ctx context.Context, documents []types.UnsignedDocument) (*types.SignReply, error) {
	body := &types.SignRequest{
		Meta: types.SignMetaRequest{
			Version:  1,
			KeyLabel: c.cfg.Issuer.CA.KeyLabel,
			Encoding: "base64",
			KeyType:  c.cfg.Issuer.CA.KeyType,
		},
		Documents: documents,
	}

	signedDocuments, _, err := c.caClient.Sign.Documents(ctx, body)
	if err != nil {
		return nil, err
	}
	return signedDocuments, nil
}
