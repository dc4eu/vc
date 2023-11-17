package ca

import (
	"context"
	"errors"
	"vc/pkg/helpers"

	"github.com/masv3971/gosunetca/types"
	"go.opentelemetry.io/otel/codes"
)

// SignDocument sends documents to the CA to be signed
func (c *Client) SignDocument(ctx context.Context, document *types.Document) {
	ctx, span := c.tp.Start(ctx, "SignDocument")
	defer span.End()

	c.log.Debug("SignDocuments", "transactionID", document.TransactionID)

	signDocument, _, err := c.caClient.PDF.Sign(ctx, document)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "caClient.sign", "transactionID", document.TransactionID)
		return
	}
	if signDocument == nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(errors.New("signDocument is nil"), "caClient.sign", "transactionID", document.TransactionID)
		return
	}

	if err := c.kv.Doc.SaveSigned(ctx, signDocument); err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "saveSigned", "transactionID", document.TransactionID)
		return
	}

	persistentDocument := &types.Document{
		TransactionID: signDocument.TransactionID,
	}
	if err := c.db.DocumentsColl.Save(ctx, persistentDocument); err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "persistent save", "transactionID", document.TransactionID)
		return
	}

	if err := c.kv.Doc.AddTTLSigned(ctx, signDocument.TransactionID); err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "AddTTLSigned", "transactionID", document.TransactionID)
		return
	}
}

// ValidateDocument sends documents to the CA to be validated
func (c *Client) ValidateDocument(ctx context.Context, document *types.Document) (*types.Validation, error) {
	ctx, span := c.tp.Start(ctx, "ValidateDocument")
	defer span.End()

	c.log.Info("ValidateDocument")
	if c.db.DocumentsColl.IsRevoked(ctx, document.TransactionID) {
		//if c.kv.Doc.IsRevoked(ctx, document.TransactionID) {
		span.SetStatus(codes.Error, helpers.ErrDocumentIsRevoked.Error())
		return nil, helpers.ErrDocumentIsRevoked
	}
	verifyDocument, _, err := c.caClient.PDF.Validate(ctx, document)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if verifyDocument.Error != "" {
		span.SetStatus(codes.Error, errors.New("error verifying document, error: "+verifyDocument.Error).Error())
		return nil, errors.New("error verifying document, error: " + verifyDocument.Error)
	}
	c.log.Debug("validateDocument", "message", verifyDocument.ValidSignature)
	return verifyDocument, nil
}
