package apiv1

import (
	"context"
	"vc/pkg/model"

	"github.com/google/uuid"
	"github.com/masv3971/gosunetca/types"
)

// PDFSignRequest is the request for sign pdf
type PDFSignRequest struct {
	PDF string `json:"pdf"`
}

// PDFSignReply is the reply for sign pdf
type PDFSignReply struct {
	TransactionID string `json:"transaction_id" validate:"required"`
}

// PDFSign is the request to sign pdf
func (c *Client) PDFSign(ctx context.Context, req *PDFSignRequest) (*PDFSignReply, error) {
	transactionID := uuid.New().String()

	c.logger.Debug("PDFSign", "transaction_id", transactionID)

	unsignedDocument := &types.Document{
		TransactionID: transactionID,
		Data:          req.PDF,
	}

	c.logger.Debug("1")

	if err := c.kv.Doc.SaveUnsigned(ctx, unsignedDocument); err != nil {
		return nil, err
	}

	c.logger.Debug("2")
	go func() error {
		c.logger.Debug("sending document to CA")
		if err := c.ca.SignDocuments(ctx, unsignedDocument); err != nil {
			return err
		}
		return nil
	}()

	c.logger.Debug("3")
	reply := &PDFSignReply{
		TransactionID: transactionID,
	}

	return reply, nil
}

// PDFGetSignedRequest is the request for get signed pdf
type PDFGetSignedRequest struct {
	TransactionID string `uri:"transaction_id" binding:"required"`
}

// PDFGetSignedReply is the reply for the signed pdf
type PDFGetSignedReply struct {
	Document *types.Document `json:"document" validate:"required"`
	Message  string          `json:"message,omitempty"`
}

// PDFGetSigned is the request to get signed pdfs
func (c *Client) PDFGetSigned(ctx context.Context, req *PDFGetSignedRequest) (*PDFGetSignedReply, error) {
	if !c.kv.Doc.ExistsSigned(ctx, req.TransactionID) {
		return &PDFGetSignedReply{Message: "Document does not exist, please try again later"}, nil
	}

	signedDoc, err := c.kv.Doc.GetSigned(ctx, req.TransactionID)
	if err != nil {
		return nil, err
	}
	resp := &PDFGetSignedReply{
		Document: signedDoc,
	}
	return resp, nil
}

// PDFRevokeRequest is the request for revoke pdf
type PDFRevokeRequest struct {
	TransactionID string `uri:"transaction_id" binding:"required"`
}

// PDFRevokeReply is the reply for revoke pdf
type PDFRevokeReply struct {
	Status bool `json:"status"`
}

// PDFRevoke is the request to revoke pdf
func (c *Client) PDFRevoke(ctx context.Context, req *PDFRevokeRequest) (*PDFRevokeReply, error) {
	if err := c.kv.Doc.SaveRevoked(ctx, req.TransactionID); err != nil {
		return &PDFRevokeReply{Status: false}, err
	}
	return &PDFRevokeReply{Status: true}, nil
}

// Status return status for each ladok instance
func (c *Client) Status(ctx context.Context) (*model.Health, error) {
	probes := model.Probes{}
	probes = append(probes, c.kv.Status(ctx))

	status := probes.Check("issuer")

	return status, nil
}
