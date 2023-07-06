package apiv1

import (
	"context"
	"time"
	"vc/pkg/model"

	"github.com/google/uuid"
)

// PDFSignRequest is the request for sign pdf
type PDFSignRequest struct {
	PDF      string `json:"pdf"`
	LadokUID string `json:"ladok_uid"`
}

// PDFSignReply is the reply for sign pdf
type PDFSignReply struct {
	TransactionID string `json:"transaction_id" validate:"required"`
}

// PDFSign is the request to sign pdf
func (c *Client) PDFSign(ctx context.Context, req *PDFSignRequest) (*PDFSignReply, error) {
	transactionID := uuid.New().String()

	unsignedDocument := &model.UnsignedDocument{Data: req.PDF, TS: time.Now().Unix()}

	if err := c.kv.Doc.SaveUnsigned(ctx, transactionID, unsignedDocument.Data, unsignedDocument.TS); err != nil {
		return nil, err
	}
	if err := c.kv.Doc.SaveLadokUID(ctx, transactionID, req.LadokUID); err != nil {
		return nil, err
	}

	go func() error {
		c.logger.Info("sending document to CA")
		if err := c.ca.SignDocuments(ctx, unsignedDocument, transactionID); err != nil {
			return err
		}
		return nil
	}()

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
	Document *model.SignedDocument `json:"document" validate:"required"`
}

// PDFGetSigned is the request to get signed pdfs
func (c *Client) PDFGetSigned(ctx context.Context, req *PDFGetSignedRequest) (*PDFGetSignedReply, error) {
	signedDoc, ts, err := c.kv.Doc.GetSigned(ctx, req.TransactionID)
	//doc, err := c.db.DocumentsColl.Get(ctx, req.TransactionID)
	if err != nil {
		return nil, err
	}
	resp := &PDFGetSignedReply{
		Document: &model.SignedDocument{
			Data: signedDoc,
			TS:   ts,
		},
	}
	return resp, nil
}

// PDFRevokeRequest is the request for revoke pdf
type PDFRevokeRequest struct {
	LadokUID string `json:"ladok_uid"`
}

// PDFRevokeReply is the reply for revoke pdf
type PDFRevokeReply struct {
	Status bool `json:"status"`
}

// PDFRevoke is the request to revoke pdf
func (c *Client) PDFRevoke(ctx context.Context, req *PDFRevokeRequest) (*PDFRevokeReply, error) {
	if err := c.db.DocumentsColl.Revoke(ctx, req.LadokUID); err != nil {
		return nil, err
	}
	return &PDFRevokeReply{Status: true}, nil
}

// Status return status for each ladok instance
func (c *Client) Status(ctx context.Context) (*model.Status, error) {
	manyStatus := model.ManyStatus{}

	//for _, ladok := range c.ladokInstances {
	//	redis := ladok.Atom.StatusRedis(ctx)
	//	ladok := ladok.Rest.StatusLadok(ctx)

	//	manyStatus = append(manyStatus, redis)
	//	manyStatus = append(manyStatus, ladok)
	//}
	status := manyStatus.Check()

	return status, nil
}
