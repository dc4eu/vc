package apiv1

import (
	"context"
	"vc/pkg/model"

	"github.com/google/uuid"
)

// SignPDFRequest is the request for sign pdf
type SignPDFRequest struct {
	PDF string `json:"pdf"`
}

// SignPDFReply is the reply for sign pdf
type SignPDFReply struct {
	TransactionID string `json:"transaction_id"`
}

// SignPDF is the request to sign pdf
func (c *Client) SignPDF(ctx context.Context, req *SignPDFRequest) (*SignPDFReply, error) {
	transactionID := uuid.New().String()

	transactionDoc := &model.Transaction{
		//ID:            transactionID,
		TransactionID: transactionID,
		KeyLabel:      "test",
		KeyType:       "test",
		HashType:      "test",
	}

	if err := c.db.SaveTransaction(ctx, transactionDoc); err != nil {
		return nil, err
	}

	// Save transationID to DB
	reply := &SignPDFReply{
		TransactionID: transactionID,
	}
	return reply, nil
}

// GetSignedPDFRequest is the request for get signed pdf
type GetSignedPDFRequest struct {
	TransactionID string `uri:"transaction_id"`
}

// GetSignedPDFReply is the reply for get signed pdf
type GetSignedPDFReply struct {
	PDF string `json:"pdf"`
}

// GetSignedPDF is the request to get signed pdf
func (c *Client) GetSignedPDF(ctx context.Context, req *GetSignedPDFRequest) (*GetSignedPDFReply, error) {
	return nil, nil
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
