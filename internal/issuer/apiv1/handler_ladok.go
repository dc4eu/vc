package apiv1

import (
	"context"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/pkg/helpers"
	"vc/pkg/model"

	"github.com/google/uuid"
	"github.com/masv3971/gosunetca/types"
)

// PDFSignRequest is the request for sign pdf
type PDFSignRequest struct {
	PDF string `json:"pdf" validate:"required,base64"`
}

// PDFSignReply is the reply for sign pdf
type PDFSignReply struct {
	TransactionID string `json:"transaction_id" validate:"required"`
}

// PDFSign is the request to sign pdf
//
//	@Summary		Sign pdf
//	@ID				ladok-pdf-sign
//	@Description	sign base64 encoded PDF
//	@Tags			ladok,pdf
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}		PDFSignReply
//	@Param			req	body PDFSignRequest true " "
//	@Router			/ladok/pdf/sign [post]
func (c *Client) PDFSign(ctx context.Context, req *PDFSignRequest) (*PDFSignReply, error) {
	if err := helpers.Check(req, c.log); err != nil {
		return nil, err
	}
	transactionID := uuid.New().String()

	c.log.Debug("PDFSign", "transaction_id", transactionID)

	unsignedDocument := &types.Document{
		TransactionID: transactionID,
		Data:          req.PDF,
	}

	if err := c.kv.Doc.SaveUnsigned(ctx, unsignedDocument); err != nil {
		return nil, err
	}

	go func() error {
		c.log.Debug("sending document to CA")
		if err := c.ca.SignDocument(ctx, unsignedDocument); err != nil {
			return err
		}
		return nil
	}()

	reply := &PDFSignReply{
		TransactionID: transactionID,
	}

	return reply, nil
}

// PDFValidateRequest is the request for verify pdf
type PDFValidateRequest struct {
	PDF string `json:"pdf"`
}

// PDFValidateReply is the reply for verify pdf
type PDFValidateReply struct {
	MSG string `json:"msg"`
}

// PDFValidate is the handler for verify pdf
//
//	@Summary		Validate pdf
//	@ID				ladok-pdf-validate
//	@Description	validate a signed base64 encoded PDF
//	@Tags			ladok,pdf
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}		PDFValidateReply
//	@Param			req	body PDFValidateRequest true " "
//	@Router			/ladok/pdf/validate [post]
func (c *Client) PDFValidate(ctx context.Context, req *PDFValidateRequest) (*types.Validation, error) {
	validateCandidate := &types.Document{
		Data: req.PDF,
	}
	res, err := c.ca.ValidateDocument(ctx, validateCandidate)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// PDFGetSignedRequest is the request for get signed pdf
type PDFGetSignedRequest struct {
	TransactionID string `uri:"transaction_id" binding:"required"`
}

// PDFGetSignedReply is the reply for the signed pdf
type PDFGetSignedReply struct {
	Document *types.Document `json:"document,omitempty"`
	Message  string          `json:"message,omitempty"`
}

// PDFGetSigned is the request to get signed pdfs
//
//	@Summary		fetch singed pdf
//	@ID				ladok-pdf-fetch
//	@Description	fetch a singed pdf
//	@Tags			ladok,pdf
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}		PDFGetSignedReply
//	@Param			req	body PDFValidateRequest true " "
//	@Router			/ladok/pdf/:transaction_id [get]
func (c *Client) PDFGetSigned(ctx context.Context, req *PDFGetSignedRequest) (*PDFGetSignedReply, error) {
	if !c.kv.Doc.ExistsSigned(ctx, req.TransactionID) {
		return &PDFGetSignedReply{Message: "Document does not exist, please try again later"}, nil
	}

	signedDoc, err := c.kv.Doc.GetSigned(ctx, req.TransactionID)
	if err != nil {
		return nil, err
	}

	if signedDoc.Error != "" {
		resp := &PDFGetSignedReply{
			Message: signedDoc.Error,
		}
		return resp, nil
	}

	return &PDFGetSignedReply{
		Document: signedDoc,
	}, nil
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
//
//	@Summary		revoke signed pdf
//	@ID				ladok-pdf-revoke
//	@Description	revoke a singed pdf
//	@Tags			ladok,pdf
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}		PDFRevokeReply
//	@Param			req	body PDFValidateRequest true " "
//	@Router			/ladok/pdf/revoke/:transaction_id [put]
func (c *Client) PDFRevoke(ctx context.Context, req *PDFRevokeRequest) (*PDFRevokeReply, error) {
	if err := c.kv.Doc.SaveRevoked(ctx, req.TransactionID); err != nil {
		return &PDFRevokeReply{Status: false}, err
	}
	return &PDFRevokeReply{Status: true}, nil
}

// Status return status for each ladok instance
func (c *Client) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	probes := model.Probes{}
	probes = append(probes, c.kv.Status(ctx))

	status := probes.Check("issuer")

	return status, nil
}
