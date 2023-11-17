package apiv1

import (
	"context"
	"errors"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/pkg/helpers"
	"vc/pkg/model"

	"go.opentelemetry.io/otel/codes"

	"github.com/google/uuid"
	"github.com/masv3971/gosunetca/types"
)

// PDFSignRequest is the request for sign pdf
type PDFSignRequest struct {
	PDF string `json:"pdf" validate:"required,base64"`
}

// PDFSignReply is the reply for sign pdf
type PDFSignReply struct {
	Data struct {
		TransactionID string `json:"transaction_id" validate:"required"`
	} `json:"data"`
}

// PDFSign is the request to sign pdf
//
//	@Summary		Sign pdf
//	@ID				ladok-pdf-sign
//	@Description	sign base64 encoded PDF
//	@Tags			ladok
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	PDFSignReply			"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		PDFSignRequest			true	" "
//	@Router			/ladok/pdf/sign [post]
func (c *Client) PDFSign(ctx context.Context, req *PDFSignRequest) (*PDFSignReply, error) {
	ctx, span := c.tp.Start(ctx, "apiv1")
	defer span.End()

	if err := helpers.Check(ctx, req, c.log); err != nil {
		return nil, err
	}
	transactionID := uuid.New().String()

	c.log.Debug("PDFSign", "transaction_id", transactionID)

	unsignedDocument := &types.Document{
		TransactionID: transactionID,
		Data:          req.PDF,
	}

	go func() {
		c.log.Debug("sending unsigned document to CA")
		c.ca.SignDocument(ctx, unsignedDocument)
	}()

	reply := &PDFSignReply{
		Data: struct {
			TransactionID string `json:"transaction_id" validate:"required"`
		}{
			TransactionID: transactionID,
		},
	}

	return reply, nil
}

// PDFValidateRequest is the request for verify pdf
type PDFValidateRequest struct {
	PDF string `json:"pdf"`
}

// PDFValidateReply is the reply for verify pdf
type PDFValidateReply struct {
	Data *types.Validation `json:"data"`
}

// PDFValidate is the handler for verify pdf
//
//	@Summary		Validate pdf
//	@ID				ladok-pdf-validate
//	@Description	validate a signed base64 encoded PDF
//	@Tags			ladok
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	PDFValidateReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		PDFValidateRequest		true	" "
//	@Router			/ladok/pdf/validate [post]
func (c *Client) PDFValidate(ctx context.Context, req *PDFValidateRequest) (*PDFValidateReply, error) {
	ctx, span := c.tp.Start(ctx, "apiv1")
	defer span.End()

	validateCandidate := &types.Document{
		Data: req.PDF,
	}

	res, err := c.ca.ValidateDocument(ctx, validateCandidate)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if res.Error != "" {
		span.SetStatus(codes.Error, err.Error())
		return nil, helpers.NewErrorFromError(errors.New(res.Error))
	}

	res.IsRevoked = c.db.DocumentsColl.IsRevoked(ctx, res.TransactionID)

	reply := &PDFValidateReply{
		Data: res,
	}

	return reply, nil
}

// PDFGetSignedRequest is the request for get signed pdf
type PDFGetSignedRequest struct {
	TransactionID string `uri:"transaction_id" binding:"required"`
}

// PDFGetSignedReply is the reply for the signed pdf
type PDFGetSignedReply struct {
	Data struct {
		Document *types.Document `json:"document,omitempty"`
		Message  string          `json:"message,omitempty"`
	} `json:"data"`
}

// PDFGetSigned is the request to get signed pdfs
//
//	@Summary		fetch singed pdf
//	@ID				ladok-pdf-fetch
//	@Description	fetch a singed pdf
//	@Tags			ladok
//	@Accept			json
//	@Produce		json
//	@Success		200				{object}	PDFGetSignedReply		"Success"
//	@Failure		400				{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			transaction_id	path		string					true	"transaction_id"
//	@Router			/ladok/pdf/{transaction_id} [get]
func (c *Client) PDFGetSigned(ctx context.Context, req *PDFGetSignedRequest) (*PDFGetSignedReply, error) {
	ctx, span := c.tp.Start(ctx, "apiv1")
	defer span.End()

	if !c.kv.Doc.ExistsSigned(ctx, req.TransactionID) {
		return &PDFGetSignedReply{
			Data: struct {
				Document *types.Document `json:"document,omitempty"`
				Message  string          `json:"message,omitempty"`
			}{
				Message: "Document does not exist, please try again later",
			},
		}, nil
	}

	if c.db.DocumentsColl.IsRevoked(ctx, req.TransactionID) {
		span.SetStatus(codes.Error, helpers.ErrDocumentIsRevoked.Error())
		return nil, helpers.ErrDocumentIsRevoked
	}

	signedDoc, err := c.kv.Doc.GetSigned(ctx, req.TransactionID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if err := c.kv.Doc.DelSigned(ctx, req.TransactionID); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if signedDoc.Error != "" {
		resp := &PDFGetSignedReply{
			Data: struct {
				Document *types.Document `json:"document,omitempty"`
				Message  string          `json:"message,omitempty"`
			}{
				Message: signedDoc.Error,
			},
		}
		return resp, nil
	}

	return &PDFGetSignedReply{
		Data: struct {
			Document *types.Document `json:"document,omitempty"`
			Message  string          `json:"message,omitempty"`
		}{
			Document: signedDoc,
		},
	}, nil
}

// PDFRevokeRequest is the request for revoke pdf
type PDFRevokeRequest struct {
	TransactionID string `uri:"transaction_id" binding:"required"`
}

// PDFRevokeReply is the reply for revoke pdf
type PDFRevokeReply struct {
	Data struct {
		Status bool `json:"status"`
	} `json:"data"`
}

// PDFRevoke is the request to revoke pdf
//
//	@Summary		revoke signed pdf
//	@ID				ladok-pdf-revoke
//	@Description	revoke a singed pdf
//	@Tags			ladok
//	@Accept			json
//	@Produce		json
//	@Success		200				{object}	PDFRevokeReply			"Success"
//	@Failure		400				{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			transaction_id	path		string					true	"transaction_id"
//	@Router			/ladok/pdf/revoke/{transaction_id} [put]
func (c *Client) PDFRevoke(ctx context.Context, req *PDFRevokeRequest) (*PDFRevokeReply, error) {
	ctx, span := c.tp.Start(ctx, "apiv1")
	defer span.End()

	if err := c.db.DocumentsColl.Revoke(ctx, req.TransactionID); err != nil {
		return nil, err
	}
	reply := &PDFRevokeReply{
		Data: struct {
			Status bool `json:"status"`
		}{
			Status: true,
		},
	}
	return reply, nil
}

// Status return status for each ladok instance
func (c *Client) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	ctx, span := c.tp.Start(ctx, "apiv1")
	defer span.End()

	probes := model.Probes{}
	probes = append(probes, c.kv.Status(ctx))

	status := probes.Check("issuer")

	return status, nil
}
