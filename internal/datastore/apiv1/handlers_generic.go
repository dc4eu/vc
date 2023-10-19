package apiv1

import (
	"context"
	"encoding/base64"
	"fmt"
	"vc/pkg/model"

	"github.com/skip2/go-qrcode"
)

// GenericUploadReply is the reply for a generic upload
type GenericUploadReply struct {
	Data struct {
		Status string `json:"status"`
	} `json:"data"`
}

// GenericUpload uploads a generic document with a set of attributes
//
//	@Summary		Generic upload
//	@ID				generic-upload
//	@Description	Upload endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	GenericUploadReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		model.GenericUpload		true	" "
//	@Router			/upload [post]
func (c *Client) GenericUpload(ctx context.Context, req *model.GenericUpload) (*GenericUploadReply, error) {
	//helpers.Check(req, c.logger.New("validate"))
	if err := c.db.GenericColl.Save(ctx, req); err != nil {
		return nil, err
	}
	reply := &GenericUploadReply{
		Data: struct {
			Status string `json:"status"`
		}{
			Status: "OK",
		},
	}
	return reply, nil
}

// GenericListReply is the reply for a generic list of documents
type GenericListReply struct {
	Data []model.GenericUpload `json:"data"`
}

// GenericList return a list of generic documents
//
//	@Summary		Generic list documents
//	@ID				generic-list
//	@Description	List documents endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	GenericListReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		model.GenericAttributes	true	" "
//	@Router			/list [post]
func (c *Client) GenericList(ctx context.Context, req *model.GenericAttributes) (*GenericListReply, error) {
	docs, err := c.db.GenericColl.List(ctx, req)
	if err != nil {
		return nil, err
	}
	reply := &GenericListReply{
		Data: docs,
	}

	return reply, nil
}

// GenericDocumentReply is the reply for a generic document
type GenericDocumentReply struct {
	Data *model.GenericUpload `json:"data"`
}

// GenericDocument return a specific generic document
//
//	@Summary		Generic get one document
//	@ID				generic-get
//	@Description	Get document endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	GenericDocumentReply	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		model.GenericAttributes	true	" "
//	@Router			/document [post]
func (c *Client) GenericDocument(ctx context.Context, req *model.GenericAttributes) (*GenericDocumentReply, error) {
	doc, err := c.db.GenericColl.Get(ctx, req)
	if err != nil {
		return nil, err
	}
	reply := &GenericDocumentReply{
		Data: doc,
	}
	return reply, nil
}

// GenericQRReply is the reply for a generic QR code
type GenericQRReply struct {
	Data struct {
		Base64Image string `json:"base64_image"`
	} `json:"data"`
}

// GenericQR returns a QR code for a specific generic document
//
//	@Summary		Generic QR code generator
//	@ID				generic-qr
//	@Description	QR code generator endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	GenericQRReply			"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		model.GenericAttributes	true	" "
//	@Router			/qr [post]
func (c *Client) GenericQR(ctx context.Context, req *model.GenericAttributes) (*GenericQRReply, error) {
	collectID := "generic"
	url := fmt.Sprintf("https://example.org/issuer/api/v1/?document_id=%s&collect_id=%s", req.DocumentID, collectID)

	qrPNG, err := qrcode.Encode(url, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}

	qrBase64 := base64.StdEncoding.EncodeToString(qrPNG)

	reply := &GenericQRReply{
		Data: struct {
			Base64Image string `json:"base64_image"`
		}{
			Base64Image: qrBase64,
		},
	}

	return reply, nil
}

// GenericRevokeRequest is the request for GenericRevoke
type GenericRevokeRequest struct {
	RevokeID string `uri:"revoke_id"`
}

// GenericRevokeReply is the reply for GenericRevoke
type GenericRevokeReply struct {
	Status string `json:"status"`
}
