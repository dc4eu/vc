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
	Status string `json:"status"`
}

// GenericUpload uploads a generic document with a set of attributes
//
//	@Summary		Generic upload
//	@ID				generic-upload
//	@Description	Upload endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	model.Response{data=GenericUploadReply}	"Success"
//	@Failure		400	{object}	model.Response{error=helpers.Error}		"Bad Request"
//	@Param			req	body		model.GenericUpload						true	" "
//	@Router			/upload [post]
func (c *Client) GenericUpload(ctx context.Context, req *model.GenericUpload) (*GenericUploadReply, error) {
	//helpers.Check(req, c.logger.New("validate"))
	if err := c.db.GenericColl.Save(ctx, req); err != nil {
		return nil, err
	}
	return &GenericUploadReply{Status: "OK"}, nil
}

// GenericList return a list of generic documents
//
//	@Summary		Generic list documents
//	@ID				generic-list
//	@Description	List documents endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	model.Response{data=[]model.GenericUpload}	"Success"
//	@Failure		400	{object}	model.Response{error=helpers.Error}			"Bad Request"
//	@Param			req	body		model.GenericAttributes						true	" "
//	@Router			/list [post]
func (c *Client) GenericList(ctx context.Context, req *model.GenericAttributes) ([]model.GenericUpload, error) {
	list, err := c.db.GenericColl.List(ctx, req)
	if err != nil {
		return nil, err
	}
	return list, nil
}

// GenericDocument return a specific generic document
//
//	@Summary		Generic get one document
//	@ID				generic-get
//	@Description	Get document endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	model.Response{data=model.GenericUpload}	"Success"
//	@Failure		400	{object}	model.Response{error=helpers.Error}		"Bad Request"
//	@Param			req	body		model.GenericAttributes					true	" "
//	@Router			/document [post]
func (c *Client) GenericDocument(ctx context.Context, req *model.GenericAttributes) (*model.GenericUpload, error) {
	doc, err := c.db.GenericColl.Get(ctx, req)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

// GenericQRReply is the reply for a generic QR code
type GenericQRReply struct {
	Base64Image string `json:"base64_image"`
}

// GenericQR returns a QR code for a specific generic document
//
//	@Summary		Generic QR code generator
//	@ID				generic-qr
//	@Description	QR code generator endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	model.Response{data=GenericQRReply}	"Success"
//	@Failure		400	{object}	model.Response{error=helpers.Error}		"Bad Request"
//	@Param			req	body		model.GenericAttributes					true	" "
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
		Base64Image: qrBase64,
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
