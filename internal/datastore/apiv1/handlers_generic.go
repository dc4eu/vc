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
func (c *Client) GenericUpload(ctx context.Context, req *model.GenericUpload) (*GenericUploadReply, error) {
	c.logger.Info("before validate", "request", req)
	if err := req.Validate(c.logger.New("validate")); err != nil {
		c.logger.Info("validate error", "error", err)
		return nil, err
	}
	c.logger.Info("after validate")
	if err := c.db.GenericColl.Save(ctx, req); err != nil {
		return nil, err
	}
	return &GenericUploadReply{Status: "OK"}, nil
}

// GenericList return a list of generic documents
func (c *Client) GenericList(ctx context.Context, req *model.GenericAttributes) ([]*model.GenericUpload, error) {
	list, err := c.db.GenericColl.List(ctx, req)
	if err != nil {
		return nil, err
	}
	return list, nil
}

// GenericDocument return a specific generic document
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
