package apiv1

import (
	"context"
	"encoding/base64"
	"fmt"
	"vc/pkg/model"

	"github.com/skip2/go-qrcode"
)

// QRReply is the reply for a generic QR code
type QRReply struct {
	Data *model.QR `json:"data"`
}

func (c *Client) qrGenerator(ctx context.Context, req *model.MetaData) (*QRReply, error) {
	collectID := "generic"
	url := fmt.Sprintf("https://example.org/issuer/api/v1/?document_id=%s&collect_id=%s", req.DocumentID, collectID)

	qrPNG, err := qrcode.Encode(url, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}

	qrBase64 := base64.StdEncoding.EncodeToString(qrPNG)

	reply := &QRReply{
		Data: &model.QR{
			Base64Image: qrBase64,
		},
	}

	return reply, nil
}
