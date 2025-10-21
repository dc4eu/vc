package apiv1

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
)

func (c *Client) CredentialInfo(ctx context.Context) (map[string]*model.CredentialConstructor, error) {
	reply := c.cfg.CredentialConstructor

	for _, constructor := range reply {
		constructor.AuthMethod = ""
		constructor.VCTMFilePath = ""
		constructor.VCTM = nil
	}

	return reply, nil
}

type GetRequestObjectRequest struct {
	ID string `uri:"id" binding:"required"`
}

func (c *Client) GetRequestObject(ctx context.Context, req *GetRequestObjectRequest) (map[string]any, error) {
	c.log.Debug("getRequestObject", "id", req.ID)

	return nil, nil
}

// Status returns the status for each instance.
func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	probes := model.Probes{}
	return probes.Check("verifier"), nil
}
