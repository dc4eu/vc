package apiv1

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
	"vc/pkg/openid4vp"
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

type UIPresentationDefinitionRequest struct {
	// Define fields as per requirements
}

type UIPresentationDefinitionReply struct {
	DCQLQuery            map[string]any  `json:"dcql_query"`
	AuthorizationRequest *openid4vp.DCQL `json:"authorization_request"`
	QRCode               string          `json:"qr_code"`
}

// UIPresentationDefinition handles the UI presentation definition request, reply Authorization Request that contains a Request URI and DCQL query, the latter for UI to show.
func (c *Client) UIPresentationDefinition(ctx context.Context, req *UIPresentationDefinitionRequest) (map[string]any, error) {
	c.log.Debug("uIPresentationDefinition")

	return nil, nil
}

type GetRequestObjectRequest struct {
	ID string `form:"id" validate:"required"`
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
