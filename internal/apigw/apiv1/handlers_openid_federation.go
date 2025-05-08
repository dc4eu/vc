package apiv1

import "context"

type OpenIDFederationReply struct{}

func (c *Client) OpenIDFederation(ctx context.Context) (*OpenIDFederationReply, error) {
	response := &OpenIDFederationReply{}

	c.log.Debug("OpenIDFederation")

	return response, nil
}
