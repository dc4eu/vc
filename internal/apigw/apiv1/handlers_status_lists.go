package apiv1

import "context"

type StatusListsRequest struct {
	ID          string `uri:"id" validate:"required"`
	ContentType string `header:"Content-Type" validate:"required"`
}

func (c *Client) StatusLists(ctx context.Context, req *StatusListsRequest) (string, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:StatusLists")
	defer span.End()

	c.log.Debug("status_lists", "request", req)

	// Implementation goes here

	return "", nil
}
