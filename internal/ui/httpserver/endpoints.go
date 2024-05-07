package httpserver

import (
	"context"

	apiv1_status "vc/internal/gen/status/apiv1.status"

	//"vc/internal/datastore/apiv1"
	//apiv1_status "vc/internal/gen/status/apiv1.status"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointStatus(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Status(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
