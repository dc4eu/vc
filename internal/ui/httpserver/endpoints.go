package httpserver

import (
	"context"
	"github.com/gin-contrib/sessions"
	apiv1_status "vc/internal/gen/status/apiv1.status"

	"vc/internal/ui/apiv1"
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

func (s *Service) login(ctx context.Context, c *gin.Context) (interface{}, error) {
	request := &apiv1.LoginRequest{}
	if err := s.bindRequest(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.Login(ctx, request)
	if err != nil {
		return nil, err
	}

	session := sessions.Default(c)
	//TODO: OBS! user är numera utbytt mot "sessionKey" vid logout samt authRequired
	session.Set("sessionKey", reply.SessionKey)
	if err := session.Save(); err != nil { //This is also where the cookie is created
		return nil, err
	}

	return nil, nil
}
