package httpserver

import (
	"context"
	"vc/internal/verifier/apiv1"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func (s *Service) endpointVerificationRequestObject(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointVerificationRequestObject called")

	session := sessions.Default(c)
	sessionID := session.Get("session_id").(string)

	request := &apiv1.VerificationRequestObjectRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	request.SessionID = sessionID

	reply, err := s.apiv1.VerificationRequestObject(ctx, request)
	if err != nil {
		return nil, err
	}

	return reply, nil
}
