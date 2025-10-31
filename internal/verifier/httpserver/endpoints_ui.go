package httpserver

import (
	"context"
	"io"
	"vc/internal/verifier/apiv1"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

func (s *Service) endpointUIMetadata(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointUIMetadata")
	defer span.End()

	reply, err := s.apiv1.UIMetadata(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointUIInteraction(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointUIInteraction")

	request := &apiv1.UIInteractionRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.UIInteraction(ctx, request)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointUINotify(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointUINotify")

	session := sessions.Default(c)

	sessionID := session.Get("session_id").(string)
	s.log.Debug("notifyEndpoint", "sessionID", sessionID)

	listener := s.notify.OpenListener(sessionID)

	defer func() {
		s.notify.CloseListener(sessionID, listener)
	}()

	c.Stream(func(w io.Writer) bool {
		msg := <-listener
		s.log.Debug("endpointUINotify", "msg", msg)
		c.SSEvent("message", msg)
		return true
	})

	return nil, nil
}
