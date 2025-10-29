package httpserver

import (
	"context"
	"io"
	"vc/internal/verifier/apiv1"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (s *Service) endpointUIInteraction(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointUIInteraction")

	session := sessions.Default(c)
	session.Set("session_id", uuid.NewString())
	if err := session.Save(); err != nil {
		return nil, err
	}

	request := &apiv1.UIInteractionRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	request.SessionID = session.Get("session_id").(string)

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
