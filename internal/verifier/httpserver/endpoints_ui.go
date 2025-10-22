package httpserver

import (
	"context"
	"io"
	"vc/internal/verifier/apiv1"

	"github.com/dustin/go-broadcast"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (s *Service) endpointUIPresentationDefinition(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointUIPresentationDefinition")

	request := &apiv1.UIPresentationDefinitionRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.UIPresentationDefinition(ctx, request)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

var notifyChannel = make(map[string]broadcast.Broadcaster)

func (s *Service) endpointUINotify(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointUINotify")

	sess := sessions.Default(c)

	sess.Set("session_id", uuid.NewString())

	sessionID := sess.Get("session_id").(string)
	s.log.Debug("notifyEndpoint", "sessionID", sessionID)

	listener := openListener(sessionID)

	defer func() {
		closeListener(sessionID, listener)
	}()

	c.Stream(func(w io.Writer) bool {
		select {
		case msg := <-listener:
			s.log.Debug("received a message")
			//messages.Add("outbound", 1)
			c.SSEvent("message", msg)
		}
		return true
	})

	return nil, nil
}

func openListener(id string) chan any {
	listener := make(chan any)
	uiNotify(id).Register(listener)
	return listener
}

func uiNotify(id string) broadcast.Broadcaster {
	b, ok := notifyChannel[id]
	if !ok {
		b = broadcast.NewBroadcaster(10)
		notifyChannel[id] = b
	}
	return b
}

func closeListener(id string, listener chan any) {
	uiNotify(id).Unregister(listener)
	close(listener)
}
