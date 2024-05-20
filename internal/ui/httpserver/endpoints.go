package httpserver

import (
	"context"
	"errors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"time"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/internal/ui/apiv1"
)

func (s *Service) endpointStatus(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Status(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointLogin(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.LoginRequest{}
	if err := s.bindRequest(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.Login(ctx, request)
	if err != nil {
		return nil, err
	}

	session := sessions.Default(c)
	session.Set(s.sessionConfig.sessionUsernameKey, reply.Username)
	session.Set(s.sessionConfig.sessionLoggedInTimeKey, reply.LoggedInTime)
	if err := session.Save(); err != nil { //This is also where the session cookie is created by gin
		s.logger.Error(err, "Failed to save session (and send cookie) during login")
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointLogout(ctx context.Context, c *gin.Context) (any, error) {
	session := sessions.Default(c)                              //gets the session based on session-ID in session cookie (handled by gin)
	username := session.Get(s.sessionConfig.sessionUsernameKey) //retrieve username for the logged in user from session storage (if nil the session does not exist or has been cleared)
	if username == nil {
		return nil, errors.New("invalid session token")
	}

	session.Clear()                   //clear the session, is later removed by MaxAge in session storage (sessionInactivityTimeoutInSeconds)
	session.Options(sessions.Options{ //Order the browser to remove the session cookie
		MaxAge:   -1, // Expired
		Path:     s.sessionConfig.sessionPath,
		Secure:   s.sessionConfig.sessionSecure,
		HttpOnly: s.sessionConfig.sessionHttpOnly,
		SameSite: s.sessionConfig.sessionSameSite,
	})
	if err := session.Save(); err != nil { //Save the cleared session and send remove session cookie to browser
		return nil, errors.New("failed to remove session (and cookie)")
	}

	return nil, nil
}

func (s *Service) endpointUser(ctx context.Context, c *gin.Context) (any, error) {
	session := sessions.Default(c)

	username, ok := session.Get(s.sessionConfig.sessionUsernameKey).(string)
	if !ok {
		return nil, errors.New("failed to convert username to string")
	}

	loggedInTime, ok := session.Get(s.sessionConfig.sessionLoggedInTimeKey).(time.Time)
	if !ok {
		return nil, errors.New("failed to convert logged in time to time.Time")
	}

	reply := &apiv1.LoggedinReply{
		Username:     username,
		LoggedInTime: loggedInTime,
	}

	return reply, nil
}

func (s *Service) endpointAPIGWStatus(ctx context.Context, g *gin.Context) (interface{}, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.StatusAPIGW(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointPortal(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.PortalRequest{}
	if err := s.bindRequest(ctx, c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.Portal(ctx, request)

	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointMockNext(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.MockNextRequest{}
	if err := s.bindRequest(ctx, c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.MockNext(ctx, request)

	if err != nil {
		return nil, err
	}
	return reply, nil
}
