package httpserver

import (
	"context"
	"errors"
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
	session.Set(sessionKey, reply.SessionKey) //the sessionkey is only stored in session storage (backend)
	if err := session.Save(); err != nil {    //This is also where the session-id and sessioncookie is created
		//s.logger.Error(err, "Failed to save session (and send cookie) during login")
		return nil, err
	}

	return nil, nil
}

func (s *Service) logout(ctx context.Context, c *gin.Context) (interface{}, error) {
	session := sessions.Default(c)  //gets the session based on session-id in session cookie (handled by gin)
	uuid := session.Get(sessionKey) //retrieve session key value from session storage
	if uuid == nil {
		return nil, errors.New("Invalid session token")
	}

	session.Clear()                   //clear the session, is later removed by MaxAge in session storage (sessionInactivityTimeoutInSeconds)
	session.Options(sessions.Options{ //Order the browser to remove the session cookie
		MaxAge:   -1, // Expired
		Path:     sessionPath,
		Secure:   sessionSecure,
		HttpOnly: sessionHttpOnly,
		SameSite: sessionSameSite,
	})
	if err := session.Save(); err != nil { //Save the cleared session and send remove session cookie to browser
		return nil, errors.New("Failed to remove session (and cookie)")
	}

	return nil, nil
}
