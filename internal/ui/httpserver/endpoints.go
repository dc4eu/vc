package httpserver

import (
	"context"
	"github.com/gin-contrib/sessions"
	"net/http"
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
	session.Set(sessionKey, reply.SessionKey)
	if err := session.Save(); err != nil { //This is also where the cookie is created
		//s.logger.Error(err, "Failed to save session (and send cookie) during login")
		return nil, err
	}

	s.logger.Info("Logged in with ", "sessionkey", reply.SessionKey)

	return nil, nil
}

/* TODO: flytta vissa av nedan logout delar till api och handler (kanske tom handler) */
func (s *Service) logoutHandler(c *gin.Context) {
	session := sessions.Default(c)
	uuid := session.Get(sessionKey)
	if uuid == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session token"})
		return
	}

	session.Clear()
	session.Options(sessions.Options{
		MaxAge:   -1, // Expired
		Path:     sessionPath,
		Secure:   sessionSecure,
		HttpOnly: sessionHttpOnly,
		SameSite: sessionSameSite,
	})
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove session (and cookie)"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}
