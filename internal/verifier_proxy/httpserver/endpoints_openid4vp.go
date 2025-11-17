package httpserver

import (
	"context"
	"net/http"
	"vc/internal/verifier_proxy/apiv1"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

// endpointRequestObject handles OpenID4VP request object retrieval
func (s *Service) endpointRequestObject(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointRequestObject")
	defer span.End()

	s.log.Debug("endpointRequestObject called")

	sessionID := c.Param("session_id")
	if sessionID == "" {
		span.SetStatus(codes.Error, "Missing session_id")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	// Get request object
	request := &apiv1.GetRequestObjectRequest{
		SessionID: sessionID,
	}

	response, err := s.apiv1.GetRequestObject(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to get request object")

		if err == apiv1.ErrSessionNotFound {
			c.AbortWithStatus(http.StatusNotFound)
			return nil, nil
		}

		c.AbortWithStatus(http.StatusInternalServerError)
		return nil, nil
	}

	c.Header("Content-Type", "application/oauth-authz-req+jwt")
	c.String(http.StatusOK, response.RequestObject)
	return nil, nil
}

// endpointDirectPost handles OpenID4VP direct_post responses from wallet
func (s *Service) endpointDirectPost(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDirectPost")
	defer span.End()

	s.log.Debug("endpointDirectPost called")

	// Parse request
	request := &apiv1.DirectPostRequest{}
	if err := c.ShouldBind(request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to bind direct_post request")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	// Process VP token
	response, err := s.apiv1.ProcessDirectPost(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to process direct_post")

		// Return error response per OpenID4VP spec
		c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return nil, nil
	}

	// Return redirect_uri if present (for cross-device flow completion)
	if response.RedirectURI != "" {
		c.Redirect(http.StatusFound, response.RedirectURI)
		return nil, nil
	}

	// Success response for same-device flow
	c.JSON(http.StatusOK, map[string]string{
		"status": "ok",
	})
	return nil, nil
}

// endpointCallback handles OpenID4VP callback (alternative to direct_post)
func (s *Service) endpointCallback(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointCallback")
	defer span.End()

	s.log.Debug("endpointCallback called")

	// Parse query parameters
	request := &apiv1.CallbackRequest{}
	if err := c.ShouldBindQuery(request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to bind callback request")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	// Process callback
	response, err := s.apiv1.ProcessCallback(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to process callback")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	// Redirect back to RP
	c.Redirect(http.StatusFound, response.RedirectURI)
	return nil, nil
}
