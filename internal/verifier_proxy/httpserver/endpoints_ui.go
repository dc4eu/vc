package httpserver

import (
	"context"
	"net/http"
	"time"
	"vc/internal/verifier_proxy/apiv1"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

// endpointQRCode serves QR code images for authorization sessions
func (s *Service) endpointQRCode(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointQRCode")
	defer span.End()

	s.log.Debug("endpointQRCode called")

	sessionID := c.Param("session_id")
	if sessionID == "" {
		span.SetStatus(codes.Error, "Missing session_id")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	// Get QR code
	request := &apiv1.GetQRCodeRequest{
		SessionID: sessionID,
	}

	response, err := s.apiv1.GetQRCode(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to get QR code")

		if err == apiv1.ErrSessionNotFound {
			c.AbortWithStatus(http.StatusNotFound)
			return nil, nil
		}

		c.AbortWithStatus(http.StatusInternalServerError)
		return nil, nil
	}

	c.Header("Content-Type", "image/png")
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Data(http.StatusOK, "image/png", response.ImageData)
	return nil, nil
}

// endpointPoll handles polling for session status updates
func (s *Service) endpointPoll(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointPoll")
	defer span.End()

	sessionID := c.Param("session_id")
	if sessionID == "" {
		span.SetStatus(codes.Error, "Missing session_id")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	// Get session status
	request := &apiv1.PollSessionRequest{
		SessionID: sessionID,
	}

	response, err := s.apiv1.PollSession(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to poll session")

		if err == apiv1.ErrSessionNotFound {
			c.JSON(http.StatusNotFound, map[string]string{
				"status": "not_found",
			})
			return nil, nil
		}

		c.JSON(http.StatusInternalServerError, map[string]string{
			"status": "error",
			"error":  err.Error(),
		})
		return nil, nil
	}

	// Set appropriate cache headers for polling
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Expires", "0")

	// If completed, include redirect_uri
	if response.Status == "completed" && response.RedirectURI != "" {
		return map[string]any{
			"status":       response.Status,
			"redirect_uri": response.RedirectURI,
			"timestamp":    time.Now().Unix(),
		}, nil
	}

	return map[string]any{
		"status":    response.Status,
		"timestamp": time.Now().Unix(),
	}, nil
}
