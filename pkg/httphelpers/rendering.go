package httphelpers

import (
	"context"
	"time"
	"vc/pkg/helpers"
	"vc/pkg/logger"

	"github.com/gin-gonic/gin"
)

type renderingHandler struct {
	client *Client
	log    *logger.Log
}

// Content renders the content
func (r *renderingHandler) Content(ctx context.Context, c *gin.Context, code int, data any) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	ctx, span := r.client.tracer.Start(ctx, "httphelpers:Render:Content")
	defer span.End()

	switch c.NegotiateFormat(gin.MIMEJSON, "*/*") {
	case gin.MIMEJSON:
		c.JSON(code, data)
	case "*/*": // curl
		c.JSON(code, data)
	default:
		c.JSON(406, gin.H{"error": helpers.NewErrorDetails("not_acceptable", "Accept header is invalid. It should be \"application/json\".")})
	}
}
