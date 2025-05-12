package httphelpers

import (
	"context"
	"fmt"
	"time"
	"vc/pkg/helpers"
	"vc/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/lithammer/shortuuid/v4"

	"github.com/gin-contrib/gzip"
)

type middlewareHandler struct {
	client *Client
	log    *logger.Log
}

// Duration middleware to calculate the duration of the request and set it in the gin context
func (m *middlewareHandler) Duration(ctx context.Context) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:Duration")
	defer span.End()

	return func(c *gin.Context) {
		t := time.Now()
		c.Next()
		duration := time.Since(t)
		c.Set("duration", duration)
	}
}

// RequestID middleware to set a unique request ID in the gin context and header
func (m *middlewareHandler) RequestID(ctx context.Context) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:RequestID")
	defer span.End()

	return func(c *gin.Context) {
		id := shortuuid.New()
		c.Set("req_id", id)
		c.Header("req_id", id)
		c.Next()
	}
}

// Logger middleware to log the request details
func (m *middlewareHandler) Logger(ctx context.Context) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:Logger")
	defer span.End()

	log := m.log.New("http")
	return func(c *gin.Context) {
		c.Next()
		log.Info("request", "status", c.Writer.Status(), "url", c.Request.URL.String(), "method", c.Request.Method, "req_id", c.GetString("req_id"))
	}
}

// AuthLog middleware to log the request details with the user information
func (m *middlewareHandler) AuthLog(ctx context.Context) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:AuthLog")
	defer span.End()

	log := m.log.New("http")
	return func(c *gin.Context) {
		u, _ := c.Get("user")
		c.Next()
		log.Info("auth", "user", u, "req_id", c.GetString("req_id"))
	}
}

// Crash middleware to recover from panics and return a 500 error
func (m *middlewareHandler) Crash(ctx context.Context) gin.HandlerFunc {
	ctx, span := m.client.tracer.Start(ctx, "httphelpers:middleware:Crash")
	defer span.End()

	log := m.log.New("http")
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				status := c.Writer.Status()
				log.Trace("crash", "error", r, "status", status, "url", c.Request.URL.Path, "method", c.Request.Method)
				m.client.Rendering.Content(ctx, c, 500, gin.H{"data": nil, "error": helpers.NewError("internal_server_error")})
			}
		}()
		c.Next()
	}
}

// ClientCertAuth middleware to authenticate the client certificate, this should compare client certificate SAH1 hash with some config value.
func (m *middlewareHandler) ClientCertAuth(ctx context.Context) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:ClientCertAuth")
	defer span.End()

	log := m.log.New("http")
	return func(c *gin.Context) {
		clientCertSHA1 := c.Request.Header.Get("X-SSL-Client-SHA1")
		log.Info("clientCertSHA1", "clientCertSHA1", clientCertSHA1)
		fmt.Println("clientCertSHA1", clientCertSHA1)
		c.Next()
	}
}

// BasicAuth middleware to authenticate the user with basic auth
func (m *middlewareHandler) BasicAuth(ctx context.Context, users map[string]string) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:BasicAuth")
	defer span.End()

	return func(c *gin.Context) {
		user, pass, ok := c.Request.BasicAuth()
		password, ok := users[user]
		if !ok || pass != password {
			c.AbortWithStatus(401)
			return
		}
		c.Next()
		m.log.Info("basic_auth", "user", user, "req_id", c.GetString("req_id"))
	}
}

// Gzip middleware sets the compression level
func (m *middlewareHandler) Gzip(ctx context.Context) gin.HandlerFunc {
	return gzip.Gzip(gzip.DefaultCompression)
}
