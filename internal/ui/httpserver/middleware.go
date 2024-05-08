package httpserver

import (
	"context"
	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"net/http"
	"time"
	"vc/pkg/helpers"
	"vc/pkg/model"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	/* session... constants is also used for the session cookie */
	sessionName                       = "vcadminwebsession" //if changed, the web (javascript) must also be updated with the new name
	sessionKey                        = "sessionkey"
	sessionInactivityTimeoutInSeconds = 3600 //one hour - also the value for the cookie
	sessionPath                       = "/"
	sessionHttpOnly                   = true
	sessionSecure                     = false //TODO: activate for https
	sessionSameSite                   = http.SameSiteStrictMode
)

func (s *Service) middlewareDuration(ctx context.Context) gin.HandlerFunc {
	return func(c *gin.Context) {
		t := time.Now()
		c.Next()
		duration := time.Since(t)
		c.Set("duration", duration)
	}
}

func (s *Service) middlewareTraceID(ctx context.Context) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("req_id", uuid.NewString())
		c.Header("req_id", c.GetString("req_id"))
		c.Next()
	}
}

func (s *Service) middlewareLogger(ctx context.Context) gin.HandlerFunc {
	log := s.logger.New("http")
	return func(c *gin.Context) {
		c.Next()
		log.Info("request", "status", c.Writer.Status(), "url", c.Request.URL.String(), "method", c.Request.Method, "req_id", c.GetString("req_id"))
	}
}

func (s *Service) middlewareCrash(ctx context.Context) gin.HandlerFunc {
	log := s.logger.New("http")
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				status := c.Writer.Status()
				log.Trace("crash", "error", r, "status", status, "url", c.Request.URL.Path, "method", c.Request.Method)
				renderContent(c, 500, gin.H{"data": nil, "error": helpers.NewError("internal_server_error")})
			}
		}()
		c.Next()
	}
}

func (s *Service) middlewareGzip(ctx context.Context) gin.HandlerFunc {
	return gzip.Gzip(gzip.DefaultCompression)
}

func (s *Service) middlewareUserSession(ctx context.Context, cfg *model.Cfg) gin.HandlerFunc {
	return setupSessionMiddleware(cfg)
}

func setupSessionMiddleware(cfg *model.Cfg) gin.HandlerFunc {
	// Configure session cookie store
	store := configureSessionStore(cfg)
	return sessions.Sessions(sessionName, store)
}

func configureSessionStore(cfg *model.Cfg) sessions.Store {
	//The first parameter is used to encrypt and decrypt cookies.
	//The second parameter is used internally by cookie.Store to handle the encryption and decryption process
	store := cookie.NewStore([]byte(cfg.UI.SessionCookieAuthenticationKey), []byte(cfg.UI.SessionStoreEncryptionKey))
	store.Options(sessions.Options{
		Path:     sessionPath,
		MaxAge:   sessionInactivityTimeoutInSeconds,
		Secure:   sessionSecure,
		HttpOnly: sessionHttpOnly,
		SameSite: sessionSameSite,
	})
	return store
}
