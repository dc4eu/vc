package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"vc/internal/ui/apiv1"
	"vc/internal/ui/httpserver"
	"vc/internal/ui/vcclient"
	"vc/pkg/configuration"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	/* session... constants is also used for the session cookie */
	sessionName                       = "vcadminwebsession" //if changed, the web (javascript) must also be updated with the new name
	sessionKey                        = "user"
	sessionInactivityTimeoutInSeconds = 3600 //one hour - also the value for the cookie
	sessionPath                       = "/"
	sessionHttpOnly                   = true
	sessionSecure                     = false //TODO: activate for https
	sessionSameSite                   = http.SameSiteStrictMode
)

type service interface {
	Close(ctx context.Context) error
}

func main() {
	//engine()

	wg := &sync.WaitGroup{}
	ctx := context.Background()

	gob.Register(time.Time{})

	services := make(map[string]service)

	cfg, err := configuration.Parse(ctx, logger.NewSimple("Configuration"))
	if err != nil {
		panic(err)
	}

	log, err := logger.New("vc_ui", cfg.Common.Log.FolderPath, cfg.Common.Production)
	if err != nil {
		panic(err)
	}

	tracer, err := trace.New(ctx, cfg, log, "vc", "ui")
	if err != nil {
		panic(err)
	}

	//TODO: add clients to connect with all other vc services and add to httpService
	apigwClient := vcclient.NewAPIGWClient(cfg, tracer, log.New("ui_apiwg_client"))
	//mockasClient :=

	apiClient, err := apiv1.New(ctx, cfg, apigwClient, log.New("ui"))
	if err != nil {
		panic(err)
	}

	httpService, err := httpserver.New(ctx, cfg, apiClient, tracer, log.New("httpserver"))
	services["httpService"] = httpService
	if err != nil {
		panic(err)
	}

	// Handle sigterm and await termChan signal
	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)

	<-termChan // Blocks here until interrupted

	mainLog := log.New("main")
	mainLog.Info("HALTING SIGNAL!")

	for serviceName, service := range services {
		if err := service.Close(ctx); err != nil {
			mainLog.Trace("serviceName", serviceName, "error", err)
		}
	}

	if err := tracer.Shutdown(ctx); err != nil {
		mainLog.Error(err, "Tracer shutdown")
	}

	wg.Wait() // Block here until are workers are done

	mainLog.Info("Stopped")
}

//TODO: remove all the func's below after refactor is done

func engine() {
	ctx := context.Background()
	cfg, err := configuration.Parse(ctx, logger.NewSimple("Configuration"))
	if err != nil {
		panic(err)
	}

	router := gin.New()

	router.Use(gin.Logger())
	//TODO: router.Use(gin.MinifyHTML())
	router.Use(gzip.Gzip(gzip.DefaultCompression))
	router.Use(setupSessionMiddleware(cfg))

	// Static route
	router.Static("/static", "./static")
	router.LoadHTMLFiles("./static/index.html")
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	httpClient := http.Client{}

	// Login route
	router.POST("/login", loginHandler(cfg))

	// Secure route group, require authentication to access
	secureRouter := router.Group("/secure")
	secureRouter.Use(authRequired)
	{
		secureRouter.POST("/mock", createMockHandler(cfg, &httpClient))
		secureRouter.POST("/portal", fetchFromPortalHandler(cfg, &httpClient))
		secureRouter.DELETE("/logout", logoutHandler)
		secureRouter.GET("/health", getHealthHandler(cfg, &httpClient))
		secureRouter.GET("/user", getUserHandler)
	}

	//TODO: add https (TLS) support
	if err := router.Run(":8080"); err != nil {
		log.Fatal("Unable to start gin engine:", err)
	}
}

func createMockHandler(cfg *model.Cfg, client *http.Client) gin.HandlerFunc {
	//closure
	return func(c *gin.Context) {
		url := cfg.UI.Services.MockAS.Addr + "/api/v1/mock/next"
		doPostForDemoFlows(c, url, client)
	}
}

func fetchFromPortalHandler(cfg *model.Cfg, client *http.Client) gin.HandlerFunc {
	//closure
	return func(c *gin.Context) {
		url := cfg.UI.Services.APIGW.Addr + "/api/v1/portal"
		doPostForDemoFlows(c, url, client)
	}
}

type demoFlowRequestBody struct {
	DocumentType            string `json:"document_type" binding:"required"`
	AuthenticSource         string `json:"authentic_source" binding:"required"`
	AuthenticSourcePersonId string `json:"authentic_source_person_id" binding:"required"`
}

func doPostForDemoFlows(c *gin.Context, url string, client *http.Client) {
	var reqBody demoFlowRequestBody

	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error marshalling body"})
		return
	}

	doPostRequest(c, url, client, err, reqBodyJSON)
}

func doPostRequest(c *gin.Context, url string, client *http.Client, err error, reqBodyJSON []byte) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBodyJSON))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error creating new http req": err.Error()})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error req": err.Error()})
		return
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error read resp": err.Error()})
		return
	}

	var jsonResp map[string]interface{}
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error Unmarshal response to json": err.Error()})
		return
	}

	c.JSON(resp.StatusCode, jsonResp)
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

func authRequired(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(sessionKey)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized/session expired"})
		return
	}

	if !isLogoutRoute(c) { // Don't touch the session (including cookie) during logout
		// Update MaxAge for the session and its cookie - extended time to expire with another 1 hour from now
		session.Options(sessions.Options{
			MaxAge:   sessionInactivityTimeoutInSeconds,
			Path:     sessionPath,
			Secure:   sessionSecure,
			HttpOnly: sessionHttpOnly,
			SameSite: sessionSameSite,
		})

		if err := session.Save(); err != nil {
			c.JSON(500, gin.H{"error": "Could not save session"})
			return
		}
	}

	c.Next()
}

func isLogoutRoute(c *gin.Context) bool {
	path := c.Request.URL.Path
	method := c.Request.Method
	return strings.HasSuffix(path, "/logout") && method == "DELETE"
}

type loginBody struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func loginHandler(cfg *model.Cfg) func(c *gin.Context) {
	//closure
	return func(c *gin.Context) {
		session := sessions.Default(c)

		var loginBody loginBody
		if err := c.ShouldBindJSON(&loginBody); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		if loginBody.Username != cfg.UI.Username || loginBody.Password != cfg.UI.Password {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
			return
		}

		// TODO: use a userID or UUID instead of username
		session.Set(sessionKey, loginBody.Username)
		if err := session.Save(); err != nil { //This is also where the cookie is created
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Successfully authenticated user"})
	}
}

func logoutHandler(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(sessionKey)
	if user == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session token"})
		return
	}

	// Delete the session and cookie
	session.Delete(sessionKey)
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

func getUserHandler(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(sessionKey)
	c.JSON(http.StatusOK, gin.H{"user": user})
}

func getHealthHandler(cfg *model.Cfg, client *http.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		url := cfg.UI.Services.APIGW.Addr + "/health"

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"Error creating new http req": err.Error()})
		}

		resp, err := client.Do(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"Error req": err.Error()})
		}

		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"Error read resp": err.Error()})
		}

		c.Data(resp.StatusCode, "application/json", data)
	}

}

func isValidUUID(str string) bool {
	if str == "" {
		return false
	}
	if _, err := uuid.Parse(str); err != nil {
		return false
	}
	return true
}