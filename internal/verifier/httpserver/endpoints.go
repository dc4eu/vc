package httpserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"vc/internal/gen/status/apiv1_status"
	"vc/internal/verifier/apiv1"
	"vc/pkg/openid4vp"
	"vc/pkg/trace"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
	trace2 "go.opentelemetry.io/otel/trace"
)

func (s *Service) endpointQRCode(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointQRCode")
	defer span.End()

	request := &openid4vp.QRRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, g, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.GenerateQRCode(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if reply.SessionID == "" {
		span.SetStatus(codes.Error, "SessionID is empty")
		return nil, errors.New("SessionID is empty")
	}

	webSession := sessions.Default(g)
	webSession.Clear()
	// bind this web session to the current backend vp session stored else-where (to be used later for result checks)
	webSession.Set("vp_session_id", reply.SessionID)
	err = webSession.Save()
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointGetAuthorizationRequest(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointGetAuthorizationRequest")
	defer span.End()

	sessionID := g.Query("id")
	if sessionID == "" {
		return nil, errors.New("id is empty")
	}

	reply, err := s.apiv1.GetAuthorizationRequest(ctx, sessionID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply.RequestObjectJWS, nil
}

type ResponseBody struct {
	Response string `json:"response"`
}

func (s *Service) endpointCallback(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointCallback")
	defer span.End()

	sessionID := g.Param("session_id")
	if sessionID == "" {
		return nil, errors.New("session_id is empty")
	}
	callbackID := g.Param("callback_id")
	if callbackID == "" {
		return nil, errors.New("callback_id is empty")
	}

	vpSession, err := s.saveRequestDataToVPSession(ctx, g, span, sessionID, callbackID)
	if err != nil {
		return nil, err
	}

	//TODO refactorisera och flytta nedan till en authorization_response_parser
	var request *openid4vp.AuthorizationResponse
	if jwe := g.PostForm("response"); jwe != "" {
		decryptedPayload, err := openid4vp.DecryptJWE(jwe, vpSession.SessionEphemeralKeyPair.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt JWE: %w", err)
		}

		request = &openid4vp.AuthorizationResponse{}
		err = json.Unmarshal(decryptedPayload, request)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal: %w", err)
		}
		if request.Error != "" {
			return nil, fmt.Errorf("error from wallet; error=%s, error_description=%s, error_uri=%s", request.Error, request.ErrorDescription, request.ErrorURI)
		}
		if request.VPTokens == nil || len(request.VPTokens) < 1 || request.PresentationSubmission == nil || request.State == "" {
			return nil, errors.New("missing on or more of mandatory fields [vp_token, presentation_submission, state]")
		}
	} else {
		if vpSession.EncryptDirectPostJWT {
			return nil, errors.New("encrypted direct_post.jwt expected as response from wallet")
		}
		vpTokenStringArray := g.PostFormArray("vp_token")
		presentationSubmissionString := g.PostForm("presentation_submission")
		stateString := g.PostForm("state")
		errorString := g.PostForm("error")
		errorDescriptionString := g.PostForm("error_description")
		errorURIString := g.PostForm("error_uri")

		s.log.Debug("Received AuthorizationResponse (direct_post.jwt):",
			"vpTokenStringArray", vpTokenStringArray,
			"presentationSubmissionString", presentationSubmissionString,
			"stateString", stateString,
			"errorString", errorString,
			"errorDescriptionString", errorDescriptionString,
			"errorURIString", errorURIString)

		if errorString != "" {
			return nil, fmt.Errorf("error from wallet during auth request error=%s, errorDescription=%s, errorURIString=%s", errorString, errorDescriptionString, errorURIString)
		}
		if vpTokenStringArray == nil || len(vpTokenStringArray) < 1 || presentationSubmissionString == "" || stateString == "" {
			return nil, errors.New("missing on or more of mandatory query string [vp_token, presentation_submission, state]")
		}

		var presentationSubmission openid4vp.PresentationSubmission
		err = json.Unmarshal([]byte(presentationSubmissionString), &presentationSubmission)
		if err != nil {
			return nil, err
		}

		var vpTokens []openid4vp.VPTokenRaw
		for _, vpTokenString := range vpTokenStringArray {
			raw, err := openid4vp.ToVPTokenRaw([]byte(vpTokenString))
			if err != nil {
				return nil, err
			}
			vpTokens = append(vpTokens, *raw)
		}

		request = &openid4vp.AuthorizationResponse{
			VPTokens:               vpTokens,
			PresentationSubmission: &presentationSubmission,
			State:                  stateString,
		}
	}

	reply, err := s.apiv1.Callback(ctx, sessionID, callbackID, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGetVerificationResult(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointGetVerificationResult")
	defer span.End()

	webSession := sessions.Default(g)
	vpSessionID, err := s.extractVPSessionIDfrom(webSession)
	if err != nil {
		return nil, errors.New("no web session found or has expired")
	}

	reply, err := s.apiv1.GetVerificationResult(ctx, vpSessionID)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointQuitVPFlow(ctx context.Context, g *gin.Context) (any, error) {
	_, span := s.tracer.Start(ctx, "httpserver:endpointQuitVPFlow")
	defer span.End()

	webSession := sessions.Default(g)
	vpSessionID, err := s.extractVPSessionIDfrom(webSession)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	webSession.Clear()
	webSession.Options(sessions.Options{MaxAge: -1})
	err = webSession.Save()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	fmt.Println("web session removed for vpSessionID:", vpSessionID)
	//TODO: ta även bort vpSession om sådan finns lagrad (om man vill det före den timat ut av sig själv?) - kan ju dock pågå interaktion från en wallet samtidigt???

	return nil, nil
}

func (s *Service) extractVPSessionIDfrom(webSession sessions.Session) (string, error) {
	rawVPSessionID := webSession.Get("vp_session_id")
	if rawVPSessionID == nil {
		return "", errors.New("vp_session_id not found")
	}
	vpSessionID, ok := rawVPSessionID.(string)
	if !ok || vpSessionID == "" {
		return "", errors.New("vp_session_id not found or empty")
	}
	return vpSessionID, nil
}

func (s *Service) endpointHealth(ctx context.Context, g *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Health(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGetVPFlowDebugInfo(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointGetVPFlowDebugInfo")
	defer span.End()

	request := &apiv1.VPFlowDebugInfoRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, g, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.GetVPFlowDebugInfo(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointPaginatedVerificationRecords(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointPaginatedVerificationRecords")
	defer span.End()

	request := &apiv1.PaginatedVerificationRecordsRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, g, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.PaginatedVerificationRecords(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	g.Header("Cache-Control", "no-store")
	g.Header("Pragma", "no-cache")

	return reply, nil
}

type RequestData struct {
	Method           string
	URL              *url.URL
	Proto            string
	ProtoMajor       int
	ProtoMinor       int
	Header           http.Header
	Body             []byte
	ContentLength    int64
	TransferEncoding []string
	Close            bool
	Host             string
	Form             url.Values
	PostForm         url.Values
	MultipartForm    *multipart.Form
	Trailer          http.Header
	RemoteAddr       string
	RequestURI       string
	TLS              *tls.ConnectionState

	ClientIP    string
	ContentType string
	UserAgent   string
	Referer     string
	Cookies     []*http.Cookie
	FullPath    string
	Handler     string
}

func (s *Service) saveRequestDataToVPSession(ctx context.Context, g *gin.Context, span trace2.Span, sessionID string, callbackID string) (*openid4vp.VPInteractionSession, error) {
	body, err := io.ReadAll(g.Request.Body)
	if err != nil {
		return nil, err
	}

	span.SetAttributes(
		trace.SafeAttr("request.body", &body),
	)

	requestData := &RequestData{
		Method:           g.Request.Method,
		URL:              g.Request.URL,
		Proto:            g.Request.Proto,
		ProtoMajor:       g.Request.ProtoMajor,
		ProtoMinor:       g.Request.ProtoMinor,
		Header:           g.Request.Header,
		Body:             body,
		ContentLength:    g.Request.ContentLength,
		TransferEncoding: g.Request.TransferEncoding,
		Close:            g.Request.Close,
		Host:             g.Request.Host,
		Form:             g.Request.Form,
		PostForm:         g.Request.PostForm,
		MultipartForm:    g.Request.MultipartForm,
		Trailer:          g.Request.Trailer,
		RemoteAddr:       g.Request.RemoteAddr,
		RequestURI:       g.Request.RequestURI,
		TLS:              g.Request.TLS,
		ClientIP:         g.ClientIP(),
		ContentType:      g.ContentType(),
		UserAgent:        g.Request.UserAgent(),
		Referer:          g.Request.Referer(),
		Cookies:          g.Request.Cookies(),
		FullPath:         g.FullPath(),
		Handler:          g.HandlerName(),
	}

	requestDataJson := convertRequestDataToJson(requestData)
	fmt.Println(requestDataJson)

	g.Request.Body = io.NopCloser(bytes.NewBuffer(body))
	vpSession, err := s.apiv1.SaveRequestDataToVPSession(ctx, sessionID, callbackID, requestDataJson)
	if err != nil {
		return nil, err
	}
	return vpSession, nil
}

func convertRequestDataToJson(data *RequestData) *openid4vp.JsonRequestData {
	jsonData := openid4vp.JsonRequestData{
		Method:           data.Method,
		URL:              data.URL.String(),
		Proto:            data.Proto,
		ProtoMajor:       data.ProtoMajor,
		ProtoMinor:       data.ProtoMinor,
		Header:           data.Header,
		Body:             data.Body,
		ContentLength:    data.ContentLength,
		TransferEncoding: data.TransferEncoding,
		Close:            data.Close,
		Host:             data.Host,
		Form:             data.Form,
		PostForm:         data.PostForm,
		Trailer:          data.Trailer,
		RemoteAddr:       data.RemoteAddr,
		RequestURI:       data.RequestURI,
		ClientIP:         data.ClientIP,
		ContentType:      data.ContentType,
		UserAgent:        data.UserAgent,
		Referer:          data.Referer,
		FullPath:         data.FullPath,
		Handler:          data.Handler,
	}

	if data.Cookies != nil {
		jsonCookies := make([]map[string]string, len(data.Cookies))
		for i, cookie := range data.Cookies {
			jsonCookies[i] = map[string]string{
				"name":       cookie.Name,
				"value":      cookie.Value,
				"path":       cookie.Path,
				"domain":     cookie.Domain,
				"expires":    cookie.Expires.String(),
				"raw_string": cookie.Raw,
				"http_only":  fmt.Sprintf("%v", cookie.HttpOnly),
				"secure":     fmt.Sprintf("%v", cookie.Secure),
				"same_site":  fmt.Sprintf("%v", cookie.SameSite),
			}
		}
		jsonData.Cookies = jsonCookies
	}

	if data.MultipartForm != nil && data.MultipartForm.Value != nil {
		multipartForm := make(map[string][]string)
		for key, values := range data.MultipartForm.Value {
			multipartForm[key] = values
		}
		jsonData.MultipartForm = multipartForm
	}

	if data.TLS != nil {
		jsonData.TLS = map[string]interface{}{
			"version":                       data.TLS.Version,
			"server_name":                   data.TLS.ServerName,
			"did_resume":                    data.TLS.DidResume,
			"cipher_suite":                  data.TLS.CipherSuite,
			"negotiated_protocol":           data.TLS.NegotiatedProtocol,
			"negotiated_protocol_is_mutual": data.TLS.NegotiatedProtocolIsMutual,
		}
	}

	return &jsonData
}
