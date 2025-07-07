package vcclient

import (
	"context"
	"net/http"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/sdjwt3"
)

type userHandler struct {
	client             *Client
	serviceBaseURL     string
	log                *logger.Log
	defaultContentType string
}

type AddPIDRequest struct {
	Username string          `json:"username" validate:"required"`
	Password string          `json:"password" validate:"required"`
	Identity *model.Identity `json:"identity,omitempty" validate:"required"`
	Meta     *model.MetaData `json:"meta,omitempty" validate:"required"`
}

func (s *userHandler) AddPID(ctx context.Context, body *AddPIDRequest) (*http.Response, error) {
	url := s.serviceBaseURL + "/pid"
	resp, err := s.client.call(ctx, http.MethodPost, url, s.defaultContentType, body, nil, false)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

type LoginPIDUserRequest struct {
	Username string `json:"username" form:"username" validate:"required"`
	Password string `json:"password" form:"password" validate:"required"`

	// RequestURI comes from session cookie
	RequestURI string `json:"-"`
}

func (s *userHandler) LoginPIDUser(ctx context.Context, body *LoginPIDUserRequest) (*http.Response, error) {
	url := s.serviceBaseURL + "/pid/login"
	resp, err := s.client.call(ctx, http.MethodPost, url, s.defaultContentType, body, nil, false)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

type GetPIDRequest struct {
	Username string `json:"username" form:"username" validate:"required"`
}

type GetPIDReply struct {
	Identity *model.Identity `json:"identity,omitempty"`
}

type UserLookupRequest struct {
	Username     string       `json:"-"`
	AuthMethod   string       `json:"-"`
	ResponseCode string       `json:"-"`
	RequestURI   string       `json:"-"`
	VCTM         *sdjwt3.VCTM `json:"-"`
}

type UserLookupReply struct {
	SVGTemplateClaims map[string]any `json:"svg_template_claims,omitempty"`
	RedirectURL       string         `json:"redirect_url,omitempty"`
}

type UserAuthenticSourceLookupRequest struct {
	AuthenticSource string `json:"authentic_source,omitempty"`
	SessionID       string `json:"-"`
}

type UserAuthenticSourceLookupReply struct {
	AuthenticSources []string `json:"authentic_sources,omitempty"`
}
