package vcclient

import (
	"context"
	"net/http"
	"vc/pkg/logger"
	"vc/pkg/model"
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

type LoginPIDUserReply struct {
	Grant       bool   `json:"grant" validate:"required"`
	Username    string `json:"username,omitempty"`
	RedirectURL string `json:"redirect_url,omitempty"`
}

func (s *userHandler) LoginPIDUser(ctx context.Context, body *LoginPIDUserRequest) (*LoginPIDUserReply, *http.Response, error) {
	url := s.serviceBaseURL + "/pid/login"
	reply := &LoginPIDUserReply{}
	resp, err := s.client.call(ctx, http.MethodPost, url, s.defaultContentType, body, reply, false)
	if err != nil {
		return nil, resp, err
	}

	return reply, resp, nil
}

type GetPIDRequest struct {
	Username string `json:"username" form:"username" validate:"required"`
}

type GetPIDReply struct {
	Identity *model.Identity `json:"identity,omitempty"`
}

type UserLookupRequest struct {
	Username   string `json:"-"`
	AuthMethod string `json:"-"`
}

type UserLookupReply struct {
	SVGTemplateClaims map[string]string `json:"svg_template_claims,omitempty"`
}
