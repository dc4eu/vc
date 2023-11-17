package gosunetca

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/masv3971/gosunetca/types"

	"github.com/go-logr/logr"
)

// Config is the configuration for the client
type Config struct {
	ServerURL string `validate:"required"`
	Token     string `validate:"required"`
	Location  string `validate:"required"`
	Reason    string `validate:"required"`
	UserAgent string
	ProxyURL  string
	//Logger    logr.Logger
}

// Client is the client for the SUNET CA API
type Client struct {
	httpClient *http.Client
	token      string
	serverURL  string
	userAgent  string
	location   string
	reason     string
	Log

	PDF *PDFService
}

// New create a new client
func New(ctx context.Context, config Config) (*Client, error) {
	if err := check(config); err != nil {
		return nil, err
	}

	c := &Client{
		httpClient: &http.Client{},
		token:      config.Token,
		serverURL:  config.ServerURL,
		userAgent:  config.UserAgent,
		location:   config.Location,
		reason:     config.Reason,
		Log:        Log{},
		PDF:        &PDFService{},
	}
	c.Logger = logr.FromContextOrDiscard(ctx)

	c.httpClient.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}

	c.PDF = &PDFService{client: c, baseURL: "/pdf"}
	return c, nil
}

// NewRequest make a new request
func (c *Client) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	rel, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(c.serverURL)
	if err != nil {
		return nil, err
	}
	url := u.ResolveReference(rel)

	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err = json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url.String(), buf)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", fmt.Sprintf("gosunetca-%s", c.userAgent))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))

	return req, nil
}

// Do does the new request
func (c *Client) do(ctx context.Context, req *http.Request, value any) (*http.Response, error) {
	c.Log.Debug("do", "method", req.Method, "path", req.URL.Path)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkResponse(resp); err != nil {
		buf := &bytes.Buffer{}
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return nil, err
		}
		caError := &types.ErrorReply{}
		if err := json.Unmarshal(buf.Bytes(), caError); err != nil {
			return nil, err
		}
		return nil, caError
	}

	if err := json.NewDecoder(resp.Body).Decode(value); err != nil {
		return nil, err
	}

	return resp, nil
}

func checkResponse(r *http.Response) error {
	switch r.StatusCode {
	case 200, 201, 202, 204, 304:
		return nil
	case 401:
		return errors.New("Unauthorized")
	case 500:
		return errors.New("Invalid")
	}
	return errors.New("Invalid request")
}

func (c *Client) call(ctx context.Context, method, path string, body, reply any) (*http.Response, error) {
	request, err := c.newRequest(
		ctx,
		method,
		path,
		body,
	)
	if err != nil {
		return nil, err
	}

	resp, err := c.do(ctx, request, reply)
	if err != nil {
		return resp, err
	}

	return resp, nil
}
