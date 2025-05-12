package vcclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
	"vc/pkg/helpers"
	"vc/pkg/logger"
)

// Client is the client
type Client struct {
	httpClient *http.Client
	url        string
	log        *logger.Log

	Document *documentHandler
	Identity *identityHandler
	Root     *rootHandler
	OIDC     *oidcHandler
	User     *userHandler
}

// Config is the configuration for the client
type Config struct {
	URL string `validate:"required"`
}

// New creates a new client
func New(config *Config) (*Client, error) {
	if err := helpers.CheckSimple(config); err != nil {
		return nil, err
	}
	c := &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		url: config.URL,
	}

	var err error
	c.log, err = logger.New("datastoreClient", "", false)
	if err != nil {
		return nil, err
	}

	defaultContentType := "application/json"

	c.Document = &documentHandler{client: c, serviceBaseURL: "api/v1/document", defaultContentType: defaultContentType, log: c.log.New("document")}
	c.Identity = &identityHandler{client: c, serviceBaseURL: "api/v1/identity", defaultContentType: defaultContentType, log: c.log.New("identity")}
	c.Root = &rootHandler{client: c, serviceBaseURL: "api/v1", defaultContentType: defaultContentType, log: c.log.New("root")}
	c.OIDC = &oidcHandler{client: c, defaultContentType: defaultContentType, log: c.log.New("oidc")}
	c.User = &userHandler{client: c, serviceBaseURL: "api/v1/user", defaultContentType: defaultContentType, log: c.log.New("user")}

	return c, nil
}

// NewRequest make a new request
func (c *Client) newRequest(ctx context.Context, method, path, contentType string, body any) (*http.Request, error) {
	rel, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(c.url)
	if err != nil {
		return nil, err
	}
	url := u.ResolveReference(rel)
	c.log.Debug("request", "url", url.String())

	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err = json.NewEncoder(buf).Encode(body)
		if err != nil {
			c.log.Error(err, "failed to encode body")
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url.String(), buf)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", contentType)
		c.log.Debug("request", "CT", req.Header.Get("Content-Type"))
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// Do does the new request
func (c *Client) do(ctx context.Context, req *http.Request, reply any, prefixReplyJSONWithData bool) (*http.Response, error) {
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
		if err := json.Unmarshal(buf.Bytes(), err); err != nil {
			return nil, err
		}
		return nil, err
	}

	var r any
	if prefixReplyJSONWithData {
		r = &struct {
			Data any `json:"data"`
		}{
			Data: reply,
		}
	} else {
		r = &reply
	}

	if err := json.NewDecoder(resp.Body).Decode(r); err != nil {
		c.log.Error(err, "failed to decode response")
		return nil, err
	}

	return resp, nil

}

// read body and make it reusable
//func readBody(body io.ReadCloser) ([]byte, error) {
//	buf := &bytes.Buffer{}
//	if _, err := buf.ReadFrom(body); err != nil {
//		return nil, err
//	}
//	return buf.Bytes(), nil
//}

func checkResponse(r *http.Response) error {
	switch r.StatusCode {
	case 200, 201, 202, 204, 304:
		return nil
	case 500:
		return ErrInvalidRequest
	case 401:
		return ErrNotAllowedRequest
	}

	return ErrInvalidRequest
}

func (c *Client) call(ctx context.Context, method, path, contentType string, body, reply any, prefixReplyJSONWithData bool) (*http.Response, error) {
	request, err := c.newRequest(
		ctx,
		method,
		path,
		contentType,
		body,
	)
	if err != nil {
		return nil, err
	}

	resp, err := c.do(ctx, request, reply, prefixReplyJSONWithData)
	if err != nil {
		return resp, err
	}

	return resp, nil
}
